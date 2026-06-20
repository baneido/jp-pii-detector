// Command gen は日本郵便の郵便番号データ（UTF-8 KEN_ALL CSV / zip）から、
// 7 桁郵便番号の実在集合をビットセットとして生成する。
//
// 入力は日本郵便の「住所の郵便番号（1 レコード 1 行、UTF-8）」CSV、または
// それを含む zip。配布元:
//
//	https://www.post.japanpost.jp/zipcode/dl/utf-zip.html
//	（utf_ken_all.zip / KEN_ALL.CSV）
//
// 出力 (-output) は 10,000,000 ビット（= 1,250,000 バイト）の生のビットセット。
// インデックス n（0〜9999999）のビットが立っていれば、7 桁郵便番号 n が実在する。
// internal/dict が //go:embed で取り込み、7 桁完全一致の照合に使う。
//
// -prefixes を指定すると、上位 3 桁の実在集合（ビットセット未生成時の
// フォールバック用 postal_prefixes.txt）も同時に生成する。
//
//	go run ./internal/dict/gen \
//	  -input utf_ken_all.zip \
//	  -output internal/dict/postal_codes.bitset \
//	  -prefixes internal/dict/postal_prefixes.txt
package main

import (
	"archive/zip"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// postalCodeCount は 7 桁郵便番号の値域（0000000〜9999999）。
	postalCodeCount = 10_000_000
	// postalBitsetSize はビットセットのバイト長（1 ビット 1 郵便番号）。
	postalBitsetSize = postalCodeCount / 8 // 1,250,000 バイト
)

func main() {
	input := flag.String("input", "", "Japan Post UTF-8 KEN_ALL CSV or zip path")
	output := flag.String("output", "", "output path for postal_codes.bitset (7-digit exact bitset)")
	prefixOutput := flag.String("prefixes", "", "optional output path for postal_prefixes.txt (3-digit fallback)")
	flag.Parse()

	if *input == "" || *output == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}

	if err := generatePostal(*input, *output, *prefixOutput); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func generatePostal(inputPath, bitsetPath, prefixPath string) error {
	codes := map[uint32]struct{}{}
	if strings.EqualFold(filepath.Ext(inputPath), ".zip") {
		if err := readZip(inputPath, codes); err != nil {
			return err
		}
	} else {
		if err := readCSVFile(inputPath, codes); err != nil {
			return err
		}
	}
	if len(codes) == 0 {
		return fmt.Errorf("no postal codes found in %s", inputPath)
	}

	bitset := make([]byte, postalBitsetSize)
	for c := range codes {
		bitset[c>>3] |= 1 << (c & 7)
	}
	if err := writeFile(bitsetPath, bitset); err != nil {
		return err
	}

	if prefixPath != "" {
		if err := writePrefixes(prefixPath, codes); err != nil {
			return err
		}
	}
	return nil
}

// writePrefixes は 7 桁集合から上位 3 桁の実在集合をソートして書き出す
// （ビットセット未生成時のフォールバック）。
func writePrefixes(path string, codes map[uint32]struct{}) error {
	prefixes := map[string]struct{}{}
	for c := range codes {
		prefixes[fmt.Sprintf("%07d", c)[:3]] = struct{}{}
	}
	sorted := make([]string, 0, len(prefixes))
	for p := range prefixes {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)

	var b strings.Builder
	for _, p := range sorted {
		b.WriteString(p)
		b.WriteByte('\n')
	}
	return writeFile(path, []byte(b.String()))
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func readZip(path string, codes map[uint32]struct{}) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer zr.Close()

	foundCSV := false
	for _, file := range zr.File {
		if file.FileInfo().IsDir() || !strings.EqualFold(filepath.Ext(file.Name), ".csv") {
			continue
		}
		foundCSV = true
		rc, err := file.Open()
		if err != nil {
			return err
		}
		err = readCSV(file.Name, rc, codes)
		closeErr := rc.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if !foundCSV {
		return fmt.Errorf("zip has no csv entries: %s", path)
	}
	return nil
}

func readCSVFile(path string, codes map[uint32]struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return readCSV(path, f, codes)
}

func readCSV(name string, r io.Reader, codes map[uint32]struct{}) error {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true

	for {
		record, err := cr.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if len(record) < 3 {
			return fmt.Errorf("%s: record has %d columns, want at least 3", name, len(record))
		}

		postalCode := strings.TrimSpace(record[2])
		if !isSevenDigitPostalCode(postalCode) {
			return fmt.Errorf("%s: invalid postal code in column 3: %q", name, postalCode)
		}
		codes[parsePostal(postalCode)] = struct{}{}
	}
}

func isSevenDigitPostalCode(s string) bool {
	if len(s) != 7 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// parsePostal は 7 桁の数字文字列をビットセットのインデックス（0〜9999999）へ変換する。
func parsePostal(s string) uint32 {
	var n uint32
	for i := range 7 {
		n = n*10 + uint32(s[i]-'0')
	}
	return n
}
