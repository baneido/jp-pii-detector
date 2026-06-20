// Command gen は日本郵便の郵便番号データ（UTF-8 KEN_ALL CSV / zip）から、
// 7 桁郵便番号の実在集合をビットセットとして生成する。
//
// 入力は日本郵便の「住所の郵便番号（1 レコード 1 行、UTF-8）」CSV、または
// それを含む zip。配布元:
//
//	https://www.post.japanpost.jp/zipcode/dl/utf-zip.html
//	（utf_ken_all.zip / KEN_ALL.CSV）
//
// 出力 (-output) は dict.PostalBitsetSize バイト（10,000,000 ビット）の生の
// ビットセット。インデックス n（0〜9999999）のビットが立っていれば、7 桁郵便番号 n が
// 実在する。internal/dict が //go:embed で取り込み、7 桁完全一致の照合に使う。
// インデックスのエンコーディングとサイズ定数は dict 側と共有する（無言の乖離を防ぐ）。
//
//	go run ./internal/dict/gen -input utf_ken_all.zip -output internal/dict/postal_codes.bitset
package main

import (
	"archive/zip"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

func main() {
	input := flag.String("input", "", "Japan Post UTF-8 KEN_ALL CSV or zip path")
	output := flag.String("output", "", "output path for postal_codes.bitset (7-digit exact bitset)")
	flag.Parse()

	if *input == "" || *output == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}

	if err := generatePostal(*input, *output); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func generatePostal(inputPath, bitsetPath string) error {
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

	bitset := make([]byte, dict.PostalBitsetSize)
	for c := range codes {
		bitset[c>>3] |= 1 << (c & 7)
	}
	if err := os.MkdirAll(filepath.Dir(bitsetPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(bitsetPath, bitset, 0o644); err != nil {
		return err
	}
	// 件数を出力する（ワークフローのサニティチェックと運用ログ用）。
	fmt.Printf("postal codes: %d\n", len(codes))
	return nil
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
		// 7 桁郵便番号を持たない行（想定外フォーマット）はスキップする。
		// 全体が空になれば呼び出し側の「no postal codes」で検出される。
		if len(record) < 3 {
			continue
		}
		postalCode := strings.TrimSpace(record[2])
		if !isSevenDigitPostalCode(postalCode) {
			continue
		}
		codes[dict.PostalCodeIndex(postalCode)] = struct{}{}
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
