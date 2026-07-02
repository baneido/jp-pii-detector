// Command gen は日本郵便の郵便番号データ（UTF-8 KEN_ALL CSV / zip）から、
// 7 桁郵便番号の実在集合をビットセットとして、また市区町村名の実在集合を
// テキスト辞書として生成する。
//
// 入力は日本郵便の「住所の郵便番号（1 レコード 1 行、UTF-8）」CSV、または
// それを含む zip。配布元:
//
//	https://www.post.japanpost.jp/zipcode/dl/utf-zip.html
//	（utf_ken_all.zip / KEN_ALL.CSV）
//
// -output（省略可）は dict.PostalBitsetSize バイト（10,000,000 ビット）の生の
// ビットセット。インデックス n（0〜9999999）のビットが立っていれば、7 桁郵便番号 n が
// 実在する。internal/dict が //go:embed で取り込み、7 桁完全一致の照合に使う。
// インデックスのエンコーディングとサイズ定数は dict 側と共有する（無言の乖離を防ぐ）。
//
// -municipalities-output（省略可）は record[6]（都道府県名）・record[7]（市区町村名）
// から生成する市区町村名の一覧（1 行 1 エントリ、ソート・重複排除済み）。
// dict.MunicipalitySuffixMatch が //go:embed で取り込み、jp-address-high-recall の
// Validate に使う。ヶ→ケ正規化、郡付きエントリの郡省略形、政令指定都市の
// 市単独形を併録する（詳細は addMunicipalityVariants を参照）。
//
//	go run ./internal/dict/gen -input utf_ken_all.zip -output internal/dict/postal_codes.bitset -municipalities-output internal/dict/municipalities.txt
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

	"github.com/baneido/jp-pii-detector/internal/dict"
)

func main() {
	input := flag.String("input", "", "Japan Post UTF-8 KEN_ALL CSV or zip path")
	output := flag.String("output", "", "output path for postal_codes.bitset (7-digit exact bitset); omit to skip")
	municipalitiesOutput := flag.String("municipalities-output", "", "output path for municipalities.txt (実在市区町村名の一覧); omit to skip")
	flag.Parse()

	if *input == "" || (*output == "" && *municipalitiesOutput == "") || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}

	if err := generate(*input, *output, *municipalitiesOutput); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// generatePostal は郵便番号ビットセットだけを生成する（既存呼び出し元・テスト互換用の薄いラッパー）。
func generatePostal(inputPath, bitsetPath string) error {
	return generate(inputPath, bitsetPath, "")
}

// generateMunicipalities は市区町村名辞書だけを生成する。
func generateMunicipalities(inputPath, municipalitiesPath string) error {
	return generate(inputPath, "", municipalitiesPath)
}

// generate は入力 CSV/zip を 1 パスで読み、要求された成果物（ビットセット・
// 市区町村名辞書）を生成する。同じ入力を 2 回読まずに済ませるため 1 関数にまとめている。
func generate(inputPath, bitsetPath, municipalitiesPath string) error {
	codes := map[uint32]struct{}{}
	munis := map[string]struct{}{}

	handle := func(record []string) error {
		if len(record) < 8 {
			return nil
		}
		if bitsetPath != "" {
			if postalCode := strings.TrimSpace(record[2]); isSevenDigitPostalCode(postalCode) {
				codes[dict.PostalCodeIndex(postalCode)] = struct{}{}
			}
		}
		if municipalitiesPath != "" {
			addMunicipalityVariants(munis, record[7])
		}
		return nil
	}

	if strings.EqualFold(filepath.Ext(inputPath), ".zip") {
		if err := readZip(inputPath, handle); err != nil {
			return err
		}
	} else {
		if err := readCSVFile(inputPath, handle); err != nil {
			return err
		}
	}

	if bitsetPath != "" {
		if len(codes) == 0 {
			return fmt.Errorf("no postal codes found in %s", inputPath)
		}
		if err := writeBitset(bitsetPath, codes); err != nil {
			return err
		}
		// 件数を出力する（ワークフローのサニティチェックと運用ログ用）。
		fmt.Printf("postal codes: %d\n", len(codes))
	}
	if municipalitiesPath != "" {
		if len(munis) == 0 {
			return fmt.Errorf("no municipalities found in %s", inputPath)
		}
		if err := writeMunicipalities(municipalitiesPath, munis); err != nil {
			return err
		}
		fmt.Printf("municipalities: %d\n", len(munis))
	}
	return nil
}

func writeBitset(bitsetPath string, codes map[uint32]struct{}) error {
	bitset := make([]byte, dict.PostalBitsetSize)
	for c := range codes {
		bitset[c>>3] |= 1 << (c & 7)
	}
	if err := os.MkdirAll(filepath.Dir(bitsetPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(bitsetPath, bitset, 0o644)
}

// addMunicipalityVariants は KEN_ALL の市区町村名 raw（record[7]）から、実在照合に
// 使う表記バリエーションを munis に加える。
//
//   - ヶ→ケ正規化（dict.NormalizeMunicipalityKa）: 表記揺れを 1 つに畳む。実行時の
//     照合側（dict.MunicipalitySuffixMatch）も同じ正規化を候補文字列に適用するため、
//     どちらの表記で書かれた住所も一致する。
//   - 郡付きエントリ（石狩郡当別町 等）は郡を省いた省略形（当別町）も併録する。
//     ただし「小郡市」「郡山市」「郡上市」のように市名自体に「郡」の字を含むものは
//     郡区分ではないため対象外（市で終わる名前は郡と誤認しない）。
//   - 政令指定都市の区（札幌市中央区 等）は「市＋区」の連結に加えて市単独形
//     （札幌市）も併録する。
func addMunicipalityVariants(munis map[string]struct{}, raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	name := dict.NormalizeMunicipalityKa(raw)
	munis[name] = struct{}{}

	if idx := strings.Index(name, "郡"); idx >= 0 && (strings.HasSuffix(name, "町") || strings.HasSuffix(name, "村")) {
		abbrev := name[idx+len("郡"):]
		if abbrev != "" {
			munis[abbrev] = struct{}{}
		}
	}

	if idx := strings.Index(name, "市"); idx >= 0 && strings.HasSuffix(name, "区") {
		cityAlone := name[:idx+len("市")]
		munis[cityAlone] = struct{}{}
	}
}

func writeMunicipalities(path string, munis map[string]struct{}) error {
	names := make([]string, 0, len(munis))
	for m := range munis {
		names = append(names, m)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("# 日本郵便 KEN_ALL（住所の郵便番号 UTF-8 版）由来の市区町村名一覧。\n")
	b.WriteString("# dict.MunicipalitySuffixMatch（jp-address-high-recall の Validate）が使う。\n")
	b.WriteString("# 生成: go run ./internal/dict/gen -input utf_ken_all.zip -output internal/dict/postal_codes.bitset -municipalities-output internal/dict/municipalities.txt\n")
	b.WriteString("# 配布元: https://www.post.japanpost.jp/zipcode/dl/utf-zip.html\n")
	for _, m := range names {
		b.WriteString(m)
		b.WriteByte('\n')
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

type recordHandler func(record []string) error

func readZip(path string, handle recordHandler) error {
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
		err = readCSV(file.Name, rc, handle)
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

func readCSVFile(path string, handle recordHandler) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return readCSV(path, f, handle)
}

func readCSV(name string, r io.Reader, handle recordHandler) error {
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
		if err := handle(record); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
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
