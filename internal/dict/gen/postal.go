// Command gen は日本郵便の郵便番号データから、7 桁郵便番号の実在集合をビットセット
// として、また市区町村名の実在集合をテキスト辞書として生成する。ビットセットの入力は
// 2 種類あり、いずれか一方または両方を指定できる（両方指定時はマージされ、重複は
// 自動的に排除される）。
//
//   - -ken-all-input: 「住所の郵便番号」CSV（1 レコード 1 行、UTF-8）、または
//     それを含む zip。配布元:
//     https://www.post.japanpost.jp/zipcode/dl/utf-zip.html
//     （utf_ken_all.zip / KEN_ALL.CSV）。郵便番号は 3 列目（0 始まりで列 2）、
//     市区町村名は 8 列目（0 始まりで列 7）。
//   - -jigyosyo-input: 「事業所の個別郵便番号」CSV、または それを含む zip。配布元:
//     https://www.post.japanpost.jp/zipcode/dl/jigyosyo/
//     （jigyosyo.zip / JIGYOSYO.CSV）。郵便番号は 8 列目（0 始まりで列 7）。
//     配布データは Shift_JIS のため、CSV としてパースする前に UTF-8 へデコードする
//     （クォート内の非 ASCII バイトを ASCII 前提でパースして誤って壊すのを避ける）。
//     市区町村名の辞書には使わない（列レイアウトが異なり、市区町村名の列を持たないため）。
//
// -output（省略可）は dict.PostalBitsetSize バイト（10,000,000 ビット）の生の
// ビットセット。インデックス n（0〜9999999）のビットが立っていれば、7 桁郵便番号 n が
// 実在する。internal/dict が //go:embed で取り込み、7 桁完全一致の照合に使う。
// インデックスのエンコーディングとサイズ定数は dict 側と共有する（無言の乖離を防ぐ）。
//
// -municipalities-output（省略可、-ken-all-input が必須）は record[7]（市区町村名）
// から生成する市区町村名の一覧（1 行 1 エントリ、ソート・重複排除済み）。
// dict.MunicipalitySuffixMatch が //go:embed で取り込み、jp-address-high-recall の
// Validate に使う。ヶ→ケ正規化、郡付きエントリの郡省略形、政令指定都市の
// 市単独形を併録する（詳細は addMunicipalityVariants を参照）。
//
//	go run ./internal/dict/gen \
//	    -ken-all-input utf_ken_all.zip \
//	    -jigyosyo-input jigyosyo.zip \
//	    -output internal/dict/postal_codes.bitset \
//	    -municipalities-output internal/dict/municipalities.txt
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

	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/transform"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// kenAllPostalColumn / jigyosyoPostalColumn は各 CSV フォーマットで郵便番号が
// 入っている列インデックス（0 始まり）。取り違えると実質ゼロ件取り込みになる
// （事業所名などの非数字列を「7 桁郵便番号でない」として黙ってスキップし続けるため）
// ので、readCSV には呼び出し側が明示的に渡す。
const (
	kenAllPostalColumn       = 2 // KEN_ALL.CSV: 3 列目 = 郵便番号（7 桁）
	kenAllMunicipalityColumn = 7 // KEN_ALL.CSV: 8 列目 = 市区町村名
	jigyosyoPostalColumn     = 7 // JIGYOSYO.CSV: 8 列目 = 個別番号（7 桁）
)

func main() {
	kenAllInput := flag.String("ken-all-input", "", "Japan Post UTF-8 KEN_ALL (住所の郵便番号) CSV or zip path")
	jigyosyoInput := flag.String("jigyosyo-input", "", "Japan Post Shift_JIS jigyosyo (事業所の個別郵便番号) CSV or zip path")
	output := flag.String("output", "", "output path for postal_codes.bitset (7-digit exact bitset); omit to skip")
	municipalitiesOutput := flag.String("municipalities-output", "", "output path for municipalities.txt (実在市区町村名の一覧、-ken-all-input が必須); omit to skip")
	flag.Parse()

	if (*kenAllInput == "" && *jigyosyoInput == "") || (*output == "" && *municipalitiesOutput == "") || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	if *municipalitiesOutput != "" && *kenAllInput == "" {
		fmt.Fprintln(os.Stderr, "error: -municipalities-output requires -ken-all-input")
		os.Exit(2)
	}

	if err := generate(*kenAllInput, *jigyosyoInput, *output, *municipalitiesOutput); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// generate は要求された成果物（郵便番号ビットセット・市区町村名辞書）を生成する。
// ビットセットは ken-all / jigyosyo 双方から、市区町村名辞書は ken-all のみから作る。
func generate(kenAllPath, jigyosyoPath, bitsetPath, municipalitiesPath string) error {
	if bitsetPath != "" {
		if err := generatePostal(kenAllPath, jigyosyoPath, bitsetPath); err != nil {
			return err
		}
	}
	if municipalitiesPath != "" {
		if err := generateMunicipalities(kenAllPath, municipalitiesPath); err != nil {
			return err
		}
	}
	return nil
}

func generatePostal(kenAllPath, jigyosyoPath, bitsetPath string) error {
	codes := map[uint32]struct{}{}
	if kenAllPath != "" {
		if err := readInput(kenAllPath, kenAllPostalColumn, nil, codes); err != nil {
			return fmt.Errorf("ken-all input: %w", err)
		}
	}
	if jigyosyoPath != "" {
		if err := readInput(jigyosyoPath, jigyosyoPostalColumn, shiftJISReader, codes); err != nil {
			return fmt.Errorf("jigyosyo input: %w", err)
		}
	}
	if len(codes) == 0 {
		return fmt.Errorf("no postal codes found in %s / %s", kenAllPath, jigyosyoPath)
	}

	if err := writeBitset(bitsetPath, codes); err != nil {
		return err
	}
	// 件数を出力する（ワークフローのサニティチェックと運用ログ用）。
	fmt.Printf("postal codes: %d\n", len(codes))
	return nil
}

// generateMunicipalities は KEN_ALL 入力だけから市区町村名辞書を生成する
// （jigyosyo データは市区町村名の列を持たないため対象外）。
func generateMunicipalities(kenAllPath, municipalitiesPath string) error {
	munis := map[string]struct{}{}
	handle := func(record []string) error {
		if len(record) <= kenAllMunicipalityColumn {
			return nil
		}
		addMunicipalityVariants(munis, record[kenAllMunicipalityColumn])
		return nil
	}
	if err := forEachRecord(kenAllPath, handle); err != nil {
		return fmt.Errorf("ken-all input: %w", err)
	}
	if len(munis) == 0 {
		return fmt.Errorf("no municipalities found in %s", kenAllPath)
	}

	if err := writeMunicipalities(municipalitiesPath, munis); err != nil {
		return err
	}
	fmt.Printf("municipalities: %d\n", len(munis))
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
	b.WriteString("# 生成: go run ./internal/dict/gen -ken-all-input utf_ken_all.zip -output internal/dict/postal_codes.bitset -municipalities-output internal/dict/municipalities.txt\n")
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

// decoderFunc は CSV としてパースする前に入力ストリームを変換する（例: Shift_JIS →
// UTF-8）。nil の場合は無変換（入力は既に UTF-8 / ASCII）。
type decoderFunc func(io.Reader) io.Reader

// shiftJISReader は r を Shift_JIS とみなして UTF-8 にデコードするラッパー。
// 事業所個別郵便番号データの配布フォーマット（Shift_JIS）向け。数字の郵便番号列
// しか使わない場合でも、クォート内の非 ASCII バイトを ASCII 前提の csv.Reader に
// そのまま渡すと誤ってフィールド区切りを壊しうるため、先にデコードする。
func shiftJISReader(r io.Reader) io.Reader {
	return transform.NewReader(r, japanese.ShiftJIS.NewDecoder())
}

func readInput(path string, postalColumn int, decode decoderFunc, codes map[uint32]struct{}) error {
	if strings.EqualFold(filepath.Ext(path), ".zip") {
		return readZip(path, postalColumn, decode, codes)
	}
	return readCSVFile(path, postalColumn, decode, codes)
}

func readZip(path string, postalColumn int, decode decoderFunc, codes map[uint32]struct{}) error {
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
		var r io.Reader = rc
		if decode != nil {
			r = decode(r)
		}
		err = readCSV(file.Name, r, postalColumn, codes)
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

func readCSVFile(path string, postalColumn int, decode decoderFunc, codes map[uint32]struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if decode != nil {
		r = decode(r)
	}
	return readCSV(path, r, postalColumn, codes)
}

func readCSV(name string, r io.Reader, postalColumn int, codes map[uint32]struct{}) error {
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
		// 郵便番号列を持たない行（想定外フォーマットや列インデックスの取り違え）は
		// スキップする。全体が空になれば呼び出し側の「no postal codes」で検出される。
		if len(record) <= postalColumn {
			continue
		}
		postalCode := strings.TrimSpace(record[postalColumn])
		if !isSevenDigitPostalCode(postalCode) {
			continue
		}
		codes[dict.PostalCodeIndex(postalCode)] = struct{}{}
	}
}

// recordHandler は市区町村名辞書生成用の、CSV レコード単位のコールバック。郵便番号
// ビットセット生成（列インデックス固定・複数入力マージ）とは別の読み取りパスとして
// 独立させている。市区町村名は ken-all-input からしか作らないため、こちらは単一入力
// のみを対象とする。
type recordHandler func(record []string) error

// forEachRecord は path（CSV または zip）の各レコードを handle に渡す。
func forEachRecord(path string, handle recordHandler) error {
	if strings.EqualFold(filepath.Ext(path), ".zip") {
		return forEachRecordInZip(path, handle)
	}
	return forEachRecordInCSVFile(path, handle)
}

func forEachRecordInZip(path string, handle recordHandler) error {
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
		err = forEachRecordInReader(file.Name, rc, handle)
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

func forEachRecordInCSVFile(path string, handle recordHandler) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return forEachRecordInReader(path, f, handle)
}

func forEachRecordInReader(name string, r io.Reader, handle recordHandler) error {
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
