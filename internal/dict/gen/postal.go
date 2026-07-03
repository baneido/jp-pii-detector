// Command gen は日本郵便の郵便番号データから、7 桁郵便番号の実在集合をビットセット
// として生成する。入力は 2 種類あり、いずれか一方または両方を指定できる（両方指定時は
// マージされ、重複は自動的に排除される）。
//
//   - -ken-all-input: 「住所の郵便番号」CSV（1 レコード 1 行、UTF-8）、または
//     それを含む zip。配布元:
//     https://www.post.japanpost.jp/zipcode/dl/utf-zip.html
//     （utf_ken_all.zip / KEN_ALL.CSV）。郵便番号は 3 列目（0 始まりで列 2）。
//   - -jigyosyo-input: 「事業所の個別郵便番号」CSV、または それを含む zip。配布元:
//     https://www.post.japanpost.jp/zipcode/dl/jigyosyo/
//     （jigyosyo.zip / JIGYOSYO.CSV）。郵便番号は 8 列目（0 始まりで列 7）。
//     配布データは Shift_JIS のため、CSV としてパースする前に UTF-8 へデコードする
//     （クォート内の非 ASCII バイトを ASCII 前提でパースして誤って壊すのを避ける）。
//
// 出力 (-output) は dict.PostalBitsetSize バイト（10,000,000 ビット）の生の
// ビットセット。インデックス n（0〜9999999）のビットが立っていれば、7 桁郵便番号 n が
// 実在する。internal/dict が //go:embed で取り込み、7 桁完全一致の照合に使う。
// インデックスのエンコーディングとサイズ定数は dict 側と共有する（無言の乖離を防ぐ）。
//
//	go run ./internal/dict/gen \
//	    -ken-all-input utf_ken_all.zip \
//	    -jigyosyo-input jigyosyo.zip \
//	    -output internal/dict/postal_codes.bitset
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

	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/transform"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// kenAllPostalColumn / jigyosyoPostalColumn は各 CSV フォーマットで郵便番号が
// 入っている列インデックス（0 始まり）。取り違えると実質ゼロ件取り込みになる
// （事業所名などの非数字列を「7 桁郵便番号でない」として黙ってスキップし続けるため）
// ので、readCSV には呼び出し側が明示的に渡す。
const (
	kenAllPostalColumn   = 2 // KEN_ALL.CSV: 3 列目 = 郵便番号（7 桁）
	jigyosyoPostalColumn = 7 // JIGYOSYO.CSV: 8 列目 = 個別番号（7 桁）
)

func main() {
	kenAllInput := flag.String("ken-all-input", "", "Japan Post UTF-8 KEN_ALL (住所の郵便番号) CSV or zip path")
	jigyosyoInput := flag.String("jigyosyo-input", "", "Japan Post Shift_JIS jigyosyo (事業所の個別郵便番号) CSV or zip path")
	output := flag.String("output", "", "output path for postal_codes.bitset (7-digit exact bitset)")
	flag.Parse()

	if (*kenAllInput == "" && *jigyosyoInput == "") || *output == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}

	if err := generatePostal(*kenAllInput, *jigyosyoInput, *output); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
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
