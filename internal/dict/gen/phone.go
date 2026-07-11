// generatePhone は市外局番一覧の CSV から internal/dict/area_codes.txt 形式の
// 一覧を生成する（gen -phone のエントリポイント。main の flag 定義は
// postal.go を参照）。
//
// 総務省の「市外局番の一覧」（電気通信番号指定状況）は Excel 中心の配布形式で
// xlsx パーサへの依存はパーサ破損のリスクが大きいため、gen は事前に市外局番列
// だけを抽出した CSV（1 列目が市外局番。他の列があっても無視する）のみを
// 受け付ける。Excel → CSV の変換は人手（または別ツール）で行うことを前提とする。
package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func generatePhone(inputPath, outputPath string) error {
	f, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	codes, err := readAreaCodeCSV(inputPath, f)
	if err != nil {
		return err
	}
	if len(codes) == 0 {
		return fmt.Errorf("no area codes found in %s", inputPath)
	}
	sort.Strings(codes)

	var b strings.Builder
	b.WriteString("# internal/dict/area_codes.txt\n")
	b.WriteString("# internal/dict/gen -phone で生成（出典・件数はコマンド実行時のメモを併記すること）。\n")
	fmt.Fprintf(&b, "# 件数: %d\n", len(codes))
	for _, c := range codes {
		b.WriteString(c)
		b.WriteString("\n")
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(outputPath, []byte(b.String()), 0o644); err != nil {
		return err
	}
	// 件数を出力する（サニティチェックと運用ログ用。postal gen と同じ運用）。
	fmt.Printf("area codes: %d\n", len(codes))
	return nil
}

func readAreaCodeCSV(name string, r io.Reader) ([]string, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true

	seen := map[string]bool{}
	var codes []string
	for {
		record, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if len(record) == 0 {
			continue
		}
		code := strings.TrimSpace(record[0])
		if !isAreaCodeFormat(code) || seen[code] {
			continue
		}
		seen[code] = true
		codes = append(codes, code)
	}
	return codes, nil
}

// isAreaCodeFormat は s が市外局番として妥当な形式（先頭 "0" の 2〜5 桁数字）かを返す。
// ヘッダ行や空セル、コメント行（"#" 始まり等）を読み飛ばすためのゆるい検証で、
// 実在性そのものはここでは判定しない（実在確認は dict.ValidAreaCode 側）。
func isAreaCodeFormat(s string) bool {
	if len(s) < 2 || len(s) > 5 || s[0] != '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
