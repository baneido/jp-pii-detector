package dict

import (
	_ "embed"
	"strings"
)

// area_codes.txt は日本の市外局番（先頭の "0" を含む全体表記。例: "03" "052"）の
// 一覧。出典・収録範囲・再生成手順は area_codes.txt 冒頭のコメントを参照
// （現状は総務省の公式データではなく、代表的な市外局番のみのシードデータ）。
// internal/dict/gen -phone が CSV から生成してコミットする。市外局番はほぼ変化
// しないため、郵便番号（postal_codes.bitset）のような月次自動更新は設けていない。
//
//go:embed area_codes.txt
var areaCodesRaw string

var areaCodes, areaCodeMinLen, areaCodeMaxLen = loadAreaCodes(areaCodesRaw)

func loadAreaCodes(raw string) (codes map[string]bool, minLen, maxLen int) {
	codes = map[string]bool{}
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		codes[line] = true
		n := len(line)
		if minLen == 0 || n < minLen {
			minLen = n
		}
		if n > maxLen {
			maxLen = n
		}
	}
	return codes, minLen, maxLen
}

// ValidAreaCode は digits（先頭が "0" の数字文字列。市外局番から始まる国内表記の
// 電話番号）に対して、先頭から最長一致する実在の市外局番を探す。
// 市外局番の桁数体系はどの符号も他の符号のプレフィックスにならない
// プレフィックスフリー符号のため、長い桁数から順に完全一致を試せば
// 高々 1 つの一致に定まる。一致すれば市外局番の桁数（先頭の 0 を含む）と
// true を返す。
func ValidAreaCode(digits string) (codeLen int, ok bool) {
	return matchAreaCode(areaCodes, areaCodeMinLen, areaCodeMaxLen, digits)
}

// matchAreaCode は ValidAreaCode の下請け。埋め込みデータから切り離してあり、
// 最長一致ロジックだけを手作りの符号集合でテストできる。
func matchAreaCode(codes map[string]bool, minLen, maxLen int, digits string) (codeLen int, ok bool) {
	if minLen <= 0 {
		return 0, false
	}
	n := maxLen
	if len(digits) < n {
		n = len(digits)
	}
	for ; n >= minLen; n-- {
		if codes[digits[:n]] {
			return n, true
		}
	}
	return 0, false
}
