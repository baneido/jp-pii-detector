package rule

import (
	"regexp"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// 2026-11-26 の公開文書の走査（1,538 件）で、既定モードのルールが全モードで取りこぼしていた氏名の形
// （person-name-role-label）。人を指す語のある無作為 460 行に人手で付けた正解（姓+名 119 人）のうち、
// 裁判所の判決書（PDF をレイアウトを保って文字にしたもの）の末尾の署名 28 人は 1 人も拾えていなかった。

// personNameJudgeSignatureSpacedRe は判決書の末尾の署名「裁判長裁判官　<姓>　<名>」のように、行全体が
// 「裁判官」「裁判長裁判官」と、1 字ずつ空白で区切った氏名である形（最高裁判所の判決書の PDF を
// pdftotext -layout などで文字にすると、均等割付の署名が「山   田   太   郎」のように 1 字ずつ離れる）。
// 字と字の間の空白の幅はそろわない（姓と名の境目が広いとは限らない）ので、空白を除いて検証する
// （validJudgeSignatureName）。値の範囲は空白を含む氏名全体。
var personNameJudgeSignatureSpacedRe = regexp.MustCompile(
	`^[ ]*(?:裁判長裁判官|裁判官)[ ]{2,}((?:[` + kanji + `ツヶケノ][ ]{1,16}){1,5}[` + kanji + `])[ ]*$`,
)

// validJudgeSignatureName は personNameJudgeSignatureSpacedRe の値の検証。1 字ずつ区切った 2〜6 字を
// つないだ文字列が、姓 + 名に分割できる（dict.SplitFullName）か、先頭の 1〜3 字が辞書の姓で残りの
// 1〜3 字が一般語でない形、末尾の 2〜3 字が辞書の名で残りが一般語でない形を通す（「<辞書の姓> <辞書に無い名>」
// の署名、「<名の辞書にだけある姓> <辞書の名>」の署名。行全体が
// 「裁判官」と 1 字ずつの字だけという強い形に限っているので、姓・名の両方の辞書までは求めない）。
func validJudgeSignatureName(v string) bool {
	fields := strings.Fields(v)
	if len(fields) < 2 || len(fields) > 6 {
		return false
	}
	for _, f := range fields {
		if len([]rune(f)) != 1 {
			return false
		}
	}
	joined := strings.Join(fields, "")
	if !notOrgName(joined) || !notPlaceholderName(joined) {
		return false
	}
	if _, _, ok := dict.SplitFullName(joined); ok {
		return true
	}
	rs := []rune(joined)
	for i := 1; i <= 3 && i < len(rs); i++ {
		rest := string(rs[i:])
		if n := len(rs) - i; n > 3 {
			continue
		}
		if dict.IsSurname(string(rs[:i])) && !dict.IsCommonWord(rest) && !dict.IsSurname(rest) {
			return true
		}
	}
	// 姓が辞書に無く名が辞書にある署名（姓と同じ字が名の辞書にだけある場合を含む）。名は 2 字以上に限る。
	for i := 1; i <= 3 && i < len(rs); i++ {
		head, rest := string(rs[:i]), string(rs[i:])
		if n := len(rs) - i; n < 2 || n > 3 {
			continue
		}
		if dict.IsGivenName(rest) && !dict.IsCommonWord(head) {
			return true
		}
	}
	return false
}
