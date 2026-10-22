package model

import (
	"strings"
	"unicode"

	"github.com/baneido/jp-pii-detector/internal/dict"
	"github.com/baneido/jp-pii-detector/internal/external"
)

// 2 段階方式（既定）: モデルに読ませる前に、確認器（confirm.go）が報告しうる
// 候補を含みうる行だけを安価な判定で選び、その行（と前後の文脈行）だけを推論する。
//
// 確認器は、モデルのスパンを次の形でしか報告しない（confirm / confirmSpan）。
//   - 数字系（電話・口座・カード・マイナンバー・郵便番号）: 数字と区切りだけの
//     値で、組み込みルールの書式に一致するもの → 7 桁以上の数字の並び
//   - 生年月日: 3 つ以上の数の組 → 数の組が 3 つ以上ある数字の並び
//   - メール: @ を含む値、またはローマ字の姓名辞書に一致する 2 語
//   - 住所: 番地（算用数字・漢数字＋丁目/番/号）を含む値
//   - 氏名: 漢字・かな、またはローマ字の姓名辞書に一致する語・大文字始まりの 2〜4 語
//
// 日本語（漢字・かな・全角英数）を含む行、@ を含む行、上の数字の並びを含む行、
// ローマ字の姓名らしい 2 語を含む行は、確認器を通りうる候補を含みうるので選ぶ。
// それ以外の行（ASCII だけのコードの大半）は、確認器がどの種別でも報告しないので
// 推論を省いても結果は変わらない（文脈として前後 1 行を含めるので、ラベルの行が
// 落ちてモデルの判断が変わることも抑える）。
//
// 選んだ行は、元の行のまま（列がずれないように）連結し、連続しない区間の間には
// 空行を 1 つ挟んでモデルに読ませる。候補の行番号は元の行へ戻す。

// contextLines は、選んだ行の前後に文脈として含める行数。
const contextLines = 1

// maxCandidateLineBytes を超える長い行（minify された JS・埋め込みデータ等）は候補に
// しない。推論コストが行の長さに比例する一方、人が書いた個人情報が載ることはまれで、
// 組み込みルールは引き続きその行も走査する（--model-full なら推論する）。
const maxCandidateLineBytes = 4096

// SetFullScan を true にすると、2 段階方式を使わずテキスト全体を推論する
// （--model-full。比較・切り分け用）。Recognize を並行に呼ぶ前に設定すること。
func (r *Recognizer) SetFullScan(full bool) { r.full = full }

// recognizeSelected は、候補を含みうる行と文脈行だけを推論する。
func (r *Recognizer) recognizeSelected(text string) ([]external.Candidate, error) {
	lines := strings.Split(text, "\n")
	sel := selectLines(lines)
	n := 0
	for _, s := range sel {
		if s {
			n++
		}
	}
	switch {
	case n == 0:
		return nil, nil
	case n == len(lines):
		return r.recognizeAll(text)
	}
	short, orig := joinSelected(lines, sel)
	cands, err := r.recognizeAll(short)
	if err != nil {
		return nil, err
	}
	return remapLines(cands, orig), nil
}

// joinSelected は選んだ行を元の行のまま連結する（連続しない区間の間には空行を 1 つ
// 挟む）。orig[i] は縮めたテキストの i 行目（0 始まり）に対応する元の行
// （区切りの空行は -1）。
func joinSelected(lines []string, sel []bool) (string, []int) {
	orig := make([]int, 0, len(lines))
	var b strings.Builder
	prev := -2
	for i, s := range sel {
		if !s {
			continue
		}
		if len(orig) > 0 {
			b.WriteByte('\n')
			if i != prev+1 {
				orig = append(orig, -1)
				b.WriteByte('\n')
			}
		}
		b.WriteString(lines[i])
		orig = append(orig, i)
		prev = i
	}
	return b.String(), orig
}

// remapLines は縮めたテキストでの候補の行番号（1 始まり）を元の行番号へ戻す。
// 区切りの空行や範囲外の候補は捨てる。列・長さは行の中身を変えていないのでそのまま。
func remapLines(cands []external.Candidate, orig []int) []external.Candidate {
	out := cands[:0]
	for _, c := range cands {
		if c.Line < 1 || c.Line > len(orig) || orig[c.Line-1] < 0 {
			continue
		}
		c.Line = orig[c.Line-1] + 1
		out = append(out, c)
	}
	return out
}

// selectLines は、推論する行（候補を含みうる行と、その前後 contextLines 行）を返す。
func selectLines(lines []string) []bool {
	sel := make([]bool, len(lines))
	for i, l := range lines {
		if !candidateLine(l) {
			continue
		}
		for j := max(0, i-contextLines); j <= min(len(lines)-1, i+contextLines); j++ {
			sel[j] = true
		}
	}
	return sel
}

// candidateLine は、行が確認器を通りうる候補を含みうるかを返す。
func candidateLine(l string) bool {
	if len(l) > maxCandidateLineBytes {
		return false
	}
	ascii := true
	at := false
	for i := 0; i < len(l); i++ {
		c := l[i]
		if c >= 0x80 {
			ascii = false
			break
		}
		if c == '@' {
			at = true
		}
	}
	if at {
		return true
	}
	if !ascii {
		for _, r := range l {
			if japaneseRune(r) {
				return true
			}
		}
	}
	return numericCandidate(l) || romajiNameCandidate(l)
}

// japaneseRune は漢字・かな・全角英数（と長音符・中黒）かを返す。
func japaneseRune(r rune) bool {
	switch {
	case r < 0x3000:
		return false
	case unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana):
		return true
	case r >= 0xFF01 && r <= 0xFF5E: // 全角英数・記号
		return true
	case r == 'ー' || r == '・' || r == '々' || r == '〒':
		return true
	}
	return false
}

// numericCandidate は、数字と区切り（confirm の numericShape と同じ "-+()./ "）の並びで、
// 7 桁以上の数字を含むもの、または 3 つ以上の数の組（生年月日）で 5 桁以上のものがあるかを返す。
func numericCandidate(l string) bool {
	digits, groups, inDigit := 0, 0, false
	for i := 0; i <= len(l); i++ {
		var c byte
		if i < len(l) {
			c = l[i]
		}
		switch {
		case c >= '0' && c <= '9':
			digits++
			if !inDigit {
				groups++
			}
			inDigit = true
			continue
		case c != 0 && strings.IndexByte("-+()./ ", c) >= 0:
			inDigit = false
			continue
		}
		if digits >= 7 || (groups >= 3 && digits >= 5) {
			return true
		}
		digits, groups, inDigit = 0, 0, false
	}
	return false
}

// romajiNameCandidate は、ローマ字の姓・名の辞書に一致する語の隣に、大文字で始まる語か
// 辞書に一致する語が続く 2 語があるかを返す（confirmSpan の romajiName と、
// capitalizedWords のうち日本人名らしいもの）。
func romajiNameCandidate(l string) bool {
	var prev string
	prevCap, prevDict := false, false
	for _, w := range asciiWords(l) {
		if w == "" {
			prev, prevCap, prevDict = "", false, false
			continue
		}
		lw := strings.ToLower(w)
		inDict := dict.IsRomajiSurname(lw) || dict.IsRomajiGivenName(lw)
		capd := w[0] >= 'A' && w[0] <= 'Z'
		if prev != "" && ((inDict && (prevDict || prevCap)) || (prevDict && capd)) {
			return true
		}
		prev, prevCap, prevDict = w, capd, inDict
	}
	return false
}

// asciiWords は英字だけの語を、空白 1 つで隣り合うものが連続するように返す。英字以外の
// 文字（空白 1 つを除く）を挟むと連続しない（空の語を挟んで区切る）。
func asciiWords(l string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(l); i++ {
		var c byte = ' '
		if i < len(l) {
			c = l[i]
		}
		letter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if letter {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			out = append(out, l[start:i])
			start = -1
			if c != ' ' {
				out = append(out, "")
			}
		} else if len(out) > 0 && out[len(out)-1] != "" {
			out = append(out, "")
		}
	}
	return out
}
