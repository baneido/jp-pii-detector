package detect

import (
	"strings"

	"github.com/baneido/jp-pii-detector/internal/normalize"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

const negativeContextWindowRunes = 20

// lineIdx は隣接行相関で検出された finding が乗る行（0 始まり）。前後の
// 論理隣接行（間が空白のみで最大 maxAdjacentLineGap 行差までの非空白行）を
// 見て負コンテキストを判定する。ScanContent の隣接行相関（scanAdjacentLines）が
// 空行を挟んだラベルまで届くようになったのに合わせ、ここも同じ規則で空行を
// スキップしないと、口座番号の直後に空行を挟んだ先に金額の単位（円）が
// 続くようなケースで、負コンテキストによる抑制を取りこぼす。
func (d *Detector) hasCrossLineNegativeContext(f Finding, lines []string, lineContexts []lineContext, lineIdx int) bool {
	if lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}
	var negCtx, posCtx []string
	for _, r := range d.rules {
		if r.ID == f.RuleID {
			negCtx = r.NegativeContext
			posCtx = r.Context
			break
		}
	}
	if len(negCtx) == 0 {
		return false
	}

	var parts []string
	offset := 0
	if p := prevNonBlankIndex(lines, lineIdx, maxAdjacentLineGap); p >= 0 {
		prev := normalize.Line(lines[p])
		parts = append(parts, prev)
		offset = len(prev) + 1 // 改行 1 バイト分
	}
	curr := normalize.Line(lines[lineIdx])
	currRunes := []rune(curr)
	if f.start > len(currRunes) || f.end > len(currRunes) {
		return false
	}
	byteStart := len(string(currRunes[:f.start]))
	byteEnd := len(string(currRunes[:f.end]))

	// 同一文に（負文脈語を伴わない）このルール自身の正ラベルが明示されている
	// 場合は、隣接行にある一般的な負文脈語（金額単位・件数等）で誤って棄却
	// しない（正ラベル優先。issue #68 段階1(a)）。値自身のラベルが id/count 等の
	// 負文脈語を伴う場合は対象外で、この経路に到達する前に呼び出し側
	// （scanLineNoIgnoreWithContext の hasNegativeNear）で既に棄却されている。
	if lineIdx < len(lineContexts) {
		st := lineContexts[lineIdx].statementFor(byteStart, byteEnd)
		if d.statementHasCleanPositiveLabel(st, posCtx) {
			return false
		}
	}

	parts = append(parts, curr)
	if n := nextNonBlankIndex(lines, lineIdx, maxAdjacentLineGap); n >= 0 {
		parts = append(parts, normalize.Line(lines[n]))
	}

	combined := strings.Join(parts, "\n")
	// 隣接行を同一視してチェックするため改行を空白に置き換える。
	// 改行と空白は両方とも 1 バイトなのでオフセットは変わらない。
	combined = strings.ReplaceAll(combined, "\n", " ")
	var runes []rune
	return d.hasNegativeContextNear(combined, offset+byteStart, offset+byteEnd, negativeContextWindowRunes, &runes, negCtx)
}

// statementHasCleanPositiveLabel は st がこのルール自身の Context キーワードに
// 一致する正ラベルを持ち、かつ負文脈語（NegativeText、例: id・count 等）を
// 伴わないかを返す。true の場合、呼び出し側は近傍の一般的な負文脈語（金額単位・
// 件数等）で値を誤って棄却しないでよい（正ラベル優先）。
//
// bankAccountId のように正ラベルの語（account 等）を含みつつも id 等の負文脈語を
// 伴うラベルは対象外とし、その場合は従来通り NegativeText による棄却を優先する
// （呼び出し側で個別にチェックする）。
func (d *Detector) statementHasCleanPositiveLabel(st *statementContext, ctx []string) bool {
	if st == nil || st.PositiveText == "" || st.NegativeText != "" {
		return false
	}
	return len(d.matchingContexts(st.PositiveText, ctx)) > 0
}

func (d *Detector) hasNegativeContextNear(s string, start, end, radius int, runes *[]rune, kws []string) bool {
	if *runes == nil {
		*runes = []rune(s)
	}
	rs := *runes
	runeStart := len([]rune(s[:start]))
	runeEnd := runeStart + len([]rune(s[start:end]))

	var generic []string
	for _, kw := range kws {
		switch rule.ClassifyNegativeKeyword(kw) {
		case rule.NegativeKeywordCurrencyPrefix, rule.NegativeKeywordLabelPrefix:
			// 通貨記号（¥100）と採番ラベル（伝票番号 100...）は、どちらも
			// 値の直前に隣接する場合のみ抑制する（hasUnitBefore）。
			if hasUnitBefore(rs, runeStart, radius, []rune(kw)) {
				return true
			}
		case rule.NegativeKeywordCurrencySuffix:
			if hasUnitAfter(rs, runeEnd, radius, []rune(kw), false) {
				return true
			}
		case rule.NegativeKeywordCounterSuffix:
			if hasUnitAfter(rs, runeEnd, radius, []rune(kw), true) {
				return true
			}
		default:
			generic = append(generic, kw)
		}
	}
	if len(generic) == 0 {
		return false
	}
	return d.containsAnyContext(contextWindow(s, start, end, radius, runes), generic)
}

func hasUnitBefore(rs []rune, start, radius int, unit []rune) bool {
	if len(unit) == 0 {
		return false
	}
	i := start - 1
	from := start - radius
	if from < 0 {
		from = 0
	}
	for i >= from && (rs[i] == ' ' || rs[i] == '\t') {
		i--
	}
	unitStart := i - len(unit) + 1
	if unitStart < from {
		return false
	}
	return runesEqual(rs[unitStart:i+1], unit)
}

func hasUnitAfter(rs []rune, end, radius int, unit []rune, requireBoundary bool) bool {
	if len(unit) == 0 {
		return false
	}
	i := end
	to := end + radius
	if to > len(rs) {
		to = len(rs)
	}
	for i < to && (rs[i] == ' ' || rs[i] == '\t') {
		i++
	}
	unitEnd := i + len(unit)
	if unitEnd > to || !runesEqual(rs[i:unitEnd], unit) {
		return false
	}
	// requireBoundary はカウンタ接尾語（件・人 等）専用。直後が漢字なら
	// 「件名」「名義」のような漢字複合語の一部とみなし、単位としては
	// 扱わない（境界不成立）。ひらがな（件に/件が/件を のような助詞続き）や
	// 記号・行末は単位として独立しているとみなし、抑制を適用する。
	return !requireBoundary || unitEnd == len(rs) || !isKanji(rs[unitEnd])
}

func runesEqual(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// isKanji は CJK 統合漢字（拡張 A を含む）かどうかを返す。ひらがな・
// カタカナはここに含めない（hasUnitAfter の requireBoundary が、助詞続き
// （件に/件が 等）と漢字複合語（件名 等）を区別するために使う）。
func isKanji(r rune) bool {
	return r >= 0x3400 && r <= 0x9fff
}
