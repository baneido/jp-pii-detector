package detect

import (
	"strings"

	"github.com/baneido/jp-pii-detecter/internal/normalize"
)

const negativeContextWindowRunes = 20

func (d *Detector) hasCrossLineNegativeContext(f Finding, lines []string, lineIdx int) bool {
	if lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}
	var negCtx []string
	for _, r := range d.rules {
		if r.ID == f.RuleID {
			negCtx = r.NegativeContext
			break
		}
	}
	if len(negCtx) == 0 {
		return false
	}

	var parts []string
	offset := 0
	if lineIdx > 0 {
		prev := normalize.Line(lines[lineIdx-1])
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
	parts = append(parts, curr)
	if lineIdx+1 < len(lines) {
		parts = append(parts, normalize.Line(lines[lineIdx+1]))
	}

	combined := strings.Join(parts, "\n")
	// 隣接行を同一視してチェックするため改行を空白に置き換える。
	// 改行と空白は両方とも 1 バイトなのでオフセットは変わらない。
	combined = strings.ReplaceAll(combined, "\n", " ")
	var runes []rune
	return d.hasNegativeContextNear(combined, offset+byteStart, offset+byteEnd, negativeContextWindowRunes, &runes, negCtx)
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
		switch {
		case isCurrencyPrefix(kw):
			if hasUnitBefore(rs, runeStart, radius, []rune(kw)) {
				return true
			}
		case isCurrencySuffix(kw):
			if hasUnitAfter(rs, runeEnd, radius, []rune(kw), false) {
				return true
			}
		case isCounterSuffix(kw):
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

func isCurrencyPrefix(kw string) bool {
	switch kw {
	case "¥", "￥", "$":
		return true
	}
	return false
}

func isCurrencySuffix(kw string) bool {
	switch kw {
	case "円", "千", "万", "億", "%", "％":
		return true
	}
	return false
}

func isCounterSuffix(kw string) bool {
	switch kw {
	case "人", "名", "件", "個", "回", "点":
		return true
	}
	return false
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
	return !requireBoundary || unitEnd == len(rs) || !isJapaneseLetter(rs[unitEnd])
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

func isJapaneseLetter(r rune) bool {
	return (r >= 0x3040 && r <= 0x30ff) || (r >= 0x3400 && r <= 0x9fff)
}
