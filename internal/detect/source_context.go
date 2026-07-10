package detect

import (
	"path/filepath"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/normalize"
)

type sourceKind int

const (
	sourceKindNone sourceKind = iota
	sourceKindCode
)

type statementContext struct {
	Start        int
	End          int
	PositiveText string
	NegativeText string
}

type lineContext struct {
	Statements []statementContext
}

func (c lineContext) statementFor(start, end int) *statementContext {
	for i := range c.Statements {
		st := &c.Statements[i]
		if start >= st.Start && end <= st.End {
			return st
		}
	}
	return nil
}

var sourceExtensions = map[string]bool{
	".go":         true,
	".js":         true,
	".jsx":        true,
	".mjs":        true,
	".cjs":        true,
	".ts":         true,
	".tsx":        true,
	".py":         true,
	".rb":         true,
	".java":       true,
	".kt":         true,
	".kts":        true,
	".scala":      true,
	".swift":      true,
	".c":          true,
	".h":          true,
	".cc":         true,
	".cpp":        true,
	".cxx":        true,
	".hpp":        true,
	".m":          true,
	".mm":         true,
	".cs":         true,
	".rs":         true,
	".php":        true,
	".sh":         true,
	".bash":       true,
	".zsh":        true,
	".sql":        true,
	".json":       true,
	".jsonc":      true,
	".yaml":       true,
	".yml":        true,
	".toml":       true,
	".properties": true,
}

var sourceContextSkipTokens = map[string]bool{
	"any":       true,
	"bool":      true,
	"boolean":   true,
	"class":     true,
	"const":     true,
	"declare":   true,
	"default":   true,
	"def":       true,
	"export":    true,
	"final":     true,
	"float":     true,
	"func":      true,
	"function":  true,
	"int":       true,
	"int32":     true,
	"int64":     true,
	"interface": true,
	"let":       true,
	"local":     true,
	"new":       true,
	"number":    true,
	"private":   true,
	"protected": true,
	"public":    true,
	"readonly":  true,
	"return":    true,
	"static":    true,
	"string":    true,
	"type":      true,
	"var":       true,
}

var sourceContextNegativeTokens = map[string]bool{
	"amount":   true,
	"build":    true,
	"checksum": true,
	"count":    true,
	"guid":     true,
	"hash":     true,
	"id":       true,
	"invoice":  true,
	"length":   true,
	"limit":    true,
	"offset":   true,
	"order":    true,
	"port":     true,
	"price":    true,
	"receipt":  true,
	"revision": true,
	"size":     true,
	"token":    true,
	"total":    true,
	"uuid":     true,
	"version":  true,
	"yen":      true,
}

func sourceKindForPath(path string) sourceKind {
	base := strings.ToLower(filepath.Base(path))
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return sourceKindCode
	}
	if sourceExtensions[strings.ToLower(filepath.Ext(path))] {
		return sourceKindCode
	}
	return sourceKindNone
}

func sourceLineContexts(file string, lines []string) []lineContext {
	out, ok := baseSourceLineContexts(file, lines)
	if !ok {
		return out
	}
	addCrossLineSourceContexts(out, lines, func(_, _ int, tokens []string) string {
		return sourceNegativeText(tokens)
	})
	return out
}

func sourceLineContextsForDiff(file string, lines []string, added []bool) []lineContext {
	out, ok := baseSourceLineContexts(file, lines)
	if !ok {
		return out
	}
	addCrossLineSourceContexts(out, lines, func(keyLine, valueLine int, tokens []string) string {
		if keyLine < len(added) && valueLine < len(added) && !added[keyLine] && added[valueLine] {
			return ""
		}
		return sourceNegativeText(tokens)
	})
	return out
}

func baseSourceLineContexts(file string, lines []string) ([]lineContext, bool) {
	out := make([]lineContext, len(lines))
	if sourceKindForPath(file) == sourceKindNone {
		return out, false
	}
	for i, line := range lines {
		out[i].Statements = extractLineStatements(normalize.Line(line))
	}
	return out, true
}

func extractLineStatements(norm string) []statementContext {
	var out []statementContext
	for _, seg := range splitSourceStatements(norm) {
		st, ok := statementContextFromSegment(norm, seg.start, seg.end)
		if ok {
			out = append(out, st)
		}
	}
	return out
}

type sourceSegment struct {
	start int
	end   int
}

func splitSourceStatements(line string) []sourceSegment {
	var out []sourceSegment
	start := 0
	var quote byte
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '`' || (c == '"' || c == '\'') && quoteStartsAt(line, i) {
			quote = c
			continue
		}
		switch c {
		case ';', ',':
			if start < i {
				out = append(out, sourceSegment{start: start, end: i})
			}
			start = i + 1
		}
	}
	if start < len(line) {
		out = append(out, sourceSegment{start: start, end: len(line)})
	}
	return out
}

// quoteStartsAt は line[i]（ダブルクォート・シングルクォートのいずれか）を
// 文字列リテラルの開始とみなすべきかを返す。バッククォートは JS/TS の
// tagged template literal（sql`...` 等）で識別子に直結できるため、呼び出し側で
// 常に文字列リテラルの開始として扱う。
// 素朴な実装（#39 まで）はクォート文字が出た時点で無条件に
// クォート開始とみなしていたため、コメント中の英語の省略形（don't 等）の
// アポストロフィが「文字列開始」と誤認され、以降の行末までが（閉じクォートが
// 現れるまで）丸ごと引用中として扱われて文脈抽出が失われていた（#54）。
//
// 識別子の内部（直前が英数字・_）にあるクォート文字は開始とみなさない。
// 行頭・空白・区切り記号（`([{,:;=+-*/<>!&|~^?%` 等）の直後、または
// Python の f"..." / r'...' / rb"..." のような 1〜2 文字の文字列プレフィックス
// （さらにその直前が区切り記号）の直後のみ、クォート開始として扱う。
func quoteStartsAt(s string, i int) bool {
	if i == 0 {
		return true
	}
	if isQuoteBoundaryByte(s[i-1]) {
		return true
	}
	// f"..." / r'...' / rb"..." 等、1〜2 文字の文字列プレフィックス直後の
	// クォートは、プレフィックスがさらに区切り記号（または行頭）から
	// 始まっている場合のみ開始とみなす。
	prefixLen := 0
	j := i - 1
	for j >= 0 && prefixLen < 2 && isStringPrefixByte(s[j]) {
		prefixLen++
		j--
	}
	if prefixLen == 0 {
		return false
	}
	if j < 0 {
		return true
	}
	return isQuoteBoundaryByte(s[j])
}

// isQuoteBoundaryByte は、直後にクォート文字が来たときそれを文字列リテラルの
// 開始とみなしてよい区切りバイト（空白・演算子・括弧等）かを返す。
func isQuoteBoundaryByte(c byte) bool {
	switch c {
	case ' ', '\t', '(', '[', '{', ',', ':', ';', '=', '+', '-', '*', '/', '<', '>', '!', '&', '|', '~', '^', '?', '%':
		return true
	}
	return false
}

// isStringPrefixByte は Python の f/r/b/u 等、文字列リテラルの接頭辞として
// 使われる英字かを返す（大文字小文字を区別しない）。
func isStringPrefixByte(c byte) bool {
	switch c {
	case 'f', 'F', 'r', 'R', 'b', 'B', 'u', 'U':
		return true
	}
	return false
}

func statementContextFromSegment(line string, start, end int) (statementContext, bool) {
	segment := line[start:end]
	relOp, opLen, ok := findSourceAssignmentOperator(segment)
	if !ok {
		return statementContext{}, false
	}
	left := segment[:relOp]
	valueStart := start + relOp + opLen
	valueStart = skipSpaces(line, valueStart, end)
	if valueStart >= end {
		return statementContext{}, false
	}
	tokens := sourceLabelTokens(left)
	if len(tokens) == 0 {
		return statementContext{}, false
	}
	return statementContext{
		Start:        valueStart,
		End:          trimRightSpaces(line, valueStart, end),
		PositiveText: strings.Join(tokens, " "),
		NegativeText: sourceNegativeText(tokens),
	}, true
}

func findSourceAssignmentOperator(segment string) (pos, width int, ok bool) {
	if i := indexUnquotedByte(segment, func(i int) bool {
		return i+1 < len(segment) && segment[i] == ':' && segment[i+1] == '='
	}); i >= 0 {
		return i, 2, true
	}
	if i := indexUnquotedByte(segment, func(i int) bool {
		return segment[i] == ':'
	}); i >= 0 {
		return i, 1, true
	}
	if i := indexUnquotedByte(segment, func(i int) bool {
		if segment[i] != '=' {
			return false
		}
		if i > 0 {
			switch segment[i-1] {
			case '=', '!', '<', '>':
				return false
			}
		}
		return i+1 >= len(segment) || segment[i+1] != '='
	}); i >= 0 {
		return i, 1, true
	}
	return 0, 0, false
}

func indexUnquotedByte(s string, match func(i int) bool) int {
	var quote byte
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '`' || (c == '"' || c == '\'') && quoteStartsAt(s, i) {
			quote = c
			continue
		}
		if match(i) {
			return i
		}
	}
	return -1
}

func sourceLabelTokens(label string) []string {
	raw := tokenizeIdentifiers(label)
	tokens := raw[:0]
	for _, tok := range raw {
		if tok == "" || sourceContextSkipTokens[tok] {
			continue
		}
		tokens = append(tokens, tok)
	}
	return tokens
}

func sourceNegativeText(tokens []string) string {
	var neg []string
	for _, tok := range tokens {
		if sourceContextNegativeTokens[tok] {
			neg = append(neg, tok)
		}
	}
	return strings.Join(neg, " ")
}

func skipSpaces(s string, pos, end int) int {
	for pos < end && (s[pos] == ' ' || s[pos] == '\t') {
		pos++
	}
	return pos
}

func trimRightSpaces(s string, start, end int) int {
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return end
}

func addCrossLineSourceContexts(ctxs []lineContext, lines []string, negativeText func(keyLine, valueLine int, tokens []string) string) {
	for i := 0; i+1 < len(lines); i++ {
		key := normalize.Line(lines[i])
		tokens, ok := sourceKeyOnlyTokens(key)
		if !ok {
			continue
		}
		value := normalize.Line(lines[i+1])
		start, end, ok := sourceWholeLineValueRange(value)
		if !ok {
			continue
		}
		ctxs[i+1].Statements = append(ctxs[i+1].Statements, statementContext{
			Start:        start,
			End:          end,
			PositiveText: strings.Join(tokens, " "),
			NegativeText: negativeText(i, i+1, tokens),
		})
	}
}

func sourceKeyOnlyTokens(line string) ([]string, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasSuffix(trimmed, ":") {
		return nil, false
	}
	key := strings.TrimSuffix(trimmed, ":")
	tokens := sourceLabelTokens(key)
	return tokens, len(tokens) > 0
}

func sourceWholeLineValueRange(line string) (int, int, bool) {
	start := skipSpaces(line, 0, len(line))
	end := trimRightSpaces(line, start, len(line))
	if start >= end {
		return 0, 0, false
	}
	return start, end, true
}
