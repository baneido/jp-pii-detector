// Package detect は行単位の PII 検出エンジンを提供する。
package detect

import (
	"sort"
	"strings"

	"github.com/baneido/jp-pii-detecter/internal/config"
	"github.com/baneido/jp-pii-detecter/internal/normalize"
	"github.com/baneido/jp-pii-detecter/internal/rule"
)

// IgnoreMarker を含む行は検出対象から除外される（意図的なダミー値向け）。
const IgnoreMarker = "jp-pii-detector:ignore"

// AllowMarker は後方互換のために残している旧除外マーカー。
const AllowMarker = "pii-allow"

const negativeContextWindowRunes = 20

// Finding は 1 件の検出結果。
type Finding struct {
	RuleID      string          `json:"rule_id"`
	Description string          `json:"description"`
	File        string          `json:"file"`
	Line        int             `json:"line"`   // 1 始まり
	Column      int             `json:"column"` // 1 始まり（ルーン単位）
	Match       string          `json:"match"`  // 元テキスト（マスクは出力層で行う）
	Confidence  rule.Confidence `json:"-"`
	// Reason は検出の根拠（調査・チューニング用。既定の出力には含めない）。
	Reason DetectReason `json:"reason,omitempty"`
	// span（ルーン単位、重複解決用）
	start, end int
}

// DetectReason は検出の根拠を表す。生の PII は含めない。
type DetectReason struct {
	BaseConfidence  string   `json:"base_confidence,omitempty"`
	FinalConfidence string   `json:"final_confidence,omitempty"`
	ContextKeywords []string `json:"context_keywords,omitempty"`
	ContextPromoted bool     `json:"context_promoted,omitempty"`
	RequireContext  bool     `json:"require_context,omitempty"`
	ContextWindow   int      `json:"context_window,omitempty"`
	Validated       bool     `json:"validated,omitempty"`
}

// Detector は設定を適用済みの検出エンジン。
type Detector struct {
	rules   []rule.Rule
	cfg     *config.Config
	minConf rule.Confidence
	// normStopwords は正規化済みの stopword（マッチ文字列は常に正規化済みのため）。
	normStopwords []string
	// ctxTokens は ASCII コンテキスト語をあらかじめ識別子トークン列に分割した
	// キャッシュ（キーワードは静的なので行ごとに再分割しないため）。
	ctxTokens map[string][]string
}

// New は設定に基づいて Detector を構築する。
func New(cfg *config.Config) (*Detector, error) {
	minConf, err := rule.ParseConfidence(cfg.MinConfidence)
	if err != nil {
		return nil, err
	}
	disabled := map[string]bool{}
	for _, id := range cfg.Rules.Disabled {
		disabled[id] = true
	}
	var rules []rule.Rule
	for _, r := range rule.Builtin() {
		if !disabled[r.ID] {
			rules = append(rules, r)
		}
	}
	normStopwords := make([]string, len(cfg.Allowlist.Stopwords))
	for i, sw := range cfg.Allowlist.Stopwords {
		normStopwords[i] = normalize.Line(sw)
	}
	// ASCII コンテキスト語のトークン分割はキーワードが静的なため一度だけ行う。
	ctxTokens := map[string][]string{}
	for _, r := range rules {
		for _, kw := range r.Context {
			if asciiOnly(kw) {
				if _, ok := ctxTokens[kw]; !ok {
					ctxTokens[kw] = tokenizeIdentifiers(kw)
				}
			}
		}
		for _, kw := range r.NegativeContext {
			if asciiOnly(kw) {
				if _, ok := ctxTokens[kw]; !ok {
					ctxTokens[kw] = tokenizeIdentifiers(kw)
				}
			}
		}
	}
	return &Detector{rules: rules, cfg: cfg, minConf: minConf, normStopwords: normStopwords, ctxTokens: ctxTokens}, nil
}

// Rules は有効なルール一覧を返す。
func (d *Detector) Rules() []rule.Rule { return d.rules }

// ScanContent はファイル内容全体を行に分割して走査する。
func (d *Detector) ScanContent(file, content string) []Finding {
	var lines []string
	for line := range strings.SplitSeq(content, "\n") {
		lines = append(lines, strings.TrimSuffix(line, "\r"))
	}

	var candidates []Finding
	for i, line := range lines {
		candidates = append(candidates, d.ScanLine(file, i+1, line)...)
	}
	for i := 0; i+1 < len(lines); i++ {
		candidates = append(candidates, d.scanAdjacentLines(file, i+1, lines[i], lines[i+1])...)
	}

	seen := map[string]bool{}
	var findings []Finding
	for _, f := range candidates {
		if d.hasCrossLineNegativeContext(f, lines, f.Line-1) {
			continue
		}
		key := findingKey(f)
		if seen[key] {
			continue
		}
		findings = append(findings, f)
		seen[key] = true
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		if findings[i].Column != findings[j].Column {
			return findings[i].Column < findings[j].Column
		}
		return findings[i].end < findings[j].end
	})
	return findings
}

func findingKey(f Finding) string {
	return f.RuleID + "\x00" + f.File + "\x00" + itoa(f.Line) + "\x00" + itoa(f.start) + "\x00" + itoa(f.end)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

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

func (d *Detector) scanAdjacentLines(file string, firstLineNo int, first, second string) []Finding {
	combined := first + "\n" + second
	firstRunes := []rune(first)
	secondRunes := []rune(second)
	sep := len(firstRunes)

	var out []Finding
	for _, f := range d.ScanLine(file, firstLineNo, combined) {
		if !f.Reason.RequireContext {
			continue
		}
		switch {
		case f.end <= sep:
			f.Line = firstLineNo
			f.Column = f.start + 1
			f.Match = string(firstRunes[f.start:f.end])
		case f.start > sep:
			start := f.start - sep - 1
			end := f.end - sep - 1
			if start < 0 || end > len(secondRunes) {
				continue
			}
			f.Line = firstLineNo + 1
			f.Column = start + 1
			f.Match = string(secondRunes[start:end])
			f.start, f.end = start, end
		default:
			continue
		}
		out = append(out, f)
	}
	return out
}

// ScanLine は 1 行を走査する。lineNo は 1 始まり。
func (d *Detector) ScanLine(file string, lineNo int, line string) []Finding {
	if line == "" || ignoredLine(line) {
		return nil
	}
	norm := normalize.Line(line)
	hasDigit, hasAt, hasCJK := classifyLine(norm)

	// コンテキスト判定・元行のルーン展開はコストが高いため、
	// 必要になるまで遅延させる（大半の行はどのパターンにもマッチしない）。
	var normRunes []rune
	var origRunes []rune

	var found []Finding
	for _, r := range d.rules {
		// 必須文字種を含まない行はパターンマッチ自体をスキップする。
		// 大半のルールは数字必須のため、数字のないコード行がほぼ無コストになる。
		switch r.Prefilter {
		case rule.PrefilterDigit:
			if !hasDigit {
				continue
			}
		case rule.PrefilterAt:
			if !hasAt {
				continue
			}
		case rule.PrefilterCJK:
			if !hasCJK {
				continue
			}
		}
		ctxComputed := false
		var ctxKeywords []string
		ctx := func() []string {
			if !ctxComputed {
				// matchingContexts は内部で小文字化しつつ、トークナイザ用に
				// 元の大文字小文字（camelCase 境界）を保った norm を受け取る。
				ctxKeywords = d.matchingContexts(norm, r.Context)
				ctxComputed = true
			}
			return ctxKeywords
		}
		ctxNear := func(start, end int) []string {
			if r.RequireContextWindow <= 0 {
				return ctx()
			}
			return d.matchingContexts(contextWindow(norm, start, end, r.RequireContextWindow, &normRunes), r.Context)
		}
		hasNegativeNear := func(start, end int) bool {
			if len(r.NegativeContext) == 0 {
				return false
			}
			return d.hasNegativeContextNear(norm, start, end, negativeContextWindowRunes, &normRunes, r.NegativeContext)
		}
		for _, p := range r.Patterns {
			if p.RequireContext && r.RequireContextWindow <= 0 && len(ctx()) == 0 {
				continue
			}
			// FindAll はマッチ全体（末尾の境界ガード文字を含む）の直後から
			// 次を探すため、`090-…-2222,090-…-4444` のように区切りが 1 文字
			// だけの隣接エンティティを取りこぼす。キャプチャ終端から再検索
			// することで、境界文字を次のマッチの先頭ガードとして再利用する。
			// 再検索スライスは常にエンティティ直後の境界文字（非数字等）から
			// 始まるため、`^` がエンティティ途中で誤マッチすることはない。
			for pos := 0; pos < len(norm); {
				m := p.Re.FindStringSubmatchIndex(norm[pos:])
				if m == nil {
					break
				}
				start, end := m[0]+pos, m[1]+pos
				if len(m) >= 4 && m[2] >= 0 {
					start, end = m[2]+pos, m[3]+pos
				}
				next := end
				if next <= pos {
					next = pos + 1 // 空マッチ対策（通常は到達しない）
				}
				pos = next
				entity := norm[start:end]
				reason := DetectReason{
					BaseConfidence: p.Base.String(),
					RequireContext: p.RequireContext,
					ContextWindow:  r.RequireContextWindow,
				}
				if p.RequireContext {
					kws := ctxNear(start, end)
					if len(kws) == 0 {
						continue
					}
					reason.ContextKeywords = kws
				}
				if hasNegativeNear(start, end) {
					continue
				}
				if r.Validate != nil {
					if !r.Validate(entity) {
						continue
					}
					reason.Validated = true
				}
				if d.allowlisted(entity) {
					continue
				}
				// RequireContext のパターンはキーワードの存在が検出の前提
				// であり昇格の根拠にならないため、Base の信頼度のまま報告する
				// （口座番号などの△ルールが常に high になるのを防ぐ）。
				conf := p.Base
				if !p.RequireContext && conf < rule.High {
					kws := ctx()
					if len(kws) > 0 {
						reason.ContextKeywords = kws
						reason.ContextPromoted = true
						conf = rule.High
					}
				}
				if conf < d.minConf {
					continue
				}
				reason.FinalConfidence = conf.String()
				// バイトオフセット → ルーン位置（正規化は 1:1 なので元行と一致）
				rs := len([]rune(norm[:start]))
				re := rs + len([]rune(entity))
				if origRunes == nil {
					origRunes = []rune(line)
				}
				found = append(found, Finding{
					RuleID:      r.ID,
					Description: r.Description,
					File:        file,
					Line:        lineNo,
					Column:      rs + 1,
					Match:       string(origRunes[rs:re]),
					Confidence:  conf,
					Reason:      reason,
					start:       rs,
					end:         re,
				})
			}
		}
	}
	return resolveOverlaps(found)
}

func ignoredLine(line string) bool {
	return strings.Contains(line, IgnoreMarker) || strings.Contains(line, AllowMarker)
}

func (d *Detector) containsAnyContext(haystack string, kws []string) bool {
	return len(d.matchingContexts(haystack, kws)) > 0
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

func (d *Detector) matchingContexts(haystack string, kws []string) []string {
	lower := strings.ToLower(haystack)
	// 識別子トークンは ASCII キーワードが単語境界で見つからなかった
	// 場合のみ必要になるため、最初に要求されるまで分割を遅延する。
	var tokens []string
	tokenized := false
	var out []string
	for _, kw := range kws {
		if containsWord(lower, kw) {
			out = append(out, kw)
			continue
		}
		// 日本語など非 ASCII 語は部分一致（containsWord）が正しいので
		// トークナイザは適用しない。ASCII 語のみ camelCase / snake_case /
		// kebab-case の識別子に分割して照合する。
		if !asciiOnly(kw) {
			continue
		}
		// キーワード側のトークンは New で事前計算済み。未登録の場合のみ分割する。
		kwTokens, ok := d.ctxTokens[kw]
		if !ok {
			kwTokens = tokenizeIdentifiers(kw)
		}
		if !tokenized {
			// camelCase の境界を保つため小文字化前の元文字列を分割する。
			tokens = tokenizeIdentifiers(haystack)
			tokenized = true
		}
		if containsTokenSubsequence(tokens, kwTokens) {
			out = append(out, kw)
		}
	}
	return out
}

// tokenizeIdentifiers は文字列を識別子の構成語トークン列に分割する。
// ASCII 英数字の連なりを、大文字小文字の切れ目（camelCase）・英字と数字の
// 切れ目・非英数字（_ - 空白など）の区切りで分割し、小文字化して返す。
// 例: "bankAccountNo" -> ["bank", "account", "no"]、
//
//	"driver_license_no" -> ["driver", "license", "no"]。
//
// 単語境界（containsWord）では取りこぼす camelCase / snake_case /
// kebab-case のラベルを、誤検出を増やさずにコンテキストとして拾うために使う。
func tokenizeIdentifiers(s string) []string {
	var tokens []string
	var cur []byte
	flush := func() {
		if len(cur) > 0 {
			tokens = append(tokens, string(cur))
			cur = cur[:0]
		}
	}
	classOf := func(c byte) byte {
		switch {
		case c >= 'A' && c <= 'Z':
			return 'U'
		case c >= 'a' && c <= 'z':
			return 'L'
		case c >= '0' && c <= '9':
			return 'D'
		}
		return 0 // 区切り文字
	}
	// prev は直前に取り込んだ文字の元の字種（U=大文字 / L=小文字 / D=数字）。
	var prev byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		cc := classOf(c)
		if cc == 0 {
			flush()
			prev = 0
			continue
		}
		if len(cur) > 0 {
			switch {
			// camelCase / 数字→語: 小文字・数字の直後の大文字は新しい語。
			case cc == 'U' && (prev == 'L' || prev == 'D'):
				flush()
			// 連続大文字（頭字語）の末尾: 直後が小文字なら、この大文字から
			// 新しい語が始まる（例: HTTPServer→["http","server"]、APIKey→["api","key"]）。
			case cc == 'U' && prev == 'U' && i+1 < len(s) && classOf(s[i+1]) == 'L':
				flush()
			// 英字と数字の境界で区切る（例: abc123→["abc","123"]）。
			case cc == 'L' && prev == 'D', cc == 'D' && prev == 'L':
				flush()
			}
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		cur = append(cur, c)
		prev = cc
	}
	flush()
	return tokens
}

// containsTokenSubsequence は kwTokens（キーワードを分割したトークン列）が
// tokens の中に連続部分列として現れるかを返す。
func containsTokenSubsequence(tokens, kwTokens []string) bool {
	if len(kwTokens) == 0 || len(kwTokens) > len(tokens) {
		return false
	}
	for i := 0; i+len(kwTokens) <= len(tokens); i++ {
		match := true
		for j, kt := range kwTokens {
			if tokens[i+j] != kt {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func containsWord(haystack, kw string) bool {
	if kw == "" {
		return true
	}
	if !asciiOnly(kw) || !isASCIIAlnum(kw[0]) || !isASCIIAlnum(kw[len(kw)-1]) {
		return strings.Contains(haystack, kw)
	}
	for offset := 0; offset <= len(haystack); {
		i := strings.Index(haystack[offset:], kw)
		if i < 0 {
			return false
		}
		start := offset + i
		end := start + len(kw)
		if !hasASCIIAlnumBefore(haystack, start) && !hasASCIIAlnumAfter(haystack, end) {
			return true
		}
		offset = start + 1
	}
	return false
}

func asciiOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func hasASCIIAlnumBefore(s string, pos int) bool {
	return pos > 0 && isASCIIAlnum(s[pos-1])
}

func hasASCIIAlnumAfter(s string, pos int) bool {
	return pos < len(s) && isASCIIAlnum(s[pos])
}

func isASCIIAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func contextWindow(s string, start, end, radius int, runes *[]rune) string {
	if radius <= 0 {
		return s
	}
	if *runes == nil {
		*runes = []rune(s)
	}
	rs := *runes
	runeStart := len([]rune(s[:start]))
	runeEnd := runeStart + len([]rune(s[start:end]))
	from := runeStart - radius
	if from < 0 {
		from = 0
	}
	to := runeEnd + radius
	if to > len(rs) {
		to = len(rs)
	}
	return string(rs[from:to])
}

// classifyLine は Prefilter 判定に使う文字種の有無を 1 パスで調べる。
func classifyLine(s string) (hasDigit, hasAt, hasCJK bool) {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '@':
			hasAt = true
		case r >= 0x3000: // CJK 記号・かな・漢字はすべて U+3000 以上
			hasCJK = true
		}
		if hasDigit && hasAt && hasCJK {
			break
		}
	}
	return
}

// allowlisted は entity（正規化済みのマッチ文字列）が除外対象かを返す。
func (d *Detector) allowlisted(entity string) bool {
	for i, sw := range d.cfg.Allowlist.Stopwords {
		if entity == sw || entity == d.normStopwords[i] {
			return true
		}
	}
	for _, re := range d.cfg.AllowRegexes() {
		if re.MatchString(entity) {
			return true
		}
	}
	return false
}

// resolveOverlaps は同一行内で範囲が重なる検出を信頼度順
// （同率なら範囲が長い方、それも同率なら先勝ち）で集約する。
// 例: クレジットカード 16 桁の先頭 12 桁にマイナンバーのパターンが
// 重なった場合、検証を通った信頼度の高い方だけを残す。
func resolveOverlaps(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		// 既存のいずれかが f 以上なら f を捨てる。
		drop := false
		for _, kept := range out {
			if overlaps(f, kept) && !better(f, kept) {
				drop = true
				break
			}
		}
		if drop {
			continue
		}
		// f が勝つ場合は、f と重なる既存をすべて取り除いてから加える。
		keep := out[:0]
		for _, kept := range out {
			if !overlaps(f, kept) {
				keep = append(keep, kept)
			}
		}
		out = append(keep, f)
	}
	return out
}

func overlaps(a, b Finding) bool {
	return a.start < b.end && b.start < a.end
}

func better(a, b Finding) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	return (a.end - a.start) > (b.end - b.start)
}
