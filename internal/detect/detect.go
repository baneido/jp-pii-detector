// Package detect は行単位の PII 検出エンジンを提供する。
package detect

import (
	"sort"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/normalize"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// IgnoreMarker を含む行は検出対象から除外される（意図的なダミー値向け）。
const IgnoreMarker = "jp-pii-detector:ignore"

// AllowMarker は後方互換のために残している旧除外マーカー。
const AllowMarker = "pii-allow"

// Finding は 1 件の検出結果。
//
// 注意: この型は出力スキーマではない。機械可読な出力（json/sarif 等）は
// internal/report の jsonFinding を経由し、値は既定でマスクされる。Finding を
// 直接 json.Marshal する経路は存在しないが、誤って marshal しても生の PII を
// 漏らさないよう、生値を保持する Match は json:"-" でシリアライズ対象から外す。
type Finding struct {
	RuleID      string          `json:"rule_id"`
	Description string          `json:"description"`
	File        string          `json:"file"`
	Line        int             `json:"line"`   // 1 始まり
	Column      int             `json:"column"` // 1 始まり（ルーン単位）
	Match       string          `json:"-"`      // 元テキスト（生値。マスクは出力層で行う。直接 marshal では出さない）
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
		// リテラルプレフィルタ: ラベル語を 1 つも含まない行は、このルールの
		// 正規表現走査をまるごとスキップする（氏名ルールのホットパス最適化）。
		if len(r.PrefilterLiterals) > 0 && !containsAnyLiteral(norm, r.PrefilterLiterals) {
			continue
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
				if p.Validate != nil {
					if !p.Validate(entity) {
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

// containsAnyLiteral は haystack に literals のいずれかが含まれるかを返す
// （リテラルプレフィルタ用。OR 条件）。
func containsAnyLiteral(haystack string, literals []string) bool {
	for _, lit := range literals {
		if strings.Contains(haystack, lit) {
			return true
		}
	}
	return false
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
