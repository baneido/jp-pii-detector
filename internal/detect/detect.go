// Package detect は行単位の PII 検出エンジンを提供する。
package detect

import (
	"strings"

	"github.com/baneido/jp-pii-detecter/internal/config"
	"github.com/baneido/jp-pii-detecter/internal/normalize"
	"github.com/baneido/jp-pii-detecter/internal/rule"
)

// IgnoreMarker を含む行は検出対象から除外される（意図的なダミー値向け）。
const IgnoreMarker = "jp-pii-detector:ignore"

// AllowMarker は後方互換のために残している旧除外マーカー。
const AllowMarker = "pii-allow"

// Finding は 1 件の検出結果。
type Finding struct {
	RuleID      string          `json:"rule_id"`
	Description string          `json:"description"`
	File        string          `json:"file"`
	Line        int             `json:"line"`   // 1 始まり
	Column      int             `json:"column"` // 1 始まり（ルーン単位）
	Match       string          `json:"match"`  // 元テキスト（マスクは出力層で行う）
	Confidence  rule.Confidence `json:"-"`
	// span（ルーン単位、重複解決用）
	start, end int
}

// Detector は設定を適用済みの検出エンジン。
type Detector struct {
	rules   []rule.Rule
	cfg     *config.Config
	minConf rule.Confidence
	// normStopwords は正規化済みの stopword（マッチ文字列は常に正規化済みのため）。
	normStopwords []string
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
	return &Detector{rules: rules, cfg: cfg, minConf: minConf, normStopwords: normStopwords}, nil
}

// Rules は有効なルール一覧を返す。
func (d *Detector) Rules() []rule.Rule { return d.rules }

// ScanContent はファイル内容全体を行に分割して走査する。
func (d *Detector) ScanContent(file, content string) []Finding {
	var findings []Finding
	lineNo := 0
	for line := range strings.SplitSeq(content, "\n") {
		lineNo++
		line = strings.TrimSuffix(line, "\r")
		findings = append(findings, d.ScanLine(file, lineNo, line)...)
	}
	return findings
}

// ScanLine は 1 行を走査する。lineNo は 1 始まり。
func (d *Detector) ScanLine(file string, lineNo int, line string) []Finding {
	if line == "" || ignoredLine(line) {
		return nil
	}
	norm := normalize.Line(line)
	hasDigit, hasAt, hasCJK := classifyLine(norm)

	// 小文字化・コンテキスト判定・元行のルーン展開はコストが高いため、
	// 必要になるまで遅延させる（大半の行はどのパターンにもマッチしない）。
	var lower string
	lowered := false
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
		ctxComputed, hasContext := false, false
		ctx := func() bool {
			if !ctxComputed {
				if !lowered {
					lower = strings.ToLower(norm)
					lowered = true
				}
				for _, kw := range r.Context {
					if strings.Contains(lower, kw) {
						hasContext = true
						break
					}
				}
				ctxComputed = true
			}
			return hasContext
		}
		for _, p := range r.Patterns {
			if p.RequireContext && !ctx() {
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
				if r.Validate != nil && !r.Validate(entity) {
					continue
				}
				if d.allowlisted(entity) {
					continue
				}
				// RequireContext のパターンはキーワードの存在が検出の前提
				// であり昇格の根拠にならないため、Base の信頼度のまま報告する
				// （口座番号などの△ルールが常に high になるのを防ぐ）。
				conf := p.Base
				if !p.RequireContext && conf < rule.High && ctx() {
					conf = rule.High
				}
				if conf < d.minConf {
					continue
				}
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
