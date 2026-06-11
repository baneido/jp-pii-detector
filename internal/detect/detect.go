// Package detect は行単位の PII 検出エンジンを提供する。
package detect

import (
	"strings"

	"github.com/baneido/jp-pii-detecter/internal/config"
	"github.com/baneido/jp-pii-detecter/internal/normalize"
	"github.com/baneido/jp-pii-detecter/internal/rule"
)

// AllowMarker を含む行は検出対象から除外される（意図的なダミー値向け）。
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
	return &Detector{rules: rules, cfg: cfg, minConf: minConf}, nil
}

// Rules は有効なルール一覧を返す。
func (d *Detector) Rules() []rule.Rule { return d.rules }

// ScanContent はファイル内容全体を行に分割して走査する。
func (d *Detector) ScanContent(file, content string) []Finding {
	var findings []Finding
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimSuffix(line, "\r")
		findings = append(findings, d.ScanLine(file, i+1, line)...)
	}
	return findings
}

// ScanLine は 1 行を走査する。lineNo は 1 始まり。
func (d *Detector) ScanLine(file string, lineNo int, line string) []Finding {
	if line == "" || strings.Contains(line, AllowMarker) {
		return nil
	}
	norm := normalize.Line(line)
	lower := strings.ToLower(norm)
	origRunes := []rune(line)

	var found []Finding
	for _, r := range d.rules {
		hasContext := false
		for _, kw := range r.Context {
			if strings.Contains(lower, kw) {
				hasContext = true
				break
			}
		}
		for _, p := range r.Patterns {
			if p.RequireContext && !hasContext {
				continue
			}
			for _, m := range p.Re.FindAllStringSubmatchIndex(norm, -1) {
				start, end := m[0], m[1]
				if len(m) >= 4 && m[2] >= 0 {
					start, end = m[2], m[3]
				}
				entity := norm[start:end]
				if r.Validate != nil && !r.Validate(entity) {
					continue
				}
				if d.allowlisted(entity) {
					continue
				}
				conf := p.Base
				if hasContext && conf < rule.High {
					conf = rule.High
				}
				if conf < d.minConf {
					continue
				}
				// バイトオフセット → ルーン位置（正規化は 1:1 なので元行と一致）
				rs := len([]rune(norm[:start]))
				re := rs + len([]rune(entity))
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

func (d *Detector) allowlisted(entity string) bool {
	for _, sw := range d.cfg.Allowlist.Stopwords {
		if entity == sw || normalize.Line(entity) == normalize.Line(sw) {
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
// （同率なら範囲が長い方）で 1 件に集約する。
// 例: クレジットカード 16 桁の先頭 12 桁にマイナンバーのパターンが
// 重なった場合、検証を通った信頼度の高い方だけを残す。
func resolveOverlaps(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		replaced := false
		drop := false
		for i, kept := range out {
			if f.start >= kept.end || f.end <= kept.start {
				continue
			}
			if better(f, kept) {
				out[i] = f
				replaced = true
			} else {
				drop = true
			}
			break
		}
		if !replaced && !drop {
			out = append(out, f)
		}
	}
	return out
}

func better(a, b Finding) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	return (a.end - a.start) > (b.end - b.start)
}
