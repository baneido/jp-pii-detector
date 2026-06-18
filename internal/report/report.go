// Package report は検出結果の出力（text/json/sarif/github）を提供する。
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// Mask は検出値を伏せ字にする。長い値は先頭・末尾のみ残す。
func Mask(s string) string {
	rs := []rune(s)
	n := len(rs)
	switch {
	case n <= 4:
		return strings.Repeat("*", n)
	case n < 8:
		return string(rs[0]) + strings.Repeat("*", n-2) + string(rs[n-1])
	default:
		return string(rs[:2]) + strings.Repeat("*", n-4) + string(rs[n-2:])
	}
}

func display(f detect.Finding, unmask bool) string {
	if unmask {
		return f.Match
	}
	return Mask(f.Match)
}

// Text は人間向けのプレーンテキストを出力する。
func Text(w io.Writer, findings []detect.Finding, unmask bool) {
	for _, f := range findings {
		fmt.Fprintf(w, "%s:%d:%d\t[%s]\t%s\t%s\t%s\n",
			f.File, f.Line, f.Column, f.Confidence, f.RuleID, f.Description, display(f, unmask))
	}
	if len(findings) > 0 {
		fmt.Fprintf(w, "\n%d 件の個人情報らしき記述を検出しました。誤検出の場合は行末コメントに %q を付けるか、設定ファイルの allowlist に追加してください。\n",
			len(findings), detect.IgnoreMarker)
	}
}

type jsonFinding struct {
	RuleID      string               `json:"rule_id"`
	Description string               `json:"description"`
	File        string               `json:"file"`
	Line        int                  `json:"line"`
	Column      int                  `json:"column"`
	Match       string               `json:"match"`
	Confidence  string               `json:"confidence"`
	Reason      *detect.DetectReason `json:"reason,omitempty"`
}

// JSON は機械可読な JSON を出力する。
func JSON(w io.Writer, findings []detect.Finding, unmask, explain bool) error {
	out := struct {
		Findings []jsonFinding `json:"findings"`
		Count    int           `json:"count"`
	}{Findings: []jsonFinding{}, Count: len(findings)}
	for _, f := range findings {
		jf := jsonFinding{
			RuleID:      f.RuleID,
			Description: f.Description,
			File:        f.File,
			Line:        f.Line,
			Column:      f.Column,
			Match:       display(f, unmask),
			Confidence:  f.Confidence.String(),
		}
		if explain {
			jf.Reason = &f.Reason
		}
		out.Findings = append(out.Findings, jf)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// GitHub は GitHub Actions の workflow command 形式で注釈を出力する。
func GitHub(w io.Writer, findings []detect.Finding, unmask bool) {
	for _, f := range findings {
		msg := fmt.Sprintf("%s: %s", f.Description, display(f, unmask))
		fmt.Fprintf(w, "::error file=%s,line=%d,col=%d,title=PII detected (%s)::%s\n",
			escapeGHProp(f.File), f.Line, f.Column, f.RuleID, escapeGH(msg))
	}
}

func escapeGH(s string) string {
	r := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	return r.Replace(s)
}

// escapeGHProp はプロパティ値（file= 等）用のエスケープ。メッセージ部と
// 異なり、区切りに使われる "," と ":" もエスケープが必要。
func escapeGHProp(s string) string {
	r := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
	return r.Replace(s)
}

// SARIF は SARIF 2.1.0 形式を出力する（GitHub Code Scanning 取り込み用）。
func SARIF(w io.Writer, findings []detect.Finding, rules []rule.Rule, unmask bool) error {
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID   string   `json:"id"`
		Name string   `json:"name"`
		Desc sarifMsg `json:"shortDescription"`
	}
	type sarifRegion struct {
		StartLine   int `json:"startLine"`
		StartColumn int `json:"startColumn"`
	}
	type sarifLocation struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region sarifRegion `json:"region"`
		} `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifMsg        `json:"message"`
		Locations []sarifLocation `json:"locations"`
	}

	var ruleDefs []sarifRule
	for _, r := range rules {
		ruleDefs = append(ruleDefs, sarifRule{ID: r.ID, Name: r.ID, Desc: sarifMsg{Text: r.Description}})
	}
	results := []sarifResult{}
	for _, f := range findings {
		var level string
		switch f.Confidence {
		case rule.High:
			level = "error"
		case rule.Low:
			level = "note"
		default:
			level = "warning"
		}
		res := sarifResult{
			RuleID:  f.RuleID,
			Level:   level,
			Message: sarifMsg{Text: fmt.Sprintf("%s: %s", f.Description, display(f, unmask))},
		}
		var loc sarifLocation
		loc.PhysicalLocation.ArtifactLocation.URI = f.File
		loc.PhysicalLocation.Region = sarifRegion{StartLine: f.Line, StartColumn: f.Column}
		res.Locations = []sarifLocation{loc}
		results = append(results, res)
	}

	doc := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "jp-pii-detect",
					"informationUri": "https://github.com/baneido/jp-pii-detector",
					"rules":          ruleDefs,
				},
			},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
