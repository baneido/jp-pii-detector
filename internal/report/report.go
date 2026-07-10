// Package report は検出結果の出力（text/json/sarif/github）を提供する。
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/baseline"
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

// Text は人間向けのプレーンテキストを出力する。explain が true の場合、
// json 出力の --explain 同様に検出理由（コンテキスト昇格・検証有無等）を
// 各検出の下に付与する（偽陽性の切り分け根拠）。
func Text(w io.Writer, findings []detect.Finding, unmask, explain bool) {
	for _, f := range findings {
		fmt.Fprintf(w, "%s:%d:%d\t[%s]\t%s\t%s\t%s\n",
			f.File, f.Line, f.Column, f.Confidence, f.RuleID, f.Description, display(f, unmask))
		if explain {
			if reason := formatReason(f.Reason); reason != "" {
				fmt.Fprintf(w, "\t  理由: %s\n", reason)
			}
		}
	}
	if len(findings) > 0 {
		fmt.Fprintf(w, "\n%d 件の個人情報らしき記述を検出しました。誤検出の場合は行末コメントに %q を付けるか、設定ファイルの allowlist に追加してください。\n"+
			"意図的に許容する既存の検出は --update-baseline でベースラインファイルに記録すると、以降のスキャンでは新規追加分のみが検出されます。\n",
			len(findings), detect.IgnoreMarker)
	}
}

// formatReason は DetectReason を text 出力向けの 1 行に整形する。
// 生の PII は含まない（DetectReason 自体がコンテキストキーワード等のみ保持する）。
func formatReason(r detect.DetectReason) string {
	var parts []string
	if r.BaseConfidence != "" {
		parts = append(parts, fmt.Sprintf("基準信頼度=%s", r.BaseConfidence))
	}
	if r.FinalConfidence != "" && r.FinalConfidence != r.BaseConfidence {
		parts = append(parts, fmt.Sprintf("最終信頼度=%s", r.FinalConfidence))
	}
	if r.RequireContext {
		parts = append(parts, "要コンテキスト=true")
	}
	if r.ContextPromoted {
		parts = append(parts, "コンテキスト昇格=true")
	}
	if len(r.ContextKeywords) > 0 {
		parts = append(parts, fmt.Sprintf("キーワード=%s", strings.Join(r.ContextKeywords, ",")))
	}
	if r.ContextWindow > 0 {
		parts = append(parts, fmt.Sprintf("コンテキスト範囲=%d文字", r.ContextWindow))
	}
	if r.Validated {
		parts = append(parts, "検証=true")
	}
	return strings.Join(parts, " ")
}

type jsonFinding struct {
	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	// Offset/EndOffset はテキスト全体先頭からのルーン単位の半開区間。単一テキスト
	// 走査（scan --stdin）で ComputeOffsets により付与されたときのみ出力する。
	// 文字オフセット基準の利用側（Microsoft Presidio 連携など）向け。
	Offset     *int                 `json:"offset,omitempty"`
	EndOffset  *int                 `json:"end_offset,omitempty"`
	Match      string               `json:"match"`
	Confidence string               `json:"confidence"`
	Reason     *detect.DetectReason `json:"reason,omitempty"`
	// Fingerprint は internal/baseline の値ハッシュ fingerprint（salt 付き
	// HMAC-SHA256）。scan --baseline <path> 指定時のみ、その baseline ファイルの
	// salt で算出して出力する（省略時は空文字列で omitempty により出力されない）。
	// baseline ファイルへの手動追記など、参照用途を想定する。
	Fingerprint string `json:"fingerprint,omitempty"`
}

// JSON は機械可読な JSON を出力する。salt を渡すと（後方互換のため可変長引数、
// 1 つ目のみ使用）各 finding に baseline fingerprint を付与する。省略時
// （既存呼び出し）は今までどおり fingerprint フィールドを出力しない。
func JSON(w io.Writer, findings []detect.Finding, unmask, explain bool, salt ...string) error {
	var fpSalt string
	if len(salt) > 0 {
		fpSalt = salt[0]
	}
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
		if f.HasOffset {
			off, end := f.Offset, f.EndOffset
			jf.Offset, jf.EndOffset = &off, &end
		}
		if explain {
			jf.Reason = &f.Reason
		}
		if fpSalt != "" {
			jf.Fingerprint = baseline.FindingFingerprint(fpSalt, f)
		}
		out.Findings = append(out.Findings, jf)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// GitHub は GitHub Actions の workflow command 形式で注釈を出力する。
// 信頼度に応じて ::error/::warning/::notice を使い分ける（SARIF の level と同じ
// 対応: high=error, medium=warning, low=notice）。以前は信頼度に関わらず常に
// ::error だったため、min_confidence を下げて可視化した medium/low 検出のたびに
// PR のチェックが「エラー」表示になり、報告閾値と失敗閾値が実質的に一致してしまう
// 問題があった（実際に CI を落とすかどうかは runScan の --fail-on 判定による）。
func GitHub(w io.Writer, findings []detect.Finding, unmask bool) {
	for _, f := range findings {
		msg := fmt.Sprintf("%s: %s", f.Description, display(f, unmask))
		fmt.Fprintf(w, "::%s file=%s,line=%d,col=%d,title=PII detected (%s)::%s\n",
			githubCommand(f.Confidence), escapeGHProp(f.File), f.Line, f.Column, f.RuleID, escapeGH(msg))
	}
}

// githubCommand は信頼度から GitHub Actions workflow command 名を決める。
func githubCommand(c rule.Confidence) string {
	switch c {
	case rule.High:
		return "error"
	case rule.Low:
		return "notice"
	default:
		return "warning"
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
		// EndLine/EndColumn は検出値の終端（EndColumn は SARIF 仕様どおり終端文字の
		// 次のカラム、排他的境界）。これが無いと GitHub Code Scanning は開始位置
		// のみでハイライト幅を推測するため、検出値の長さによっては隣接文字まで
		// 誤ってハイライトされる。
		EndLine   int `json:"endLine"`
		EndColumn int `json:"endColumn"`
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
		// PartialFingerprints はマスク方針を迂回しない安定な識別子。生の検出値は
		// 低エントロピー値を候補列挙で照合されうるため含めず、ルール ID・ファイル
		// パス・同一ルールのファイル内出現順（occurrence）から算出する。
		PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	}

	var ruleDefs []sarifRule
	for _, r := range rules {
		ruleDefs = append(ruleDefs, sarifRule{ID: r.ID, Name: r.ID, Desc: sarifMsg{Text: r.Description}})
	}
	results := []sarifResult{}
	occurrence := map[string]int{}
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
		endLine, endCol := f.Line, f.Column+utf8.RuneCountInString(f.Match)
		loc.PhysicalLocation.Region = sarifRegion{
			StartLine: f.Line, StartColumn: f.Column,
			EndLine: endLine, EndColumn: endCol,
		}
		res.Locations = []sarifLocation{loc}

		// 行・カラムは周辺行の増減だけで変わるため fingerprint には含めない。
		// findings は検出位置順に安定ソート済みなので、同一ルール・同一ファイル内の
		// occurrence は行が前後へ移動しても維持され、別の出現は区別できる。
		fpKey := f.RuleID + "\x00" + f.File
		idx := occurrence[fpKey]
		occurrence[fpKey] = idx + 1
		res.PartialFingerprints = map[string]string{
			"primaryLocationLineHash": locationFingerprint(f.RuleID, f.File, idx),
		}

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

// locationFingerprint は SARIF の partialFingerprints 用に、ルール ID・ファイルパス・
// 同一ルールのファイル内出現順から安定なハッシュを算出する。行・カラムと生の PII
// 値は含めないため、周辺行の増減で同じ検出の位置がずれても識別子は変わらない。
func locationFingerprint(ruleID, file string, occurrence int) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%d", ruleID, file, occurrence)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}
