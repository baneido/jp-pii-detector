package scripts_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fpScript = "scripts/fp-corpus-report.sh"
const fpTrendScript = "scripts/fp-corpus-trend.sh"

type fpReportRuleCount struct {
	RuleID  string  `json:"rule_id"`
	Count   int     `json:"count"`
	PerMLoC float64 `json:"per_mloc"`
}

type fpReport struct {
	Corpus        string              `json:"corpus"`
	PhysicalLines int                 `json:"physical_lines"`
	MLoC          float64             `json:"mloc"`
	FindingsTotal int                 `json:"findings_total"`
	ByRule        []fpReportRuleCount `json:"by_rule"`
}

// writeFindingsJSON は internal/report.JSON が書き出す {"findings": [...], "count": N}
// 形式（rule_id/match/confidence 等）を模した findings JSON をテスト用ディレクトリに書く。
func writeFindingsJSON(t *testing.T, dir string, findings []map[string]any) string {
	t.Helper()
	if findings == nil {
		findings = []map[string]any{}
	}
	doc := map[string]any{"findings": findings, "count": len(findings)}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeLines(t *testing.T, path string, n int) {
	t.Helper()
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("line\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFPCorpusReportAggregatesByRule(t *testing.T) {
	corpusDir := t.TempDir()
	// 2 ファイル、合計 10 物理行。
	writeLines(t, filepath.Join(corpusDir, "a.txt"), 5)
	writeLines(t, filepath.Join(corpusDir, "b.txt"), 5)

	findings := []map[string]any{
		{"rule_id": "jp-phone-number", "description": "電話番号", "file": "a.txt", "line": 1, "column": 1, "match": "09*****78", "confidence": "high"},
		{"rule_id": "jp-phone-number", "description": "電話番号", "file": "a.txt", "line": 2, "column": 1, "match": "09*****79", "confidence": "high"},
		{"rule_id": "jp-postal-code", "description": "郵便番号", "file": "b.txt", "line": 1, "column": 1, "match": "15**01", "confidence": "medium"},
	}
	findingsPath := writeFindingsJSON(t, t.TempDir(), findings)

	out, code := runScript(t, fpScript, nil, "sample", corpusDir, findingsPath)
	if code != 0 {
		t.Fatalf("exit=%d\n%s", code, out)
	}

	var got fpReport
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, out)
	}
	if got.Corpus != "sample" {
		t.Errorf("corpus = %q, want %q", got.Corpus, "sample")
	}
	if got.PhysicalLines != 10 {
		t.Errorf("physical_lines = %d, want 10", got.PhysicalLines)
	}
	wantMLoC := 10.0 / 1_000_000.0
	if got.MLoC != wantMLoC {
		t.Errorf("mloc = %v, want %v", got.MLoC, wantMLoC)
	}
	if got.FindingsTotal != 3 {
		t.Errorf("findings_total = %d, want 3", got.FindingsTotal)
	}
	if len(got.ByRule) != 2 {
		t.Fatalf("by_rule has %d entries, want 2: %+v", len(got.ByRule), got.ByRule)
	}
	// count 降順: jp-phone-number(2) が jp-postal-code(1) より先。
	if got.ByRule[0].RuleID != "jp-phone-number" || got.ByRule[0].Count != 2 {
		t.Errorf("by_rule[0] = %+v, want jp-phone-number count=2", got.ByRule[0])
	}
	if got.ByRule[1].RuleID != "jp-postal-code" || got.ByRule[1].Count != 1 {
		t.Errorf("by_rule[1] = %+v, want jp-postal-code count=1", got.ByRule[1])
	}
	// マスク済み match 値すら集計結果に漏れていないこと（rule_id と件数のみ）。
	if strings.Contains(out, "match") || strings.Contains(out, "09") {
		t.Errorf("aggregated report must not leak finding values:\n%s", out)
	}
}

func TestFPCorpusReportCountsOnlyScannerEligibleFiles(t *testing.T) {
	corpusDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(corpusDir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeLines(t, filepath.Join(corpusDir, "src", "a.txt"), 3)
	writeLines(t, filepath.Join(corpusDir, "src", "b.txt"), 2)

	for _, dir := range []string{
		".git",
		"node_modules",
		"vendor",
		".venv",
		"venv",
		"__pycache__",
		"dist",
		"build",
		".next",
		"target",
	} {
		if err := os.MkdirAll(filepath.Join(corpusDir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		writeLines(t, filepath.Join(corpusDir, dir, "ignored.txt"), 7)
	}

	big := make([]byte, 5*1024*1024+1)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(filepath.Join(corpusDir, "too-big.txt"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corpusDir, "binary.bin"), []byte("text before nul\x00\ntext after\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	findingsPath := writeFindingsJSON(t, t.TempDir(), nil)
	out, code := runScript(t, fpScript, nil, "sample", corpusDir, findingsPath)
	if code != 0 {
		t.Fatalf("exit=%d\n%s", code, out)
	}

	var got fpReport
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, out)
	}
	if got.PhysicalLines != 5 {
		t.Errorf("physical_lines = %d, want scanner-eligible line count 5", got.PhysicalLines)
	}
}

func TestFPCorpusReportZeroFindings(t *testing.T) {
	corpusDir := t.TempDir()
	writeLines(t, filepath.Join(corpusDir, "a.txt"), 1)
	findingsPath := writeFindingsJSON(t, t.TempDir(), nil)

	out, code := runScript(t, fpScript, nil, "clean", corpusDir, findingsPath)
	if code != 0 {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	var got fpReport
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, out)
	}
	if got.FindingsTotal != 0 {
		t.Errorf("findings_total = %d, want 0", got.FindingsTotal)
	}
	if len(got.ByRule) != 0 {
		t.Errorf("by_rule = %+v, want empty", got.ByRule)
	}
}

func TestFPCorpusReportRejectsMissingArgs(t *testing.T) {
	out, code := runScript(t, fpScript, nil)
	if code == 0 {
		t.Fatalf("expected non-zero exit for missing args\n%s", out)
	}
	if !strings.Contains(out, "usage:") {
		t.Errorf("expected usage message in output, got:\n%s", out)
	}
}

func TestFPCorpusReportRejectsMissingCorpusDir(t *testing.T) {
	findingsPath := writeFindingsJSON(t, t.TempDir(), nil)
	missingDir := filepath.Join(t.TempDir(), "does-not-exist")

	out, code := runScript(t, fpScript, nil, "name", missingDir, findingsPath)
	if code == 0 {
		t.Fatalf("expected non-zero exit for missing corpus dir\n%s", out)
	}
}

func TestFPCorpusReportRejectsMissingFindingsFile(t *testing.T) {
	corpusDir := t.TempDir()
	writeLines(t, filepath.Join(corpusDir, "a.txt"), 1)
	missingFindings := filepath.Join(t.TempDir(), "missing.json")

	out, code := runScript(t, fpScript, nil, "name", corpusDir, missingFindings)
	if code == 0 {
		t.Fatalf("expected non-zero exit for missing findings file\n%s", out)
	}
}

func writeFPSummary(t *testing.T, path, generatedAt string, total int, rate float64, byRule map[string]int) {
	t.Helper()
	rules := make([]map[string]any, 0, len(byRule))
	for ruleID, count := range byRule {
		rules = append(rules, map[string]any{
			"rule_id":  ruleID,
			"count":    count,
			"per_mloc": float64(count) / 2,
		})
	}
	doc := map[string]any{
		"generated_at":         generatedAt,
		"corpora_count":        3,
		"total_physical_lines": 2_000_000,
		"total_mloc":           2.0,
		"total_findings":       total,
		"findings_per_mloc":    rate,
		"by_rule":              rules,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFPCorpusTrendWarnsWithoutFailing(t *testing.T) {
	dir := t.TempDir()
	previous := filepath.Join(dir, "previous.json")
	current := filepath.Join(dir, "current.json")
	writeFPSummary(t, previous, "2026-07-01T00:00:00Z", 10, 5, map[string]int{"email-address": 10})
	writeFPSummary(t, current, "2026-07-08T00:00:00Z", 13, 6.5, map[string]int{"email-address": 13})

	out, code := runScript(t, fpTrendScript, nil, current, previous, "20")
	if code != 0 {
		t.Fatalf("trend warning must be non-gating: exit=%d\n%s", code, out)
	}
	var got struct {
		Warning              bool    `json:"warning"`
		OverallWarning       bool    `json:"overall_warning"`
		OverallChangePercent float64 `json:"overall_change_percent"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid trend JSON: %v\n%s", err, out)
	}
	if !got.Warning || !got.OverallWarning || got.OverallChangePercent != 30 {
		t.Errorf("unexpected warning result: %+v", got)
	}
}

func TestFPCorpusTrendWarnsForNewRuleFromZero(t *testing.T) {
	dir := t.TempDir()
	previous := filepath.Join(dir, "previous.json")
	current := filepath.Join(dir, "current.json")
	writeFPSummary(t, previous, "2026-07-01T00:00:00Z", 10, 5, map[string]int{"email-address": 10})
	writeFPSummary(t, current, "2026-07-08T00:00:00Z", 11, 5.5, map[string]int{
		"email-address": 10,
		"new-rule":      1,
	})

	out, code := runScript(t, fpTrendScript, nil, current, previous, "20")
	if code != 0 {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	var got struct {
		Warning        bool `json:"warning"`
		OverallWarning bool `json:"overall_warning"`
		ByRule         []struct {
			RuleID        string   `json:"rule_id"`
			PreviousCount int      `json:"previous_count"`
			ChangePercent *float64 `json:"change_percent"`
			Warning       bool     `json:"warning"`
		} `json:"by_rule"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Warning || got.OverallWarning {
		t.Errorf("new rule should warn independently of total threshold: %+v", got)
	}
	for _, rule := range got.ByRule {
		if rule.RuleID == "new-rule" {
			if rule.PreviousCount != 0 || rule.ChangePercent != nil || !rule.Warning {
				t.Errorf("unexpected new-rule trend: %+v", rule)
			}
			return
		}
	}
	t.Fatal("new-rule trend is missing")
}

func TestFPCorpusTrendRejectsInvalidBaseline(t *testing.T) {
	dir := t.TempDir()
	previous := filepath.Join(dir, "previous.json")
	current := filepath.Join(dir, "current.json")
	if err := os.WriteFile(previous, []byte(`{"findings_per_mloc":"invalid"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	writeFPSummary(t, current, "2026-07-08T00:00:00Z", 10, 5, map[string]int{"email-address": 10})

	out, code := runScript(t, fpTrendScript, nil, current, previous, "20")
	if code == 0 || !strings.Contains(out, "previous summary の形式が不正") {
		t.Fatalf("invalid baseline must fail closed: exit=%d\n%s", code, out)
	}
}

func TestFPCorpusWorkflowWeeklyTrendIsHardened(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "fp-corpus-report.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"- cron: '0 3 * * 1'",
		"cancel-in-progress: false",
		"permissions: {}",
		"contents: read",
		"id-token: write",
		"github.event.repository.default_branch",
		"actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1",
		"google-github-actions/auth@c200f3691d83b41bf9bbd8638997a462592937ed # v2",
		"google-github-actions/setup-gcloud@e427ad8a34f8676edf47cf7d7925499adf3eb74f # v2",
		"scripts/fp-corpus-trend.sh",
		"--if-generation-match=0",
		"--if-generation-match=\"$BASELINE_GENERATION\"",
		"::warning::fp-corpus-report が前回比閾値を超えました（非ゲート）",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("workflow is missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"\n  pull_request:",
		"issues: write",
		"pull-requests: write",
		"github.event.issue",
		"${{ github.event.pull_request",
		"google-github-actions/auth@v2",
		"google-github-actions/setup-gcloud@v2",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("workflow must not contain %q", forbidden)
		}
	}
}
