package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/piifixtures"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// sample は電話番号 1 件の検出結果を返す。実在しうる携帯番号形式はリポジトリに
// コミットしないため、Match の値はフィクスチャから受け取る。
func sample(match string) []detect.Finding {
	return []detect.Finding{{
		RuleID:      "jp-phone-number",
		Description: "電話番号",
		File:        "users.csv",
		Line:        4,
		Column:      6,
		Match:       match,
		Confidence:  rule.High,
	}}
}

func TestMask(t *testing.T) {
	piifixtures.Require(t)
	tests := []struct{ in, want string }{
		{piifixtures.MustGet(t, "report.phone_for_mask"), "09*********00"}, // 090-0000-0000（13 文字: 先頭・末尾 2 文字）
		{"abc", "***"},
		{"abcdef", "a****f"},
		{"", ""},                 // 空文字
		{"abcd", "****"},         // 4 文字以下は全マスク
		{"abcde", "a***e"},       // 5 文字（先頭・末尾 1 文字）
		{"abcdefg", "a*****g"},   // 7 文字（< 8 の上限）
		{"abcdefgh", "ab****gh"}, // 8 文字（先頭・末尾 2 文字に切替）
		{piifixtures.MustGet(t, "report.phone_fullwidth_in"), "０９*******００"}, // 全角 11 文字: マルチバイトはルーン単位
	}
	for _, tt := range tests {
		if got := Mask(tt.in); got != tt.want {
			t.Errorf("Mask(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTextMasksByDefault(t *testing.T) {
	piifixtures.Require(t)
	phone := piifixtures.MustGet(t, "report.phone_match")
	var buf bytes.Buffer
	Text(&buf, sample(phone), false)
	out := buf.String()
	if strings.Contains(out, phone) {
		t.Error("output should be masked")
	}
	if !strings.Contains(out, "users.csv:4:6") {
		t.Errorf("missing location: %s", out)
	}
	if !strings.Contains(out, "1 件") || !strings.Contains(out, "jp-pii-detector:ignore") {
		t.Errorf("missing summary with remediation hint: %s", out)
	}
}

func TestTextNoFindingsNoSummary(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, nil, false)
	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %q", buf.String())
	}
}

// confidence → SARIF level の対応（high=error, medium=warning, low=note）。
func TestSARIFLevels(t *testing.T) {
	piifixtures.Require(t)
	phone := piifixtures.MustGet(t, "report.phone_match")
	fs := []detect.Finding{}
	for _, c := range []rule.Confidence{rule.High, rule.Medium, rule.Low} {
		f := sample(phone)[0]
		f.Confidence = c
		fs = append(fs, f)
	}
	var buf bytes.Buffer
	if err := SARIF(&buf, fs, rule.Builtin(), false); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Level string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, r := range doc.Runs[0].Results {
		got = append(got, r.Level)
	}
	want := []string{"error", "warning", "note"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("levels = %v, want %v", got, want)
			break
		}
	}
}

func TestJSON(t *testing.T) {
	piifixtures.Require(t)
	phone := piifixtures.MustGet(t, "report.phone_match")
	var buf bytes.Buffer
	if err := JSON(&buf, sample(phone), true, false); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Count    int `json:"count"`
		Findings []struct {
			Match      string `json:"match"`
			Confidence string `json:"confidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Count != 1 || got.Findings[0].Match != phone || got.Findings[0].Confidence != "high" {
		t.Errorf("unexpected JSON: %s", buf.String())
	}
}

// TestJSONOffsets は scan --stdin で付与される offset/end_offset の JSON 出力を確認する。
// 特に offset==0（テキスト先頭一致）が省略されず "offset": 0 として出ること
// （*int + omitempty をうっかり int + omitempty に戻すと 0 が欠落する回帰の防止）と、
// HasOffset でない finding には両フィールドが現れないことを検証する。フィクスチャ不要。
func TestJSONOffsets(t *testing.T) {
	findings := []detect.Finding{
		{RuleID: "a", File: "<stdin>", Line: 1, Column: 1, Match: "abc",
			HasOffset: true, Offset: 0, EndOffset: 3},
		{RuleID: "b", File: "<stdin>", Line: 1, Column: 5, Match: "de"}, // HasOffset=false
	}
	var buf bytes.Buffer
	if err := JSON(&buf, findings, true, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"offset": 0`) {
		t.Errorf(`offset==0 が省略された（"offset": 0 が無い）: %s`, out)
	}

	var got struct {
		Findings []struct {
			Offset    *int `json:"offset"`
			EndOffset *int `json:"end_offset"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	f0 := got.Findings[0]
	if f0.Offset == nil || *f0.Offset != 0 || f0.EndOffset == nil || *f0.EndOffset != 3 {
		t.Errorf("finding[0] offsets = %v/%v, want 0/3: %s", f0.Offset, f0.EndOffset, out)
	}
	if f1 := got.Findings[1]; f1.Offset != nil || f1.EndOffset != nil {
		t.Errorf("HasOffset でない finding に offset が出ている: %s", out)
	}
}

func TestJSONExplainIncludesReason(t *testing.T) {
	piifixtures.Require(t)
	phone := piifixtures.MustGet(t, "report.phone_match")
	fs := sample(phone)
	fs[0].Reason = detect.DetectReason{
		BaseConfidence:  "medium",
		FinalConfidence: "high",
		ContextKeywords: []string{"tel"},
		ContextPromoted: true,
		Validated:       true,
	}
	var buf bytes.Buffer
	if err := JSON(&buf, fs, false, true); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Findings []struct {
			Match  string              `json:"match"`
			Reason detect.DetectReason `json:"reason"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Findings[0].Match == phone {
		t.Fatalf("explain JSON should still mask match: %s", buf.String())
	}
	if got.Findings[0].Reason.BaseConfidence != "medium" || !got.Findings[0].Reason.ContextPromoted {
		t.Fatalf("reason missing: %s", buf.String())
	}
}

func TestGitHubEscapes(t *testing.T) {
	piifixtures.Require(t)
	var buf bytes.Buffer
	fs := sample(piifixtures.MustGet(t, "report.phone_match"))
	fs[0].Description = "改行\nと%"
	GitHub(&buf, fs, false)
	out := buf.String()
	if !strings.HasPrefix(out, "::error file=users.csv,line=4,col=6,") {
		t.Errorf("unexpected prefix: %s", out)
	}
	if strings.Contains(out, "\n改行") || !strings.Contains(out, "%0A") || !strings.Contains(out, "%25") {
		t.Errorf("workflow command not escaped: %s", out)
	}
}

// file= プロパティの値はプロパティ区切りの "," ":" もエスケープされる。
func TestGitHubEscapesFileProperty(t *testing.T) {
	piifixtures.Require(t)
	var buf bytes.Buffer
	fs := sample(piifixtures.MustGet(t, "report.phone_match"))
	fs[0].File = "a,b/c:d.csv"
	GitHub(&buf, fs, false)
	out := buf.String()
	if !strings.HasPrefix(out, "::error file=a%2Cb/c%3Ad.csv,line=4,") {
		t.Errorf("file property not escaped: %s", out)
	}
}

func TestSARIF(t *testing.T) {
	piifixtures.Require(t)
	phone := piifixtures.MustGet(t, "report.phone_match")
	var buf bytes.Buffer
	if err := SARIF(&buf, sample(phone), rule.Builtin(), false); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v", doc["version"])
	}
	if strings.Contains(buf.String(), phone) {
		t.Error("SARIF output should be masked")
	}
}
