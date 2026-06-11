package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detecter/internal/detect"
	"github.com/baneido/jp-pii-detecter/internal/rule"
)

func sample() []detect.Finding {
	return []detect.Finding{{
		RuleID:      "jp-phone-number",
		Description: "電話番号",
		File:        "users.csv",
		Line:        4,
		Column:      6,
		Match:       "090-1234-5678",
		Confidence:  rule.High,
	}}
}

func TestMask(t *testing.T) {
	tests := []struct{ in, want string }{
		{"090-1234-5678", "09*********78"},
		{"abc", "***"},
		{"abcdef", "a****f"},
	}
	for _, tt := range tests {
		if got := Mask(tt.in); got != tt.want {
			t.Errorf("Mask(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTextMasksByDefault(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sample(), false)
	out := buf.String()
	if strings.Contains(out, "090-1234-5678") {
		t.Error("output should be masked")
	}
	if !strings.Contains(out, "users.csv:4:6") {
		t.Errorf("missing location: %s", out)
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sample(), true); err != nil {
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
	if got.Count != 1 || got.Findings[0].Match != "090-1234-5678" || got.Findings[0].Confidence != "high" {
		t.Errorf("unexpected JSON: %s", buf.String())
	}
}

func TestGitHubEscapes(t *testing.T) {
	var buf bytes.Buffer
	fs := sample()
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

func TestSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sample(), rule.Builtin(), false); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v", doc["version"])
	}
	if strings.Contains(buf.String(), "090-1234-5678") {
		t.Error("SARIF output should be masked")
	}
}
