package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binPath string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "jp-pii-detect-e2e")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmp)
	binPath = filepath.Join(tmp, "jp-pii-detect")
	if out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput(); err != nil {
		panic("build: " + err.Error() + "\n" + string(out))
	}
	os.Exit(m.Run())
}

// run はバイナリを実行し、stdout と終了コードを返す。
func run(t *testing.T, dir string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return string(out), code
}

// piiDir は PII を含むファイル 1 つだけの作業ディレクトリを作る。
func piiDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "users.csv"), []byte("TEL: 090-1234-5678\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestScanExitCodes(t *testing.T) {
	dir := piiDir(t)
	out, code := run(t, dir, "scan", ".")
	if code != 1 {
		t.Errorf("exit = %d, want 1（検出あり）", code)
	}
	if strings.Contains(out, "090-1234-5678") {
		t.Errorf("output should be masked: %s", out)
	}
	if !strings.Contains(out, "jp-phone-number") {
		t.Errorf("missing rule id: %s", out)
	}

	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "a.txt"), []byte("no pii\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, code := run(t, clean, "scan", "."); code != 0 {
		t.Errorf("exit = %d, want 0（検出なし）", code)
	}
}

func TestScanExitZero(t *testing.T) {
	if _, code := run(t, piiDir(t), "scan", "--exit-zero", "."); code != 0 {
		t.Errorf("exit = %d, want 0（--exit-zero）", code)
	}
}

func TestScanUnmask(t *testing.T) {
	out, _ := run(t, piiDir(t), "scan", "--unmask", ".")
	if !strings.Contains(out, "090-1234-5678") {
		t.Errorf("--unmask should show raw value: %s", out)
	}
}

func TestScanJSONFormat(t *testing.T) {
	out, code := run(t, piiDir(t), "scan", "--format", "json", ".")
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	var doc struct {
		Count    int `json:"count"`
		Findings []struct {
			RuleID string `json:"rule_id"`
			File   string `json:"file"`
			Line   int    `json:"line"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if doc.Count != 1 || doc.Findings[0].RuleID != "jp-phone-number" || doc.Findings[0].Line != 1 {
		t.Errorf("unexpected JSON: %s", out)
	}
}

func TestScanSARIFAndGitHubFormats(t *testing.T) {
	out, _ := run(t, piiDir(t), "scan", "--format", "sarif", ".")
	if !strings.Contains(out, `"version": "2.1.0"`) {
		t.Errorf("not SARIF: %s", out)
	}
	out, _ = run(t, piiDir(t), "scan", "--format", "github", ".")
	if !strings.HasPrefix(out, "::error file=") {
		t.Errorf("not workflow command: %s", out)
	}
}

func TestErrorsExitTwo(t *testing.T) {
	dir := piiDir(t)
	for _, args := range [][]string{
		{"scan", "--format", "bogus", "."},
		{"scan", "--min-confidence", "bogus", "."},
		{"scan", "--config", "/nonexistent/config.toml", "."},
		{"unknown-command"},
	} {
		if _, code := run(t, dir, args...); code != 2 {
			t.Errorf("%v: exit = %d, want 2", args, code)
		}
	}
}

func TestMinConfidenceFlagOverride(t *testing.T) {
	dir := t.TempDir()
	// 区切りなし携帯（コンテキストなし）は medium → high 指定で報告されない。
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("09012345678\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, code := run(t, dir, "scan", "."); code != 1 {
		t.Error("medium finding should be reported by default")
	}
	if _, code := run(t, dir, "scan", "--min-confidence", "high", "."); code != 0 {
		t.Error("medium finding should be hidden with --min-confidence high")
	}
}

func TestRulesCommand(t *testing.T) {
	out, code := run(t, t.TempDir(), "rules")
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	for _, id := range []string{"jp-my-number", "jp-phone-number", "credit-card"} {
		if !strings.Contains(out, id) {
			t.Errorf("rules output missing %s:\n%s", id, out)
		}
	}
}

func TestVersionCommand(t *testing.T) {
	out, code := run(t, t.TempDir(), "version")
	if code != 0 || strings.TrimSpace(out) == "" {
		t.Errorf("version: exit=%d out=%q", code, out)
	}
}
