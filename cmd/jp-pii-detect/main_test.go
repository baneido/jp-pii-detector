package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/piifixtures"
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
// 携帯電話番号は実在しうるためフィクスチャから読み込む。
func piiDir(t *testing.T) string {
	t.Helper()
	piifixtures.Require(t)
	dir := t.TempDir()
	content := "TEL: " + piifixtures.MustGet(t, "cmd.phone_mobile_sep") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "users.csv"), []byte(content), 0o644); err != nil {
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
	if strings.Contains(out, piifixtures.MustGet(t, "cmd.phone_mobile_sep")) {
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
	dir := piiDir(t)
	out, _ := run(t, dir, "scan", "--unmask", ".")
	if !strings.Contains(out, piifixtures.MustGet(t, "cmd.phone_mobile_sep")) {
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

// 走査対象の一部ファイルが読み取れない場合でも、収集できた findings は
// 通常どおり出力しつつ、警告を stderr に出し、終了コードは 2（部分走査）に
// なること。黙って exit 0/1 にすると走査が不完全なまま結果を装うことになり
// セキュリティツールとして危険なため。
func TestScanPartialErrorExitsTwoWithReport(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root では読み取り権限のチェックが効かないためスキップ")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("口座番号: 1234567\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	denied := filepath.Join(dir, "denied.txt")
	if err := os.WriteFile(denied, []byte("no pii\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(denied, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(denied, 0o644) })

	cmd := exec.Command(binPath, "scan", ".")
	cmd.Dir = dir
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run: %v", err)
		}
		code = ee.ExitCode()
	}
	if code != 2 {
		t.Errorf("exit = %d, want 2（部分走査）", code)
	}
	if !strings.Contains(string(out), "jp-bank-account") {
		t.Errorf("収集済みの findings が出力されていない: %s", out)
	}
	if !strings.Contains(stderr.String(), "denied.txt") {
		t.Errorf("stderr に警告が出力されていない: %s", stderr.String())
	}
}

func TestMinConfidenceFlagOverride(t *testing.T) {
	piifixtures.Require(t)
	dir := t.TempDir()
	// 区切りなし携帯（コンテキストなし）は medium → high 指定で報告されない。
	content := piifixtures.MustGet(t, "cmd.phone_mobile_nosep") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, code := run(t, dir, "scan", "."); code != 1 {
		t.Error("medium finding should be reported by default")
	}
	if _, code := run(t, dir, "scan", "--min-confidence", "high", "."); code != 0 {
		t.Error("medium finding should be hidden with --min-confidence high")
	}
}

func TestScanHighRecallFlag(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("勤務地: 渋谷区道玄坂2-10-7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, code := run(t, dir, "scan", "."); code != 0 {
		t.Error("high-recall finding should be hidden by default")
	}
	out, code := run(t, dir, "scan", "--high-recall", ".")
	if code != 1 {
		t.Errorf("exit = %d, want 1 with --high-recall", code)
	}
	if !strings.Contains(out, "jp-address-high-recall") {
		t.Fatalf("missing high-recall rule in output: %s", out)
	}
}

func TestScanJSONExplain(t *testing.T) {
	dir := piiDir(t)
	out, code := run(t, dir, "scan", "--format", "json", "--explain", ".")
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(out, `"reason"`) || !strings.Contains(out, `"base_confidence"`) {
		t.Fatalf("--explain should include reason: %s", out)
	}
	if strings.Contains(out, piifixtures.MustGet(t, "cmd.phone_mobile_sep")) {
		t.Fatalf("--explain should not unmask match: %s", out)
	}
}

// TestScanStdinOffsets は scan --stdin が標準入力を 1 本のテキストとして走査し、
// json 出力に offset/end_offset（テキスト先頭からのルーン単位の半開区間）を付与
// すること、そのオフセットで元テキストを切り出すと検出値に一致することを確認する。
// メールアドレスは機微でない架空ドメインを使うため外部フィクスチャ不要。
func TestScanStdinOffsets(t *testing.T) {
	input := "連絡先一覧\n担当: test.user@kaisha.co.jp まで\n"
	// 一時ディレクトリで実行し、リポジトリの .jp-pii.toml を拾わない（既定設定で走査）。
	cmd := exec.Command(binPath, "scan", "--stdin", "--format", "json", "--unmask")
	cmd.Dir = t.TempDir()
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.Output()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run --stdin: %v", err)
		}
		code = ee.ExitCode()
	}
	if code != 1 {
		t.Errorf("exit = %d, want 1（検出あり）\n%s", code, out)
	}
	var doc struct {
		Findings []struct {
			RuleID    string `json:"rule_id"`
			Match     string `json:"match"`
			Offset    *int   `json:"offset"`
			EndOffset *int   `json:"end_offset"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	runes := []rune(input)
	var found bool
	for _, f := range doc.Findings {
		if f.RuleID != "email-address" {
			continue
		}
		found = true
		if f.Offset == nil || f.EndOffset == nil {
			t.Fatalf("offset/end_offset が無い: %s", out)
		}
		if *f.Offset < 0 || *f.EndOffset > len(runes) || *f.Offset > *f.EndOffset {
			t.Fatalf("offset 範囲外: [%d, %d) len=%d", *f.Offset, *f.EndOffset, len(runes))
		}
		if got := string(runes[*f.Offset:*f.EndOffset]); got != f.Match {
			t.Errorf("input[%d:%d] = %q, want match %q", *f.Offset, *f.EndOffset, got, f.Match)
		}
		if f.Match != "test.user@kaisha.co.jp" {
			t.Errorf("match = %q, want %q", f.Match, "test.user@kaisha.co.jp")
		}
	}
	if !found {
		t.Fatalf("email-address が検出されなかった: %s", out)
	}
}

// TestScanStdinNoFindings は scan --stdin の負例: PII を含まない入力と空入力は
// いずれも検出なし（exit 0、count 0）になることを確認する。
func TestScanStdinNoFindings(t *testing.T) {
	for _, in := range []string{"ここには個人情報は含まれません\n", ""} {
		cmd := exec.Command(binPath, "scan", "--stdin", "--format", "json")
		cmd.Dir = t.TempDir()
		cmd.Stdin = strings.NewReader(in)
		out, err := cmd.Output() // 検出なしなら exit 0 → err == nil
		if err != nil {
			t.Fatalf("clean stdin %q should exit 0: %v\n%s", in, err, out)
		}
		var doc struct {
			Count int `json:"count"`
		}
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, out)
		}
		if doc.Count != 0 {
			t.Errorf("count = %d, want 0 for %q: %s", doc.Count, in, out)
		}
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
