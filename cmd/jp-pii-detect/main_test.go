package main_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/testfixtures"
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

// runWithStderr は stdout と stderr を別々に検証したい CLI UX テスト用。
func runWithStderr(t *testing.T, dir string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Dir = dir
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

// piiDir は PII を含むファイル 1 つだけの作業ディレクトリを作る。
// 携帯電話番号は実在しうるためフィクスチャから読み込む。
func piiDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	content := "TEL: " + testfixtures.MustGet(t, "cmd.phone_mobile_sep") + "\n"
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
	if strings.Contains(out, testfixtures.MustGet(t, "cmd.phone_mobile_sep")) {
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
	if !strings.Contains(out, testfixtures.MustGet(t, "cmd.phone_mobile_sep")) {
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

// 不完全な走査結果を「既知」として固定すると、その後の CI が検出漏れを
// 正常扱いしてしまう。警告が 1 件でもあれば baseline を作成しないことを確認する。
func TestBaselineUpdateRejectsPartialScan(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root では読み取り権限のチェックが効かないためスキップ")
	}
	dir := t.TempDir()
	denied := filepath.Join(dir, "denied.txt")
	if err := os.WriteFile(denied, []byte("no pii\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(denied, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(denied, 0o644) })
	baselinePath := filepath.Join(dir, "baseline.json")

	_, stderr, code := runWithStderr(t, dir, "scan", "--baseline", baselinePath, "--update-baseline", ".")
	if code != 2 {
		t.Fatalf("exit = %d, want 2: %s", code, stderr)
	}
	if !strings.Contains(stderr, "baseline を更新しませんでした") {
		t.Errorf("fail-closed の理由が表示されていない: %s", stderr)
	}
	if _, err := os.Stat(baselinePath); !os.IsNotExist(err) {
		t.Errorf("不完全な走査で baseline が作成された: %v", err)
	}
}

func TestMinConfidenceFlagOverride(t *testing.T) {
	dir := t.TempDir()
	// 区切りなし携帯（コンテキストなし）は medium → high 指定で報告されない。
	content := testfixtures.MustGet(t, "cmd.phone_mobile_nosep") + "\n"
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
	if strings.Contains(out, testfixtures.MustGet(t, "cmd.phone_mobile_sep")) {
		t.Fatalf("--explain should not unmask match: %s", out)
	}
}

// TestScanTextExplain は text 出力でも --explain で検出理由が確認できることを
// 確認する（従来は json 限定だった）。
func TestScanTextExplain(t *testing.T) {
	dir := piiDir(t)
	without, code := run(t, dir, "scan", ".")
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if strings.Contains(without, "理由:") {
		t.Errorf("--explain 未指定では理由を出すべきではない: %s", without)
	}
	out, code := run(t, dir, "scan", "--explain", ".")
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(out, "理由:") {
		t.Fatalf("--explain should annotate text output with a reason: %s", out)
	}
	if strings.Contains(out, testfixtures.MustGet(t, "cmd.phone_mobile_sep")) {
		t.Fatalf("--explain should not unmask match: %s", out)
	}
}

// TestScanFailOnSeparateFromMinConfidence は --fail-on が --min-confidence
// （報告閾値）と独立した終了コード用の閾値であることを確認する。medium 検出は
// 常に報告されるが、--fail-on high を指定すると high 未満のみの場合は exit 0
// になる（--format github が信頼度に関わらず一律 CI を落としていた問題への対処）。
func TestScanFailOnSeparateFromMinConfidence(t *testing.T) {
	dir := t.TempDir()
	// 区切りなし携帯（コンテキストなし）は medium 信頼度で検出される。
	content := testfixtures.MustGet(t, "cmd.phone_mobile_nosep") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	// --fail-on 未指定: 既存契約どおり報告があれば exit 1。
	if _, code := run(t, dir, "scan", "."); code != 1 {
		t.Error("--fail-on 未指定なら medium 検出でも exit 1 のはず（既存の exit code 契約）")
	}
	// --fail-on high: medium 検出は報告されるが、high 未満のため exit 0。
	out, code := run(t, dir, "scan", "--fail-on", "high", ".")
	if code != 0 {
		t.Errorf("--fail-on high で medium 検出のみなら exit 0 のはず, got %d", code)
	}
	if !strings.Contains(out, "jp-phone-number") {
		t.Errorf("--fail-on を指定しても報告自体は行われるはず: %s", out)
	}
}

// TestScanFailOnTriggersAtOrAboveThreshold は --fail-on 閾値以上の検出があれば
// exit 1 になることを確認する（TestScanFailOnSeparateFromMinConfidence の対比）。
func TestScanFailOnTriggersAtOrAboveThreshold(t *testing.T) {
	dir := piiDir(t) // TEL: ラベル付き区切りあり携帯 → high 信頼度
	if _, code := run(t, dir, "scan", "--fail-on", "high", "."); code != 1 {
		t.Error("--fail-on high は high 信頼度の検出があれば exit 1 のはず")
	}
	if _, code := run(t, dir, "scan", "--fail-on", "low", "."); code != 1 {
		t.Error("--fail-on low は high 信頼度の検出があれば exit 1 のはず")
	}
}

func TestScanFailOnCanBeLowerThanReportThreshold(t *testing.T) {
	dir := t.TempDir()
	content := testfixtures.MustGet(t, "cmd.phone_mobile_nosep") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, dir, "scan", "--min-confidence", "high", "--fail-on", "medium", ".")
	if code != 1 {
		t.Errorf("非表示の medium finding でも --fail-on medium なら exit = %d, want 1", code)
	}
	if out != "" {
		t.Errorf("--min-confidence high なので medium finding は表示しない: %s", out)
	}
}

// TestScanFailOnExitZeroStillWins は --exit-zero が --fail-on より優先される
// （既存の --exit-zero の意味を変えない）ことを確認する。
func TestScanFailOnExitZeroStillWins(t *testing.T) {
	dir := piiDir(t)
	if _, code := run(t, dir, "scan", "--fail-on", "low", "--exit-zero", "."); code != 0 {
		t.Error("--exit-zero は --fail-on より優先されるはず")
	}
}

// フィクスチャ不要（--fail-on の値検証は走査対象の内容に依存しないため）。
func TestScanFailOnInvalidValueExitsTwo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("no pii\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, code := run(t, dir, "scan", "--fail-on", "bogus", "."); code != 2 {
		t.Error("--fail-on bogus は exit 2 のはず")
	}
}

// TestScanFlagAfterPositionalPath は "scan . --high-recall" のようにパス指定の
// 後ろに置かれたフラグも解釈されることを確認する回帰テスト。以前は Go の flag
// パッケージの制約により "--high-recall" 自体が存在しないパスとして扱われ、
// 分かりにくい「no such file」エラー（exit 2）になっていた。
func TestScanFlagAfterPositionalPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("勤務地: 渋谷区道玄坂2-10-7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outBefore, codeBefore := run(t, dir, "scan", "--high-recall", ".")
	outAfter, codeAfter := run(t, dir, "scan", ".", "--high-recall")
	if codeBefore != 1 || codeAfter != 1 {
		t.Fatalf("exit codes = %d/%d, want 1/1（フラグの前後どちらでも同じ結果のはず）", codeBefore, codeAfter)
	}
	if outBefore != outAfter {
		t.Errorf("output differs by flag position:\nbefore=%q\nafter=%q", outBefore, outAfter)
	}
	if !strings.Contains(outAfter, "jp-address-high-recall") {
		t.Fatalf("missing high-recall rule when flag follows path: %s", outAfter)
	}
}

// TestScanFlagWithValueAfterPositionalPath は値ありフラグ（--format）もパスの
// 後ろで機能することを確認する。
func TestScanFlagWithValueAfterPositionalPath(t *testing.T) {
	dir := piiDir(t)
	out, code := run(t, dir, "scan", ".", "--format", "json")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	var doc struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON（パス後ろの --format 値が正しく解釈されていない可能性）: %v\n%s", err, out)
	}
	if doc.Count != 1 {
		t.Errorf("count = %d, want 1", doc.Count)
	}
}

// TestScanDoubleDashStopsFlagParsing は "--" 以降を非フラグ引数として扱う
// Go flag パッケージ標準の挙動を、フラグ並べ替え後も壊していないことを確認する。
func TestScanDoubleDashStopsFlagParsing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("no pii\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, code := run(t, dir, "scan", "--", "."); code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
}

// TestScanHyphenLeadingPathAfterDoubleDash は、ハイフン始まりの実ファイルを
// 標準 CLI と同じく "--" の後へ置けば走査できることを確認する。
func TestScanHyphenLeadingPathAfterDoubleDash(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.txt", "-weird.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("no pii\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, code := run(t, dir, "scan", ".", "--", "-weird.txt"); code != 0 {
		t.Errorf("exit = %d, want 0（-weird.txt はパスとして扱う）", code)
	}
}

func TestCLIHelpVersionAndUnknownFlags(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{{"--help"}, {"scan", "--help"}, {"rules", "-h"}} {
		out, code := run(t, dir, args...)
		if code != 0 || !strings.Contains(out, "Usage:") {
			t.Errorf("%v: exit=%d output=%q", args, code, out)
		}
	}
	for _, arg := range []string{"version", "--version", "-version"} {
		out, code := run(t, dir, arg)
		if code != 0 || strings.TrimSpace(out) == "" {
			t.Errorf("%s: exit=%d output=%q", arg, code, out)
		}
	}
	for _, args := range [][]string{{"scan", "--typo"}, {"scan", ".", "--typo"}, {"rules", "--typo"}} {
		_, stderr, code := runWithStderr(t, dir, args...)
		if code != 2 || !strings.Contains(stderr, "unknown flag") {
			t.Errorf("%v: exit=%d stderr=%q", args, code, stderr)
		}
	}
}

func TestScanRejectsAmbiguousModesAndPaths(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"scan", "--stdin", "--staged"},
		{"scan", "--staged", "--diff", "HEAD~1"},
		{"scan", "--staged", "."},
		{"scan", "--summary", "--quiet"},
	} {
		if _, code := run(t, dir, args...); code != 2 {
			t.Errorf("%v: exit=%d, want 2", args, code)
		}
	}
}

func TestScanSummaryIsWrittenToStderr(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("no pii\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runWithStderr(t, dir, "scan", "--summary", ".")
	if code != 0 || stdout != "" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, want := range []string{"summary:", "mode=full", "scanned=1", "findings=0", "warnings=0"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("summary missing %q: %s", want, stderr)
		}
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

// stdinJSONFinding は scan --stdin --format json の findings 配列 1 要素分の
// 部分デコード先（TestScanStdinDecodesJSONUnicodeEscapes 系のテストで共有）。
type stdinJSONFinding struct {
	RuleID    string `json:"rule_id"`
	Match     string `json:"match"`
	Offset    *int   `json:"offset"`
	EndOffset *int   `json:"end_offset"`
}

// runStdinJSON は jp-pii-detect scan --stdin --format json --unmask を input
// に対して実行し、パース済みの findings と終了コードを返す（TestScanStdinOffsets
// と同じ流儀。t.TempDir() で実行することでリポジトリの .jp-pii.toml を拾わず
// 既定設定で走査する）。
func runStdinJSON(t *testing.T, input string) ([]stdinJSONFinding, int) {
	t.Helper()
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
	var doc struct {
		Findings []stdinJSONFinding `json:"findings"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	return doc.Findings, code
}

// jsonEscapeAll は s の非 ASCII ルーンを JSON の \uXXXX エスケープ表記へ変換
// する（json.dumps(s, ensure_ascii=True) の非 ASCII 部分相当を手組みするテスト
// ヘルパー）。internal/source の同名の非公開テストヘルパーとは独立（package
// main_test からは呼べないため）。本テストで使うフィクスチャ値（氏名）は
// BMP 内に収まるためサロゲートペア対応は省略する。
func jsonEscapeAll(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x80 {
			b.WriteRune(r)
			continue
		}
		fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}

// TestScanStdinDecodesJSONUnicodeEscapes は scan --stdin が、フルスキャン
// （internal/source の scanFiles）の最終段と同じ JSON \uXXXX エスケープの
// 復号ビュー（internal/source.DecodeEscapedView）を適用することを確認する。
func TestScanStdinDecodesJSONUnicodeEscapes(t *testing.T) {
	name := testfixtures.MustGet(t, "detect.name_sato_hanako")

	// エスケープあり: json.dumps({"customer_name": name}, ensure_ascii=True)
	// 相当の入力から氏名（person-name）が検出され、offset/end_offset は
	// エスケープ済みの元 stdin ではなく復号後テキスト上のルーンオフセットに
	// なることを確認する。
	t.Run("エスケープあり", func(t *testing.T) {
		input := `{"customer_name": "` + jsonEscapeAll(name) + `"}` + "\n"
		// decodeJSONUnicodeEscapes は改行を生まないため行数は不変、\uXXXX
		// （6 ルーン）は名前の実ルーン数へ縮む。オフセット検証の期待値として
		// 復号後テキストを手組みする。
		decodedRunes := []rune(`{"customer_name": "` + name + `"}` + "\n")

		findings, code := runStdinJSON(t, input)
		if code != 1 {
			t.Fatalf("exit = %d, want 1（検出あり）", code)
		}

		var found bool
		for _, f := range findings {
			if f.RuleID != "person-name" {
				continue
			}
			found = true
			if f.Offset == nil || f.EndOffset == nil {
				t.Fatalf("offset/end_offset が無い: %+v", f)
			}
			if *f.Offset < 0 || *f.EndOffset > len(decodedRunes) || *f.Offset > *f.EndOffset {
				t.Fatalf("offset 範囲外: [%d, %d) len=%d", *f.Offset, *f.EndOffset, len(decodedRunes))
			}
			if got := string(decodedRunes[*f.Offset:*f.EndOffset]); got != f.Match {
				t.Errorf("復号後テキスト[%d:%d] = %q, want match %q", *f.Offset, *f.EndOffset, got, f.Match)
			}
			if f.Match != name {
				t.Errorf("match = %q, want %q", f.Match, name)
			}
		}
		if !found {
			t.Fatalf("person-name が検出されなかった: %+v", findings)
		}
	})

	// エスケープなし: \u を含まない入力は DecodeEscapedView が ok=false を返し
	// text を変更しないため、出力（offset を含む）は本機能追加前と不変である
	// はず。TestScanStdinOffsets と同じ入力・期待値を使った回帰確認。
	t.Run("エスケープなし_出力不変", func(t *testing.T) {
		input := "連絡先一覧\n担当: test.user@kaisha.co.jp まで\n"
		runes := []rune(input)

		findings, code := runStdinJSON(t, input)
		if code != 1 {
			t.Fatalf("exit = %d, want 1（検出あり）", code)
		}

		var found bool
		for _, f := range findings {
			if f.RuleID != "email-address" {
				continue
			}
			found = true
			if f.Offset == nil || f.EndOffset == nil {
				t.Fatalf("offset/end_offset が無い: %+v", f)
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
			t.Fatalf("email-address が検出されなかった: %+v", findings)
		}
	})
}

// baselineJSON は scan --baseline --format json を実行し、パース済みの
// findings（rule_id/file/fingerprint のみ）と count、終了コードを返す。
func baselineJSON(t *testing.T, dir string, args ...string) (findings []struct {
	RuleID      string `json:"rule_id"`
	File        string `json:"file"`
	Fingerprint string `json:"fingerprint"`
}, count, code int) {
	t.Helper()
	out, code := run(t, dir, args...)
	var doc struct {
		Count    int `json:"count"`
		Findings []struct {
			RuleID      string `json:"rule_id"`
			File        string `json:"file"`
			Fingerprint string `json:"fingerprint"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	return doc.Findings, doc.Count, code
}

// TestBaselineUpdateThenFilterSuppressesKnownFindings は --update-baseline →
// --baseline の往復で、既知の finding が exit 0（0 件）になることを確認する
// positive ケース。メールアドレスは機微でない架空ドメインを使うためフィクスチャ
// 不要（TestScanStdinOffsets と同じ慣習）。
func TestBaselineUpdateThenFilterSuppressesKnownFindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "legacy.txt"), []byte("担当: legacy.user@kaisha.co.jp まで\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(dir, "baseline.json")

	// baseline 導入前は通常どおり検出されて exit 1。
	if _, code := run(t, dir, "scan", "."); code != 1 {
		t.Fatalf("baseline 導入前: exit = %d, want 1", code)
	}

	out, code := run(t, dir, "scan", "--baseline", baselinePath, "--update-baseline", ".")
	if code != 0 {
		t.Fatalf("--update-baseline: exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, baselinePath) {
		t.Errorf("update-baseline の完了メッセージにパスが含まれない: %s", out)
	}
	if _, err := os.Stat(baselinePath); err != nil {
		t.Fatalf("baseline file not created: %v", err)
	}

	findings, count, code := baselineJSON(t, dir, "scan", "--baseline", baselinePath, "--format", "json", ".")
	if code != 0 {
		t.Fatalf("--baseline: exit = %d, want 0（既知の finding は除外される）", code)
	}
	if count != 0 || len(findings) != 0 {
		t.Errorf("findings = %v, want empty（baseline 済み）", findings)
	}
}

// TestBaselineNewFindingStillFails は baseline に無い新規 finding が引き続き
// exit 1 になることを確認する negative ケース。
func TestBaselineNewFindingStillFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "legacy.txt"), []byte("担当: legacy.user@kaisha.co.jp まで\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(dir, "baseline.json")
	if _, code := run(t, dir, "scan", "--baseline", baselinePath, "--update-baseline", "."); code != 0 {
		t.Fatal("update-baseline should exit 0")
	}

	// 新規ファイルに別のメールアドレスを追加する（baseline には未記録）。
	if err := os.WriteFile(filepath.Join(dir, "new.txt"), []byte("担当: new.user@kaisha.co.jp まで\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, count, code := baselineJSON(t, dir, "scan", "--baseline", baselinePath, "--format", "json", ".")
	if code != 1 {
		t.Fatalf("新規 finding があるので exit = %d, want 1", code)
	}
	if count != 1 || len(findings) != 1 || findings[0].File != "new.txt" {
		t.Errorf("findings = %v, want only new.txt", findings)
	}
}

// TestBaselineValueChangeStillFires は baseline 済みだった finding でも、
// 検出値自体が変わっていれば別 fingerprint として扱われ、引き続き検出される
// ことを確認する（fingerprint は値に依存し、行番号には依存しない設計の検証）。
func TestBaselineValueChangeStillFires(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.txt")
	if err := os.WriteFile(path, []byte("担当: legacy.user@kaisha.co.jp まで\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(dir, "baseline.json")
	if _, code := run(t, dir, "scan", "--baseline", baselinePath, "--update-baseline", "."); code != 0 {
		t.Fatal("update-baseline should exit 0")
	}

	// 同じファイル・同じ行の値だけを変更する。
	if err := os.WriteFile(path, []byte("担当: legacy.user.changed@kaisha.co.jp まで\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, count, code := baselineJSON(t, dir, "scan", "--baseline", baselinePath, "--format", "json", ".")
	if code != 1 {
		t.Fatalf("値が変わった finding は exit = %d, want 1", code)
	}
	if count != 1 || len(findings) != 1 || findings[0].File != "legacy.txt" {
		t.Errorf("findings = %v, want the changed legacy.txt finding", findings)
	}
}

// TestBaselineUpdateMergesWithExisting は --update-baseline を 2 回実行した
// とき、既存の fingerprint を保ったまま新規分だけが追記される（＝2 回目以降も
// 1 回目の記録が失われない）ことを確認する。
func TestBaselineUpdateMergesWithExisting(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "legacy.txt"), []byte("担当: legacy.user@kaisha.co.jp まで\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(dir, "baseline.json")
	if _, code := run(t, dir, "scan", "--baseline", baselinePath, "--update-baseline", "."); code != 0 {
		t.Fatal("1st update-baseline should exit 0")
	}

	if err := os.WriteFile(filepath.Join(dir, "new.txt"), []byte("担当: new.user@kaisha.co.jp まで\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, code := run(t, dir, "scan", "--baseline", baselinePath, "--update-baseline", "."); code != 0 {
		t.Fatal("2nd update-baseline should exit 0")
	}

	// 両方のファイルとも既知になっているはず。
	_, count, code := baselineJSON(t, dir, "scan", "--baseline", baselinePath, "--format", "json", ".")
	if code != 0 || count != 0 {
		t.Errorf("count = %d, code = %d, want 0/0（両方とも baseline 済み）", count, code)
	}
}

// TestBaselineShowBaselineDisplaysWithoutAffectingExitCode は --show-baseline
// が baseline 済みの finding も参考表示するが、終了コードには影響しないことを
// 確認する。
func TestBaselineShowBaselineDisplaysWithoutAffectingExitCode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "legacy.txt"), []byte("担当: legacy.user@kaisha.co.jp まで\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(dir, "baseline.json")
	if _, code := run(t, dir, "scan", "--baseline", baselinePath, "--update-baseline", "."); code != 0 {
		t.Fatal("update-baseline should exit 0")
	}

	// --baseline のみ: 既知分のみなので exit 0、表示も 0 件。
	_, count, code := baselineJSON(t, dir, "scan", "--baseline", baselinePath, "--format", "json", ".")
	if code != 0 || count != 0 {
		t.Fatalf("--baseline のみ: count=%d code=%d, want 0/0", count, code)
	}

	// --show-baseline を付けると baseline 済み分が参考表示されるが、
	// 新規 finding が無いので終了コードは 0 のまま。
	findings, count, code := baselineJSON(t, dir, "scan", "--baseline", baselinePath, "--show-baseline", "--format", "json", ".")
	if code != 0 {
		t.Fatalf("--show-baseline: exit = %d, want 0（新規 finding が無いため）", code)
	}
	if count != 1 || len(findings) != 1 || findings[0].File != "legacy.txt" {
		t.Errorf("--show-baseline should list the baselined finding for reference: %v", findings)
	}
}

// TestBaselineFlagValidation は --update-baseline / --show-baseline が
// --baseline <path> 無しで指定された場合、走査せず exit 2 になることを確認する。
func TestBaselineFlagValidation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("no pii\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"scan", "--update-baseline", "."},
		{"scan", "--show-baseline", "."},
	} {
		if _, code := run(t, dir, args...); code != 2 {
			t.Errorf("%v: exit = %d, want 2", args, code)
		}
	}
}

// TestBaselineLoadMissingFileExitsTwo は --baseline に存在しないファイルを
// 指定した場合、走査エラーとして exit 2 になることを確認する
// （--update-baseline と違い、事前作成なしでは自動生成しない）。
func TestBaselineLoadMissingFileExitsTwo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("no pii\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, code := run(t, dir, "scan", "--baseline", filepath.Join(dir, "nonexistent-baseline.json"), "."); code != 2 {
		t.Errorf("exit = %d, want 2", code)
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

// ruleLine は rules コマンドの出力から ID 列（左詰め）が id に一致する行を探す。
func ruleLine(t *testing.T, out, id string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == id {
			return line
		}
	}
	t.Fatalf("rules output missing %s:\n%s", id, out)
	return ""
}

// TestRulesCommandRespectsConfig は rules コマンドが config.Load 経由で
// .jp-pii.toml の disabled 指定を反映することを確認する（以前は rule.Builtin() を
// 素通ししていたため、設定ファイルで無効化したルールも常に「使える」ように
// 見えていた）。
func TestRulesCommandRespectsConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".jp-pii.toml")
	if err := os.WriteFile(cfgPath, []byte("[rules]\ndisabled = [\"jp-my-number\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, dir, "rules", "--config", cfgPath)
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	if line := ruleLine(t, out, "jp-my-number"); !strings.Contains(line, "無効") {
		t.Errorf("disabled ルールが「無効」と表示されていない: %s", line)
	}
	if line := ruleLine(t, out, "jp-phone-number"); !strings.Contains(line, "有効") {
		t.Errorf("disabled していないルールが「有効」と表示されていない: %s", line)
	}
}

// rules コマンドは --config を反映した実効ルール一覧（builtin + custom の合成、
// disabled 指定は除外ではなく「無効」タグで表示）を出力する。
func TestRulesCommandWithConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".jp-pii.toml")
	cfgBody := `
[rules]
disabled = ["credit-card"]

[[rules.custom]]
id = "student-id"
description = "学籍番号"
pattern = 'S\d{8}'
digit_boundary = true
`
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, dir, "rules", "--config", cfgPath)
	if code != 0 {
		t.Errorf("exit = %d, want 0:\n%s", code, out)
	}
	if line := ruleLine(t, out, "credit-card"); !strings.Contains(line, "無効") {
		t.Errorf("disabled ルールが「無効」と表示されていない: %s", line)
	}
	if !strings.Contains(out, "student-id") {
		t.Errorf("rules output missing custom rule student-id:\n%s", out)
	}
}

// TestRulesCommandHighRecallFlag は rules コマンドが --high-recall の効果
// （高再現率ルールの有効化）を反映することを確認する。
func TestRulesCommandHighRecallFlag(t *testing.T) {
	dir := t.TempDir()
	outDefault, code := run(t, dir, "rules")
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	line := ruleLine(t, outDefault, "jp-address-high-recall")
	if !strings.Contains(line, "無効") || !strings.Contains(line, "高再現率") {
		t.Errorf("既定では高再現率ルールは無効と表示されるはず: %s", line)
	}

	outHR, code := run(t, dir, "rules", "--high-recall")
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	lineHR := ruleLine(t, outHR, "jp-address-high-recall")
	if !strings.Contains(lineHR, "有効") || !strings.Contains(lineHR, "高再現率") {
		t.Errorf("--high-recall 指定時は高再現率ルールが有効と表示されるはず: %s", lineHR)
	}
}

// TestRulesCommandHighRecallConfig は rules コマンドが設定ファイルの
// high_recall=true も scan と同じように実効状態へ反映することを確認する。
func TestRulesCommandHighRecallConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".jp-pii.toml")
	if err := os.WriteFile(cfgPath, []byte("[rules]\nhigh_recall = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, dir, "rules", "--config", cfgPath)
	if code != 0 {
		t.Fatalf("exit = %d, want 0:\n%s", code, out)
	}
	line := ruleLine(t, out, "jp-address-high-recall")
	if !strings.Contains(line, "有効") || !strings.Contains(line, "高再現率") {
		t.Errorf("high_recall=true の実効状態が表示されていない: %s", line)
	}
}

// カスタムルールの正規表現コンパイル失敗は、rules コマンドでも
// panic ではなく exit 2（設定エラー）として扱う。
func TestRulesCommandInvalidCustomRule(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".jp-pii.toml")
	cfgBody := "[[rules.custom]]\nid = \"bad\"\npattern = \"(\"\n"
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, code := run(t, dir, "rules", "--config", cfgPath); code != 2 {
		t.Errorf("exit = %d, want 2 for invalid custom rule regex", code)
	}
}

func TestVersionCommand(t *testing.T) {
	out, code := run(t, t.TempDir(), "version")
	if code != 0 || strings.TrimSpace(out) == "" {
		t.Errorf("version: exit=%d out=%q", code, out)
	}
}

// explainDroppedDir は口座番号（jp-bank-account、コンテキスト "口座" あり）と
// 同じ 7 桁を共有するが郵便番号としてはコンテキスト不足で棄却される値を持つ
// 作業ディレクトリを作る（--explain-dropped の require-context-missing 確認用。
// 実在しうる番号形式を含まない合成データのためフィクスチャ不要）。
func explainDroppedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	content := "口座番号: 1234567 (手数料300円)\n"
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestScanJSONExplainDropped は --explain-dropped 指定時のみ JSON 出力に
// dropped 配列（rule_id/reason 等）が追加され、生の検出値を含まないことを
// 確認する。未指定時は "dropped" キー自体が出力に現れないこと（出力スキーマが
// 完全に不変であること）も確認する。
func TestScanJSONExplainDropped(t *testing.T) {
	dir := explainDroppedDir(t)

	without, code := run(t, dir, "scan", "--format", "json", ".")
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if strings.Contains(without, `"dropped"`) {
		t.Errorf("--explain-dropped 未指定では dropped キーを出すべきではない: %s", without)
	}

	out, code := run(t, dir, "scan", "--format", "json", "--explain-dropped", ".")
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(out, `"dropped"`) || !strings.Contains(out, `"jp-postal-code"`) ||
		!strings.Contains(out, `"require-context-missing"`) {
		t.Fatalf("--explain-dropped should list the dropped candidate with its reason: %s", out)
	}
	if strings.Contains(out, "1234567") {
		t.Fatalf("--explain-dropped leaked a raw value: %s", out)
	}
}

// TestScanTextExplainDropped は --explain-dropped 指定時のみ text 出力に
// 「棄却候補」セクションが追加されることを確認する（未指定時は追加されない）。
func TestScanTextExplainDropped(t *testing.T) {
	dir := explainDroppedDir(t)

	without, code := run(t, dir, "scan", ".")
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if strings.Contains(without, "棄却候補") {
		t.Errorf("--explain-dropped 未指定では棄却候補セクションを出すべきではない: %s", without)
	}

	out, code := run(t, dir, "scan", "--explain-dropped", ".")
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(out, "棄却候補") || !strings.Contains(out, "jp-postal-code") ||
		!strings.Contains(out, "require-context-missing") {
		t.Fatalf("--explain-dropped should annotate text output with dropped candidates: %s", out)
	}
	if strings.Contains(out, "1234567") {
		t.Fatalf("--explain-dropped leaked a raw value: %s", out)
	}
}
