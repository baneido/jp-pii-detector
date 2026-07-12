package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// mockRecognizerSource は [external_recognizer] からモック外部レコグナイザとして
// 呼び出す、最小限の standalone Go プログラム。internal/external・internal/source の
// テストで使う「テストバイナリ自身を再実行する」パターン（TestHelperProcess）は
// ここでは使えない: cmd/jp-pii-detect の TestMain は常に `go build -o binPath .` を
// 実行してから m.Run() へ進むため、re-exec した子プロセスの作業ディレクトリに
// go.mod が無いと（このテストが作る一時ディレクトリはリポジトリ外）TestMain 自体が
// panic してしまう。そのため、この 1 ファイルだけは go build で単体の実行ファイルに
// してから command として渡す（jp-pii-detect 本体プロセスから見れば実運用の
// python3 レコグナイザ等と同じ「外部の実行ファイル」であり、実運用の起動経路に
// 忠実な検証になる）。
const mockRecognizerSource = `package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req map[string]any
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		text, _ := req["text"].(string)
		if text == "" {
			continue
		}
		file, _ := req["file"].(string)
		fmt.Printf("{\"file\":%q,\"rule_id\":\"demo-marker-external\",\"line\":1,\"column\":1,\"length\":4,\"confidence\":\"high\"}\n", file)
	}
}
`

// buildMockRecognizer は mockRecognizerSource を go build して実行ファイルのパスを返す。
// 受け取った各リクエストにつき固定スパン（1行目・1列目・4ルーン）の候補
// "demo-marker-external" を返すだけの最小実装。
func buildMockRecognizer(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "mock_recognizer.go")
	if err := os.WriteFile(src, []byte(mockRecognizerSource), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "mock-recognizer")
	if out, err := exec.Command("go", "build", "-o", bin, src).CombinedOutput(); err != nil {
		t.Fatalf("build mock recognizer: %v\n%s", err, out)
	}
	return bin
}

// externalRecognizerConfigTOML は [external_recognizer] 設定を作る。
func externalRecognizerConfigTOML(binPath string) string {
	return "[external_recognizer]\ncommand = [\"" + binPath + "\"]\ntimeout_seconds = 10\n"
}

// runStdin は run（main_test.go）の標準入力対応版。
func runStdin(t *testing.T, dir, input string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(input)
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

func TestScanFullScanWithExternalRecognizer(t *testing.T) {
	mockBin := buildMockRecognizer(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "note.txt"), []byte("ABCD is written here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 設定ファイルはスキャン対象ディレクトリの外に置く（中に置くと設定ファイル自身の
	// テキストも外部レコグナイザへ送られてしまい、テストの assertion が複雑になるため）。
	cfgPath := filepath.Join(t.TempDir(), "ext.jp-pii.toml")
	if err := os.WriteFile(cfgPath, []byte(externalRecognizerConfigTOML(mockBin)), 0o644); err != nil {
		t.Fatal(err)
	}

	out, code := run(t, dir, "scan", "--config", cfgPath, "--format", "json", ".")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (external finding present)\n%s", code, out)
	}
	var doc struct {
		Findings []struct {
			RuleID string `json:"rule_id"`
			File   string `json:"file"`
			Match  string `json:"match"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	found := false
	for _, f := range doc.Findings {
		if f.RuleID == "demo-marker-external" {
			found = true
			if !strings.HasSuffix(f.File, "note.txt") {
				t.Errorf("finding.File = %q, want suffix note.txt", f.File)
			}
		}
	}
	if !found {
		t.Fatalf("no demo-marker-external finding in output: %s", out)
	}
}

func TestScanStdinWithExternalRecognizer(t *testing.T) {
	mockBin := buildMockRecognizer(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ext.jp-pii.toml")
	if err := os.WriteFile(cfgPath, []byte(externalRecognizerConfigTOML(mockBin)), 0o644); err != nil {
		t.Fatal(err)
	}

	out, code := runStdin(t, dir, "ABCD is written here\n", "scan", "--config", cfgPath, "--format", "json", "--stdin")
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (external finding present)\n%s", code, out)
	}
	var doc struct {
		Findings []struct {
			RuleID    string `json:"rule_id"`
			File      string `json:"file"`
			Offset    *int   `json:"offset"`
			EndOffset *int   `json:"end_offset"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	found := false
	for _, f := range doc.Findings {
		if f.RuleID == "demo-marker-external" {
			found = true
			if f.File != "<stdin>" {
				t.Errorf("finding.File = %q, want <stdin>", f.File)
			}
			// --stdin は ComputeOffsets を通すため、外部レコグナイザ由来の finding にも
			// offset/end_offset が付与されるはず。
			if f.Offset == nil || f.EndOffset == nil {
				t.Errorf("finding = %+v, want offset/end_offset to be set", f)
			} else if *f.Offset != 0 || *f.EndOffset != 4 {
				t.Errorf("offset/end_offset = %d/%d, want 0/4", *f.Offset, *f.EndOffset)
			}
		}
	}
	if !found {
		t.Fatalf("no demo-marker-external finding in output: %s", out)
	}
}

func TestScanWithoutExternalRecognizerConfiguredBehavesAsBefore(t *testing.T) {
	// [external_recognizer] を設定しない既定状態では、外部レコグナイザ関連の
	// コードパスに一切触れないことを確認する（既存の振る舞いに影響しないことの
	// 回帰テスト）。
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "note.txt"), []byte("no pii here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, dir, "scan", ".")
	if code != 0 {
		t.Errorf("exit = %d, want 0: %s", code, out)
	}
}
