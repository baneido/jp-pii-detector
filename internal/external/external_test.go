package external

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// テスト方針: 実際の子プロセスを起動して検証したいが、python3 等の外部処理系に
// 依存すると `go test ./...` の可搬性が落ちる。Go 標準ライブラリ（os/exec_test.go 等）
// と同じ「テストバイナリ自身を再実行するモックヘルパー」パターンを使う。
// TestHelperProcess は JP_PII_EXTERNAL_TEST_HELPER 環境変数が立っているときだけ
// 本体として動作し、通常の `go test` 実行では何もしない空テストとして扱われる
// （helperConfig が Command[0]=os.Args[0] を渡して自分自身を再実行させる）。

// helperConfig は TestHelperProcess を子プロセスとして起動する Config を作る。
// mode は TestHelperProcess 側の switch で分岐する動作モード。
func helperConfig(mode string) Config {
	return Config{
		Command: []string{os.Args[0], "-test.run=^TestHelperProcess$", "--", mode},
	}
}

// TestHelperProcess は実テストではなく、Run() が再実行するモック外部レコグナイザの
// 本体。JP_PII_EXTERNAL_TEST_HELPER が立っていなければ即座に return する（通常の
// `go test ./...` 実行時は空の合格テストとして扱われる）。
func TestHelperProcess(t *testing.T) {
	if os.Getenv("JP_PII_EXTERNAL_TEST_HELPER") != "1" {
		return
	}
	defer os.Exit(0)

	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}
	if len(args) == 0 {
		return
	}

	switch args[0] {
	case "echo-fixed":
		readHelperRequests()
		os.Stdout.WriteString(`{"file":"a.txt","rule_id":"person-name-external","line":1,"column":1,"length":2,"confidence":"medium"}` + "\n")
	case "echo-per-file":
		for _, r := range readHelperRequests() {
			os.Stdout.WriteString(`{"file":"` + r.File + `","rule_id":"person-name-external","line":1,"column":1,"length":1,"confidence":"low"}` + "\n")
		}
	case "sleep":
		readHelperRequests()
		time.Sleep(5 * time.Second)
	case "bad-json":
		readHelperRequests()
		os.Stdout.WriteString(`{"file":"a.txt","rule_id":"person-name-external","line":1,"column":1,"length":1,"confidence":"low"}` + "\n")
		os.Stdout.WriteString("not valid json\n")
	case "bad-json-flood":
		readHelperRequests()
		os.Stdout.WriteString("not valid json\n")
		// 親が不正行を検出した直後に読み取りをやめても、子プロセスが大量に
		// 書き込み続けようとするとパイプが詰まってブロックする状況を再現する
		// （典型的なパイプバッファ 64KB を大きく超える単発の Write）。
		big := bytes.Repeat([]byte("x"), 8*1024*1024)
		os.Stdout.Write(big)
		os.Stdout.WriteString("\n")
	case "nonzero-exit":
		readHelperRequests()
		os.Exit(1)
	case "many":
		readHelperRequests()
		for range 2000 {
			os.Stdout.WriteString(`{"file":"a.txt","rule_id":"many-external","line":1,"column":1,"length":1,"confidence":"low"}` + "\n")
		}
	case "stderr-and-echo":
		readHelperRequests()
		os.Stderr.WriteString("diag message from helper\n")
		os.Stdout.WriteString(`{"file":"a.txt","rule_id":"person-name-external","line":1,"column":1,"length":1,"confidence":"low"}` + "\n")
	case "empty-lines":
		readHelperRequests()
		os.Stdout.WriteString("\n")
		os.Stdout.WriteString(`{"file":"a.txt","rule_id":"person-name-external","line":1,"column":1,"length":1,"confidence":"low"}` + "\n")
		os.Stdout.WriteString("\n")
	}
}

// readHelperRequests は標準入力から JSONL のリクエスト行をすべて読み切る
// （request は external.go 定義の非公開型。同一パッケージなのでそのまま使える）。
func readHelperRequests() []request {
	var reqs []request
	dec := json.NewDecoder(os.Stdin)
	for {
		var r request
		if err := dec.Decode(&r); err != nil {
			break
		}
		reqs = append(reqs, r)
	}
	return reqs
}

func TestRunDisabledConfigDoesNothing(t *testing.T) {
	cands, diags := Run(context.Background(), Config{}, []FileInput{{File: "a.txt", Text: "x"}})
	if cands != nil || diags != nil {
		t.Fatalf("Run(Config{}) = %v, %v; want nil, nil（未設定時は一切実行されない）", cands, diags)
	}
}

func TestRunEmptyInputsDoesNothing(t *testing.T) {
	// command 自体は（存在すれば）実行可能でも、inputs が空なら起動しない
	// （存在しないコマンドを指定しているのは「呼ばれていれば診断が出るはず」を
	// 逆手に取った検証: diags が空のままなら exec.Command 自体に到達していない）。
	cfg := Config{Command: []string{"this-command-does-not-exist-anywhere"}}
	cands, diags := Run(context.Background(), cfg, nil)
	if cands != nil || diags != nil {
		t.Fatalf("Run with no inputs = %v, %v; want nil, nil", cands, diags)
	}
}

func TestRunEchoesValidCandidate(t *testing.T) {
	t.Setenv("JP_PII_EXTERNAL_TEST_HELPER", "1")
	cands, diags := Run(context.Background(), helperConfig("echo-fixed"),
		[]FileInput{{File: "a.txt", Text: "山田太郎です"}})
	if len(cands) != 1 {
		t.Fatalf("candidates = %v (diagnostics=%v), want 1", cands, diags)
	}
	want := Candidate{File: "a.txt", RuleID: "person-name-external", Line: 1, Column: 1, Length: 2, Confidence: "medium"}
	if cands[0] != want {
		t.Errorf("candidate = %+v, want %+v", cands[0], want)
	}
}

func TestRunGroupsCandidatesByFile(t *testing.T) {
	t.Setenv("JP_PII_EXTERNAL_TEST_HELPER", "1")
	inputs := []FileInput{
		{File: "a.txt", Text: "AAA"},
		{File: "b.txt", Text: "BBB"},
		{File: "c.txt", Text: "CCC"},
	}
	cands, diags := Run(context.Background(), helperConfig("echo-per-file"), inputs)
	if len(cands) != len(inputs) {
		t.Fatalf("candidates = %v (diagnostics=%v), want %d entries", cands, diags, len(inputs))
	}
	got := map[string]bool{}
	for _, c := range cands {
		got[c.File] = true
	}
	for _, in := range inputs {
		if !got[in.File] {
			t.Errorf("missing candidate for file %q in %v", in.File, cands)
		}
	}
}

func TestRunTimeoutDiscardsAll(t *testing.T) {
	t.Setenv("JP_PII_EXTERNAL_TEST_HELPER", "1")
	cfg := helperConfig("sleep")
	cfg.Timeout = 200 * time.Millisecond
	start := time.Now()
	cands, diags := Run(context.Background(), cfg, []FileInput{{File: "a.txt", Text: "x"}})
	elapsed := time.Since(start)
	if cands != nil {
		t.Errorf("candidates = %v, want nil on timeout", cands)
	}
	if len(diags) == 0 {
		t.Error("want at least one diagnostic message on timeout")
	}
	if elapsed > 4*time.Second {
		t.Errorf("Run took %s; timeout (200ms) does not appear to have been enforced", elapsed)
	}
}

func TestRunMalformedJSONLineDiscardsAllCandidates(t *testing.T) {
	t.Setenv("JP_PII_EXTERNAL_TEST_HELPER", "1")
	cands, diags := Run(context.Background(), helperConfig("bad-json"), []FileInput{{File: "a.txt", Text: "x"}})
	if cands != nil {
		t.Errorf("candidates = %v, want nil when a malformed JSON line is present", cands)
	}
	if len(diags) == 0 {
		t.Error("want a diagnostic message describing the malformed line")
	}
}

func TestRunNonZeroExitDiscardsAllCandidates(t *testing.T) {
	t.Setenv("JP_PII_EXTERNAL_TEST_HELPER", "1")
	cands, diags := Run(context.Background(), helperConfig("nonzero-exit"), []FileInput{{File: "a.txt", Text: "x"}})
	if cands != nil {
		t.Errorf("candidates = %v, want nil on nonzero exit", cands)
	}
	if len(diags) == 0 {
		t.Error("want a diagnostic message describing the abnormal exit")
	}
}

// TestRunMalformedJSONCancelsChildPromptlyEvenIfChildKeepsWriting は、不正な JSON 行を
// 検出した直後に読み取りをやめても、子プロセスがその後も大量に書き込み続けようとして
// パイプが詰まってブロックする状況で Run() が即座に子プロセスを強制終了し、
// タイムアウトいっぱいまで待たされないことを確認する回帰テスト。cancel() の
// 明示呼び出しを外すと、このテストは cfg.Timeout に近い時間がかかるようになり失敗する。
func TestRunMalformedJSONCancelsChildPromptlyEvenIfChildKeepsWriting(t *testing.T) {
	t.Setenv("JP_PII_EXTERNAL_TEST_HELPER", "1")
	cfg := helperConfig("bad-json-flood")
	cfg.Timeout = 5 * time.Second // 修正が効いていればこれよりずっと早く戻るはず
	start := time.Now()
	cands, diags := Run(context.Background(), cfg, []FileInput{{File: "a.txt", Text: "x"}})
	elapsed := time.Since(start)
	if cands != nil {
		t.Errorf("candidates = %v, want nil", cands)
	}
	if len(diags) == 0 {
		t.Error("want at least one diagnostic message")
	}
	if elapsed > 2*time.Second {
		t.Errorf("Run took %s after detecting a malformed JSON line (Timeout=%s); "+
			"want it to cancel the blocked child promptly instead of waiting near the full timeout", elapsed, cfg.Timeout)
	}
}

func TestRunMaxFindingsCapsCandidates(t *testing.T) {
	t.Setenv("JP_PII_EXTERNAL_TEST_HELPER", "1")
	cfg := helperConfig("many")
	cfg.MaxFindings = 10
	cands, diags := Run(context.Background(), cfg, []FileInput{{File: "a.txt", Text: "x"}})
	if len(cands) != 10 {
		t.Errorf("candidates = %d (diagnostics=%v), want exactly MaxFindings=10", len(cands), diags)
	}
}

func TestRunDefaultsMaxFindingsWhenUnset(t *testing.T) {
	t.Setenv("JP_PII_EXTERNAL_TEST_HELPER", "1")
	cfg := helperConfig("many") // helper がちょうど 2000 件送るため、既定 1000 でキャップされることを確認できる
	cands, _ := Run(context.Background(), cfg, []FileInput{{File: "a.txt", Text: "x"}})
	if len(cands) != DefaultMaxFindings {
		t.Errorf("candidates = %d, want DefaultMaxFindings=%d", len(cands), DefaultMaxFindings)
	}
}

func TestRunCapturesStderrAsDiagnostic(t *testing.T) {
	t.Setenv("JP_PII_EXTERNAL_TEST_HELPER", "1")
	cands, diags := Run(context.Background(), helperConfig("stderr-and-echo"), []FileInput{{File: "a.txt", Text: "x"}})
	if len(cands) != 1 {
		t.Fatalf("candidates = %v (diagnostics=%v)", cands, diags)
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d, "diag message from helper") {
			found = true
		}
	}
	if !found {
		t.Errorf("diagnostics = %v, want stderr content included", diags)
	}
}

func TestRunSkipsBlankLines(t *testing.T) {
	t.Setenv("JP_PII_EXTERNAL_TEST_HELPER", "1")
	cands, diags := Run(context.Background(), helperConfig("empty-lines"), []FileInput{{File: "a.txt", Text: "x"}})
	if len(cands) != 1 {
		t.Fatalf("candidates = %v (diagnostics=%v), want 1 (blank lines should be tolerated, not treated as malformed)", cands, diags)
	}
}
