package source

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/external"
)

// TestHelperProcess はモック外部レコグナイザの本体（internal/external/external_test.go
// と同じ「テストバイナリ自身を再実行する」パターン。パッケージごとに別のテスト
// バイナリになるため、ここにも同名のヘルパーが必要）。
// JP_PII_EXTERNAL_TEST_HELPER が立っていなければ即座に return する。
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
	case "mark-three":
		// 何を受け取っても同じ候補を 3 件返す（max_findings の上限超過の確認用）。
		dec := json.NewDecoder(os.Stdin)
		for {
			var req struct{}
			if err := dec.Decode(&req); err != nil {
				break
			}
		}
		for range 3 {
			os.Stdout.WriteString(`{"file":"a.txt","rule_id":"ext-marker-external","line":1,"column":1,"length":1,"confidence":"high"}` + "\n")
		}
	case "mark-each-file":
		// 受け取った各ファイルにつき 1 件、固定スパンの候補を返す
		// （テストは「どのファイルが子プロセスへ送られたか」を検証できる）。
		dec := json.NewDecoder(os.Stdin)
		enc := json.NewEncoder(os.Stdout)
		for {
			var req struct {
				File string `json:"file"`
				Text string `json:"text"`
			}
			if err := dec.Decode(&req); err != nil {
				break
			}
			if req.Text == "" {
				continue
			}
			_ = enc.Encode(struct {
				File       string `json:"file"`
				RuleID     string `json:"rule_id"`
				Line       int    `json:"line"`
				Column     int    `json:"column"`
				Length     int    `json:"length"`
				Confidence string `json:"confidence"`
			}{File: req.File, RuleID: "ext-marker-external", Line: 1, Column: 1, Length: 1, Confidence: "high"})
		}
	}
}

func externalHelperConfigTOML(mode string) string {
	// TOML の文字列配列として argv を渡す。os.Args[0] はテストバイナリの絶対パス。
	// Windows のパス（C:\Users\...）のバックスラッシュを TOML の基本文字列の
	// エスケープと解釈させないよう、リテラル文字列（'...'）で渡す。
	return "[external_recognizer]\ncommand = [" +
		`'` + os.Args[0] + `', "-test.run=^TestHelperProcess$", "--", "` + mode + `"` +
		"]\n"
}

func TestScanPathsWithoutExternalRecognizerNeverInvokesRunExternalRecognizer(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "a.txt"), []byte("no pii here\n"))

	cfg, err := config.Parse("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ExternalRecognizerEnabled() {
		t.Fatal("default config unexpectedly has ExternalRecognizerEnabled() = true")
	}
	// runExternalRecognizer 自体を直接呼び、未設定時は候補マップ構築にすら
	// 進まないことを確認する（呼び出しコストがゼロであることの直接的な根拠）。
	got, _ := runExternalRecognizer(cfg, []string{filepath.Join(tmp, "a.txt")}, []string{"no pii here\n"}, []bool{false})
	if got != nil {
		t.Fatalf("runExternalRecognizer() = %v, want nil when disabled", got)
	}
}

func TestScanPathsMergesExternalFindings(t *testing.T) {
	t.Setenv("JP_PII_EXTERNAL_TEST_HELPER", "1")
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "a.txt"), []byte("hello a\n"))
	writeFile(t, filepath.Join(tmp, "b.txt"), []byte("hello b\n"))
	// 5MB 超はそもそも読み取り対象外（テキストが空のまま skip される）なので
	// 外部レコグナイザにも送られないはずだが、ここでは通常ファイルの経路のみ検証する。

	cfg, err := config.Parse(externalHelperConfigTOML("mark-each-file"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings, warnings, err := ScanPaths(d, cfg, []string{tmp})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}

	var extFiles []string
	for _, f := range findings {
		if f.RuleID == "ext-marker-external" {
			extFiles = append(extFiles, filepath.Base(f.File))
			if !f.Reason.External {
				t.Errorf("finding %+v: Reason.External = false, want true", f)
			}
		}
	}
	sort.Strings(extFiles)
	want := []string{"a.txt", "b.txt"}
	if len(extFiles) != len(want) || extFiles[0] != want[0] || extFiles[1] != want[1] {
		t.Fatalf("external findings = %v, want one per file %v", extFiles, want)
	}
}

func TestScanPathsExternalRecognizerDoesNotReceiveSkippedFiles(t *testing.T) {
	t.Setenv("JP_PII_EXTERNAL_TEST_HELPER", "1")
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "a.txt"), []byte("hello a\n"))
	// NUL バイトを含むバイナリは読み取りフェーズで skip され、外部レコグナイザにも
	// 送られないはずである。
	writeFile(t, filepath.Join(tmp, "binary.bin"), []byte{0x00, 0x01, 0x02})

	cfg, err := config.Parse(externalHelperConfigTOML("mark-each-file"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings, _, err := ScanPaths(d, cfg, []string{tmp})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, f := range findings {
		if f.RuleID == "ext-marker-external" {
			count++
			if filepath.Base(f.File) != "a.txt" {
				t.Errorf("unexpected external finding for %q (binary.bin must not reach the external recognizer)", f.File)
			}
		}
	}
	if count != 1 {
		t.Fatalf("external finding count = %d, want 1 (only a.txt should have been sent)", count)
	}
}

// TestScanPathsReportsExternalMaxFindingsExceeded は外部レコグナイザの候補が
// max_findings を超えたとき、超過を黙って捨てずに ScanStats.ExternalTruncated で
// 件数を返すことを確認する（組み込み側が走査を失敗扱いにするための手がかり）。
func TestScanPathsReportsExternalMaxFindingsExceeded(t *testing.T) {
	t.Setenv("JP_PII_EXTERNAL_TEST_HELPER", "1")
	for _, tc := range []struct {
		limit     int
		truncated bool
	}{{2, true}, {3, false}, {10, false}} {
		tmp := t.TempDir()
		writeFile(t, filepath.Join(tmp, "a.txt"), []byte("no pii here\n"))
		cfg, err := config.Parse(externalHelperConfigTOML("mark-three") + "max_findings = " + strconv.Itoa(tc.limit) + "\n")
		if err != nil {
			t.Fatal(err)
		}
		d, err := detect.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		_, _, st, err := ScanPathsWithStats(d, cfg, []string{tmp})
		if err != nil {
			t.Fatal(err)
		}
		if got := st.ExternalTruncated != nil; got != tc.truncated {
			t.Fatalf("limit=%d: ExternalTruncated = %v, want truncated=%v", tc.limit, st.ExternalTruncated, tc.truncated)
		}
		if tc.truncated {
			if !errors.Is(st.ExternalTruncated, external.ErrMaxFindingsExceeded) {
				t.Errorf("limit=%d: errors.Is(ErrMaxFindingsExceeded) = false", tc.limit)
			}
			if st.ExternalTruncated.Limit != 2 || st.ExternalTruncated.Received != 3 {
				t.Errorf("limit=%d: got %+v, want Limit=2 Received=3", tc.limit, *st.ExternalTruncated)
			}
		}
	}
}
