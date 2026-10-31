package jppii_test

// 後方互換のテスト。項目を足す前（e8d576c）の公開 API だけを、当時と同じ書き方で
// 使う。このファイルがコンパイルでき、結果が testdata/compat_golden.json と一致すれば、
// 既存の呼び出し側のコードは同じように動く。golden は項目を足す前のコードで作った。
//
// 入力は下の compatFixture（架空の値だけ）に固定している。検出ロジックを直して
// このテストの結果が変わった場合は、変わった内容が意図どおりかを確かめてから
// JPPII_UPDATE_COMPAT_GOLDEN=1 を付けて実行し、golden を作り直す。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/baneido/jp-pii-detector/pkg/jppii"
)

const compatGolden = "testdata/compat_golden.json"

// compatFixture は架空の値だけで作った入力。マーカーの行と JSON のエスケープの行も含める。
var compatFixture = []struct{ name, text string }{
	{"contact.txt", "担当者: 見本 花子\n電話番号: 090-0000-0000\nメール: hanako@example.jp\n〒100-0000 東京都千代田区架空町1-2-3\n"},
	{"form.md", "| 氏名 | 見本 太郎 |\n| 生年月日 | 1990年1月1日 |\n| TEL | 03-0000-0000 |\n"},
	{"ignored.txt", "電話番号: 090-0000-0000 jp-pii-detector:ignore\nメール: taro@example.jp\n"},
	{"escaped.json", `{"name": "\u898b\u672c \u82b1\u5b50", "tel": "090-0000-0000"}` + "\n"},
	{"bom.csv", "\uFEFF氏名,電話番号\n見本 花子,090-0000-0000\n"},
}

// compatFinding は既存の項目だけを記録する。生値は保存せず、ハッシュにする。
type compatFinding struct {
	Case        string `json:"case"`
	Profile     string `json:"profile"`
	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
	File        string `json:"file"`
	RepoPath    string `json:"repo_path"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	MatchHash   string `json:"match_hash"`
	MaskedHash  string `json:"masked_hash"`
	Fingerprint string `json:"fingerprint"`
	Confidence  string `json:"confidence"`
	Reportable  bool   `json:"reportable"`
}

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

func compatRun(t *testing.T) []compatFinding {
	t.Helper()
	empty := ""
	profiles := []struct {
		name string
		opts jppii.Options
	}{
		{"default", jppii.Options{ConfigTOML: &empty}},
		{"low", jppii.Options{ConfigTOML: &empty, MinConfidence: "low"}},
		{"high-recall", jppii.Options{ConfigTOML: &empty, MinConfidence: "low", HighRecall: true, NameRoster: true}},
	}
	var out []compatFinding
	for _, p := range profiles {
		s, err := jppii.NewScanner(p.opts)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range compatFixture {
			var res jppii.Result = s.ScanText(c.name, c.text)
			if len(res.Warnings) != 0 {
				t.Fatalf("%s: warnings %v", c.name, res.Warnings)
			}
			for _, f := range res.Findings {
				out = append(out, compatFinding{
					Case: c.name, Profile: p.name, RuleID: f.RuleID, Description: f.Description,
					File: f.File, RepoPath: f.RepoPath, Line: f.Line, Column: f.Column,
					MatchHash: hash(f.Match), MaskedHash: hash(f.Masked()),
					Fingerprint: f.Fingerprint("compat-salt"), Confidence: f.Confidence,
					Reportable: s.IsReportable(f.Confidence),
				})
			}
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// compatDigest はプロファイルごとの件数と、全項目を並べた JSON の SHA-256。
// 全件を保存すると大きいので、要約だけを golden にする。
type compatDigest struct {
	Findings int    `json:"findings"`
	SHA256   string `json:"sha256"`
}

func digest(fs []compatFinding) map[string]compatDigest {
	by := map[string][]compatFinding{}
	for _, f := range fs {
		by[f.Profile] = append(by[f.Profile], f)
	}
	out := map[string]compatDigest{}
	for p, list := range by {
		data, _ := json.Marshal(list)
		h := sha256.Sum256(data)
		out[p] = compatDigest{Findings: len(list), SHA256: hex.EncodeToString(h[:])}
	}
	return out
}

func TestCompatGoldenUnchanged(t *testing.T) {
	got := digest(compatRun(t))
	if os.Getenv("JPPII_UPDATE_COMPAT_GOLDEN") == "1" {
		data, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(compatGolden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(compatGolden, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(compatGolden)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]compatDigest
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("existing fields changed:\n got  %+v\n want %+v", got, want)
	}
}

// 項目を足す前の API を、当時の書き方（名前付きの項目、関数の型）で使う。
// 型や関数の形が変わるとコンパイルできなくなる。
func TestCompatOldAPISurface(t *testing.T) {
	var (
		_ func(jppii.Options) (*jppii.Scanner, error)          = jppii.NewScanner
		_ func(string) string                                  = jppii.Mask
		_ func(string, string, string, string) string          = jppii.Fingerprint
		_ func() (string, error)                               = jppii.NewSalt
		_ func() string                                        = jppii.RepoRoot
		_ func() func(string) string                           = jppii.RepoRelativeFunc
		_ func(string) ([]string, error)                       = jppii.ValidateConfig
		_ func(bool, string) ([]jppii.AddedLine, error)        = jppii.AddedLines
		_ func([]string, *jppii.Hooks) int                     = jppii.RunScan
		_ func([]string) int                                   = jppii.RunRules
		_ func(string)                                         = jppii.SetBundledModelDir
		_ func(string, jppii.RawFinding) string                = jppii.RawFingerprint
		_ func(*jppii.Scanner) error                           = (*jppii.Scanner).Close
		_ func(*jppii.Scanner) []string                        = (*jppii.Scanner).ConfigWarnings
		_ func(*jppii.Scanner) string                          = (*jppii.Scanner).MinConfidence
		_ func(*jppii.Scanner, []string) (jppii.Result, error) = (*jppii.Scanner).ScanPaths
		_ func(*jppii.Scanner) (jppii.Result, error)           = (*jppii.Scanner).ScanStaged
		_ func(*jppii.Scanner, string) (jppii.Result, error)   = (*jppii.Scanner).ScanDiff
		_ func(*jppii.Scanner, string, string) jppii.Result    = (*jppii.Scanner).ScanText
		_ func(*jppii.Scanner) []jppii.RuleInfo                = (*jppii.Scanner).Rules
		_ func(*jppii.Scanner, string) bool                    = (*jppii.Scanner).IsReportable
		_ func(*jppii.Scanner, string) bool                    = (*jppii.Scanner).PathAllowed
		_ func(*jppii.Scanner, string) bool                    = (*jppii.Scanner).ValueAllowed
		_ func(*jppii.Scanner) bool                            = (*jppii.Scanner).RespectGitignore
		_ func(jppii.Finding) string                           = jppii.Finding.Masked
		_ func(jppii.Finding, string) string                   = jppii.Finding.Fingerprint
		_ jppii.ConfidenceLevel                                = jppii.ConfidenceHigh
	)
	empty := ""
	_ = jppii.Options{ConfigPath: "", ConfigTOML: &empty, MinConfidence: "", FailOn: "", HighRecall: false,
		NameRoster: false, NoGitignore: false, ModelDir: "", ModelFull: false}
	_ = jppii.Finding{RuleID: "", Description: "", File: "", RepoPath: "", Line: 0, Column: 0, Match: "", Confidence: ""}
	_ = jppii.Stats{FilesDiscovered: 0, FilesScanned: 0, SkippedFiles: 0, ExcludedPaths: 0}
	_ = jppii.Result{Findings: nil, Warnings: nil, Stats: jppii.Stats{}}
	_ = jppii.RuleInfo{ID: "", Description: "", Enabled: false, HighRecall: false}
	_ = jppii.ConfigFileName + jppii.Usage
	_ = []jppii.ConfidenceLevel{jppii.ConfidenceLow, jppii.ConfidenceMedium}
	// 以前の型は == で比べられ、map のキーにできた。項目を足してもそのままであること。
	_ = map[jppii.Finding]bool{}
	_ = map[jppii.Options]bool{}
	_ = map[jppii.Stats]bool{}
	_ = map[jppii.RuleInfo]bool{}
	var _ jppii.Hooks
	var _ jppii.ScanInfo
	var _ jppii.Renderer
	var _ jppii.RuleDef
}
