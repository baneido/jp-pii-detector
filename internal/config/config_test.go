package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/baneido/jp-pii-detector/internal/rule"
)

func TestParse(t *testing.T) {
	cfg, err := Parse(`
min_confidence = "high"

[rules]
disabled = ["person-name"]

[allowlist]
paths = ["^testdata/", "\\.md$"]
regexes = ["@example\\.com$"]
stopwords = ["090-0000-0000"]
`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinConfidence != "high" {
		t.Errorf("MinConfidence = %q", cfg.MinConfidence)
	}
	if !containsString(cfg.Rules.Disabled, "person-name") {
		t.Errorf("Disabled = %v", cfg.Rules.Disabled)
	}
	if cfg.PathAllowed("testdata/sample.txt") {
		t.Error("testdata/ should be excluded")
	}
	if cfg.PathAllowed("docs/memo.md") {
		t.Error("*.md should be excluded")
	}
	if !cfg.PathAllowed("internal/main.go") {
		t.Error("main.go should be allowed")
	}
	if len(cfg.AllowRegexes()) != 1 {
		t.Errorf("AllowRegexes = %v", cfg.AllowRegexes())
	}
}

func TestPathAllowedSupportsGlobPatterns(t *testing.T) {
	cfg, err := Parse(`
[allowlist]
paths = ["path/to/**/target", "path/to/*.txt"]
`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PathAllowed("path/to/deep/target") {
		t.Error("** should exclude nested target paths")
	}
	if cfg.PathAllowed("path/to/a/b/target") {
		t.Error("** should exclude deeply nested target paths")
	}
	if cfg.PathAllowed("path/to/target") {
		t.Error("** should also exclude paths with no intermediate directory")
	}
	if cfg.PathAllowed("path/to/memo.txt") {
		t.Error("*.txt should exclude direct child txt files")
	}
	if !cfg.PathAllowed("path/to/nested/memo.txt") {
		t.Error("*.txt should not cross directory boundaries")
	}
	if !cfg.PathAllowed("path/to/memo.md") {
		t.Error("unmatched paths should be allowed")
	}
}

func TestPathAllowedKeepsRegexPatterns(t *testing.T) {
	cfg, err := Parse(`
[allowlist]
paths = ["^testdata/", "\\.lock$"]
`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PathAllowed("testdata/sample.txt") {
		t.Error("regex ^testdata/ should still exclude testdata paths")
	}
	if cfg.PathAllowed("go.sum.lock") {
		t.Error("regex \\.lock$ should still exclude lock files")
	}
	if !cfg.PathAllowed("internal/main.go") {
		t.Error("unmatched paths should be allowed")
	}
}

func TestParseHighRecallRulesDisabledByDefault(t *testing.T) {
	cfg, err := Parse("")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range rule.HighRecallRuleIDs() {
		if !containsString(cfg.Rules.Disabled, id) {
			t.Fatalf("Disabled = %v, want high-recall rule %q to be disabled by default", cfg.Rules.Disabled, id)
		}
	}
}

func TestParseHighRecallOptInLeavesRulesEnabled(t *testing.T) {
	cfg, err := Parse(`
[rules]
high_recall = true
`)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range rule.HighRecallRuleIDs() {
		if containsString(cfg.Rules.Disabled, id) {
			t.Fatalf("Disabled = %v, want high-recall rule %q to remain enabled", cfg.Rules.Disabled, id)
		}
	}
}

func TestParseHighRecallOptInStillHonorsExplicitDisable(t *testing.T) {
	ids := rule.HighRecallRuleIDs()
	if len(ids) == 0 {
		t.Fatal("HighRecallRuleIDs must not be empty")
	}
	cfg, err := Parse(`
[rules]
high_recall = true
disabled = ["` + ids[0] + `"]
`)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(cfg.Rules.Disabled, ids[0]) {
		t.Fatalf("Disabled = %v, want explicit disable for %q", cfg.Rules.Disabled, ids[0])
	}
	for _, id := range ids[1:] {
		if containsString(cfg.Rules.Disabled, id) {
			t.Fatalf("Disabled = %v, want unrelated high-recall rule %q to remain enabled", cfg.Rules.Disabled, id)
		}
	}
}

func TestSetHighRecallTogglesAutoDisabledRules(t *testing.T) {
	cfg, err := Parse(`
[rules]
disabled = ["person-name"]
`)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetHighRecall(true)
	if !cfg.Rules.HighRecall {
		t.Fatal("HighRecall = false, want true")
	}
	if !containsString(cfg.Rules.Disabled, "person-name") {
		t.Fatalf("Disabled = %v, want explicit disable to remain", cfg.Rules.Disabled)
	}
	for _, id := range rule.HighRecallRuleIDs() {
		if containsString(cfg.Rules.Disabled, id) {
			t.Fatalf("Disabled = %v, want auto-disabled high-recall rule %q to be re-enabled", cfg.Rules.Disabled, id)
		}
	}

	cfg.SetHighRecall(false)
	for _, id := range rule.HighRecallRuleIDs() {
		if !containsString(cfg.Rules.Disabled, id) {
			t.Fatalf("Disabled = %v, want high-recall rule %q to be disabled again", cfg.Rules.Disabled, id)
		}
	}
}

func TestParseInvalidRegex(t *testing.T) {
	if _, err := Parse("[allowlist]\npaths = [\"(\"]\n"); err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestParseCooccurrenceBoostDefaultsFalse(t *testing.T) {
	cfg, err := Parse("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rules.CooccurrenceBoost {
		t.Error("CooccurrenceBoost = true, want false by default")
	}
}

func TestParseCooccurrenceBoostOptIn(t *testing.T) {
	cfg, err := Parse(`
[rules]
cooccurrence_boost = true
`)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Rules.CooccurrenceBoost {
		t.Error("CooccurrenceBoost = false, want true")
	}
}

func TestParseExcludeKindsDefaultsEmpty(t *testing.T) {
	cfg, err := Parse("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules.ExcludeKinds) != 0 {
		t.Errorf("ExcludeKinds = %v, want empty by default (既定は空で挙動不変)", cfg.Rules.ExcludeKinds)
	}
}

func TestParseExcludeKinds(t *testing.T) {
	cfg, err := Parse(`
[rules]
exclude_kinds = ["service"]
`)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(cfg.Rules.ExcludeKinds, "service") {
		t.Errorf("ExcludeKinds = %v, want it to contain %q", cfg.Rules.ExcludeKinds, "service")
	}
}

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.MinConfidence != "medium" {
		t.Errorf("MinConfidence = %q, want medium", cfg.MinConfidence)
	}
	if cfg.Rules.HighRecall {
		t.Error("HighRecall = true, want false by default")
	}
	if cfg.Rules.CooccurrenceBoost {
		t.Error("CooccurrenceBoost = true, want false by default")
	}
	for _, id := range rule.HighRecallRuleIDs() {
		if !containsString(cfg.Rules.Disabled, id) {
			t.Fatalf("Disabled = %v, want high-recall rule %q disabled by Default()", cfg.Rules.Disabled, id)
		}
	}
	if !cfg.PathAllowed("anything") {
		t.Error("default should allow all paths")
	}
}

func TestLoadMissingFileFallsBackToDefault(t *testing.T) {
	dir := t.TempDir()
	// .git を置いて上方探索をここで打ち切らせる（hermetic にするため）。
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinConfidence != "medium" {
		t.Errorf("MinConfidence = %q", cfg.MinConfidence)
	}
	if _, err := Load("/nonexistent/path.toml"); err == nil {
		t.Error("explicit missing path should error")
	}
}

func TestLoadExplicitPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.toml")
	if err := os.WriteFile(path, []byte(`min_confidence = "low"`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinConfidence != "low" {
		t.Errorf("MinConfidence = %q, want low", cfg.MinConfidence)
	}
}

// サブディレクトリからの実行でもリポジトリルートの設定を見つける。
func TestLoadSearchesUpwardToRepoRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, DefaultFileName), []byte(`min_confidence = "high"`), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "internal", "app")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinConfidence != "high" {
		t.Errorf("MinConfidence = %q, want high（ルートの設定を読むべき）", cfg.MinConfidence)
	}
}

// リポジトリルート（.git のあるディレクトリ）より上の設定は読まない。
func TestLoadStopsAtRepoRoot(t *testing.T) {
	outer := t.TempDir()
	if err := os.WriteFile(filepath.Join(outer, DefaultFileName), []byte(`min_confidence = "low"`), 0o644); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(outer, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinConfidence != "medium" {
		t.Errorf("MinConfidence = %q, want medium（リポジトリ外の設定を読んではならない）", cfg.MinConfidence)
	}
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// --- [[rules.custom]] ---

func TestParseCustomRule(t *testing.T) {
	cfg, err := Parse(`
[[rules.custom]]
id = "student-id"
description = "学籍番号"
pattern = 'S\d{8}'
context = ["学籍番号", "student_id"]
negative_context = ["サンプル"]
require_context = true
require_context_window = 20
base_confidence = "high"
digit_boundary = true
`)
	if err != nil {
		t.Fatal(err)
	}
	rules := cfg.CustomRules()
	if len(rules) != 1 {
		t.Fatalf("CustomRules() = %v, want 1 rule", rules)
	}
	r := rules[0]
	if r.ID != "student-id" || r.Description != "学籍番号" {
		t.Errorf("rule = %+v", r)
	}
	if r.RequireContextWindow != 20 {
		t.Errorf("RequireContextWindow = %d, want 20", r.RequireContextWindow)
	}
	if len(r.Patterns) != 1 {
		t.Fatalf("Patterns = %v, want 1", r.Patterns)
	}
	p := r.Patterns[0]
	if p.Base != rule.High {
		t.Errorf("Base = %v, want High", p.Base)
	}
	if !p.RequireContext {
		t.Error("RequireContext = false, want true")
	}
	m := p.Re.FindStringSubmatch("学籍番号: S12345678 です")
	if m == nil || m[1] != "S12345678" {
		t.Fatalf("match = %v, want group 1 = S12345678", m)
	}
	// digit_boundary により、より長い数字列の一部としては一致しない。
	if p.Re.MatchString("S123456789") {
		t.Error("digit_boundary should reject a longer digit run as a partial match")
	}
}

func TestParseCustomRuleDefaultsToMediumConfidence(t *testing.T) {
	cfg, err := Parse(`
[[rules.custom]]
id = "student-id"
pattern = 'S\d{8}'
`)
	if err != nil {
		t.Fatal(err)
	}
	rules := cfg.CustomRules()
	if len(rules) != 1 || rules[0].Patterns[0].Base != rule.Medium {
		t.Fatalf("CustomRules() = %v, want 1 rule with Base=Medium", rules)
	}
}

func TestParseCustomRuleWithoutDigitBoundaryUsesRawPattern(t *testing.T) {
	cfg, err := Parse(`
[[rules.custom]]
id = "custom-token"
pattern = 'TOKEN-[A-Z0-9]{8}'
`)
	if err != nil {
		t.Fatal(err)
	}
	re := cfg.CustomRules()[0].Patterns[0].Re
	m := re.FindStringSubmatch("key=TOKEN-AB12CD34;")
	if m == nil || m[0] != "TOKEN-AB12CD34" {
		t.Fatalf("match = %v, want whole match TOKEN-AB12CD34", m)
	}
}

func TestParseCustomRuleInvalidRegexIsConfigError(t *testing.T) {
	_, err := Parse(`
[[rules.custom]]
id = "bad"
pattern = "("
`)
	if err == nil {
		t.Fatal("expected error for uncompilable custom rule pattern")
	}
	if !strings.Contains(err.Error(), "bad") {
		t.Errorf("error = %v, want it to mention the rule id", err)
	}
}

func TestParseCustomRuleInvalidBaseConfidence(t *testing.T) {
	_, err := Parse(`
[[rules.custom]]
id = "bad"
pattern = "x"
base_confidence = "urgent"
`)
	if err == nil {
		t.Fatal("expected error for invalid base_confidence")
	}
}

func TestParseCustomRuleMissingID(t *testing.T) {
	_, err := Parse(`
[[rules.custom]]
pattern = "x"
`)
	if err == nil {
		t.Fatal("expected error for missing id")
	}
}

func TestParseCustomRuleMissingPattern(t *testing.T) {
	_, err := Parse(`
[[rules.custom]]
id = "bad"
`)
	if err == nil {
		t.Fatal("expected error for missing pattern")
	}
}

func TestParseCustomRuleDuplicateIDRejected(t *testing.T) {
	_, err := Parse(`
[[rules.custom]]
id = "dup"
pattern = "x"

[[rules.custom]]
id = "dup"
pattern = "y"
`)
	if err == nil {
		t.Fatal("expected error for duplicate custom rule id")
	}
}

func TestParseCustomRuleCollidesWithBuiltinIDRejected(t *testing.T) {
	_, err := Parse(`
[[rules.custom]]
id = "credit-card"
pattern = "x"
`)
	if err == nil {
		t.Fatal("expected error when custom rule id collides with a built-in rule id")
	}
}

// --- 未知の設定キー ---

func TestParseUnknownKeyWarns(t *testing.T) {
	cfg, err := Parse(`
min_confidence = "high"
unknown_top_level = true

[rules]
disabled = ["person-name"]
typo_key = "x"
`)
	if err != nil {
		t.Fatal(err)
	}
	warnings := cfg.Warnings()
	if len(warnings) == 0 {
		t.Fatal("Warnings() is empty, want a warning for unknown keys")
	}
	joined := strings.Join(warnings, " ")
	for _, want := range []string{"unknown_top_level", "typo_key"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Warnings() = %v, want it to mention %q", warnings, want)
		}
	}
}

func TestParseKnownConfigProducesNoWarnings(t *testing.T) {
	cfg, err := Parse(`
min_confidence = "high"

[rules]
disabled = ["person-name"]
high_recall = true

[[rules.custom]]
id = "student-id"
description = "学籍番号"
pattern = 'S\d{8}'
context = ["student"]
negative_context = ["sample"]
require_context = true
require_context_window = 20
base_confidence = "high"
digit_boundary = true

[allowlist]
paths = ["^testdata/"]
regexes = ["@example\\.com$"]
stopwords = ["090-0000-0000"]
`)
	if err != nil {
		t.Fatal(err)
	}
	if warnings := cfg.Warnings(); len(warnings) != 0 {
		t.Errorf("Warnings() = %v, want none for a fully-known config", warnings)
	}
}

// リポジトリ自身の .jp-pii.toml が、新規キーを使っていなくても
// 警告なしでパースできることを確認する（既存設定の後方互換性）。
func TestRepoOwnConfigParsesWithoutWarnings(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", DefaultFileName))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(string(data))
	if err != nil {
		t.Fatal(err)
	}
	if warnings := cfg.Warnings(); len(warnings) != 0 {
		t.Errorf("Warnings() = %v, want none for the repo's own %s", warnings, DefaultFileName)
	}
	if len(cfg.CustomRules()) != 0 {
		t.Errorf("CustomRules() = %v, want none (repo config defines no custom rules)", cfg.CustomRules())
	}
	// external_recognizer は任意コマンド実行機能のため、リポジトリ自身の
	// .jp-pii.toml には意図的に追加しない（設計メモ参照）。既定の未設定状態を
	// ここで確認しておく。
	if cfg.ExternalRecognizerEnabled() {
		t.Error("ExternalRecognizerEnabled() = true, want false for the repo's own config (must not be enabled by default)")
	}
}

func TestParseExternalRecognizerDefaultsDisabled(t *testing.T) {
	cfg, err := Parse("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ExternalRecognizerEnabled() {
		t.Error("ExternalRecognizerEnabled() = true, want false when [external_recognizer] is absent")
	}
	if cfg.ExternalRecognizerConfig().Enabled() {
		t.Error("ExternalRecognizerConfig().Enabled() = true, want false when [external_recognizer] is absent")
	}
}

func TestParseExternalRecognizerEnabled(t *testing.T) {
	cfg, err := Parse(`
[external_recognizer]
command = ["python3", "my_ner.py"]
timeout_seconds = 5
max_findings = 50
`)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ExternalRecognizerEnabled() {
		t.Fatal("ExternalRecognizerEnabled() = false, want true")
	}
	want := []string{"python3", "my_ner.py"}
	if got := cfg.ExternalRecognizer.Command; !slices.Equal(got, want) {
		t.Errorf("ExternalRecognizer.Command = %v, want %v", got, want)
	}
	ec := cfg.ExternalRecognizerConfig()
	if !ec.Enabled() {
		t.Fatal("ExternalRecognizerConfig().Enabled() = false, want true")
	}
	if !slices.Equal(ec.Command, want) {
		t.Errorf("ExternalRecognizerConfig().Command = %v, want %v", ec.Command, want)
	}
	if ec.Timeout != 5*time.Second {
		t.Errorf("ExternalRecognizerConfig().Timeout = %v, want 5s", ec.Timeout)
	}
	if ec.MaxFindings != 50 {
		t.Errorf("ExternalRecognizerConfig().MaxFindings = %d, want 50", ec.MaxFindings)
	}
}

func TestParseExternalRecognizerUnsetTimeoutAndMaxFindingsPassThroughAsZero(t *testing.T) {
	// timeout_seconds・max_findings 未指定時は 0 のまま internal/external.Config へ
	// 渡し、既定値へのフォールバックは external.Run 側の責務にする（config 側で
	// 二重にデフォルト値を持たない）。
	cfg, err := Parse(`
[external_recognizer]
command = ["my-recognizer"]
`)
	if err != nil {
		t.Fatal(err)
	}
	ec := cfg.ExternalRecognizerConfig()
	if ec.Timeout != 0 {
		t.Errorf("Timeout = %v, want 0 (fallback happens in internal/external, not here)", ec.Timeout)
	}
	if ec.MaxFindings != 0 {
		t.Errorf("MaxFindings = %d, want 0 (fallback happens in internal/external, not here)", ec.MaxFindings)
	}
}

func TestParseExternalRecognizerEmptyCommandFirstElementIsConfigError(t *testing.T) {
	_, err := Parse(`
[external_recognizer]
command = [""]
`)
	if err == nil {
		t.Fatal("Parse() succeeded, want an error for an empty command[0]")
	}
}

func TestParseExternalRecognizerUnknownSubkeyWarns(t *testing.T) {
	cfg, err := Parse(`
[external_recognizer]
command = ["my-recognizer"]
typo_key = "x"
`)
	if err != nil {
		t.Fatal(err)
	}
	warnings := cfg.Warnings()
	if len(warnings) == 0 {
		t.Fatal("Warnings() is empty, want a warning for the unknown external_recognizer.typo_key")
	}
	if joined := strings.Join(warnings, " "); !strings.Contains(joined, "typo_key") {
		t.Errorf("Warnings() = %v, want it to mention %q", warnings, "typo_key")
	}
}
