package config

import (
	"os"
	"path/filepath"
	"testing"

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
