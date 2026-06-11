package config

import (
	"os"
	"path/filepath"
	"testing"
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
	if len(cfg.Rules.Disabled) != 1 || cfg.Rules.Disabled[0] != "person-name" {
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

func TestParseInvalidRegex(t *testing.T) {
	if _, err := Parse("[allowlist]\npaths = [\"(\"]\n"); err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.MinConfidence != "medium" {
		t.Errorf("MinConfidence = %q, want medium", cfg.MinConfidence)
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
