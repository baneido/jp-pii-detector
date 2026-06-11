package config

import "testing"

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
