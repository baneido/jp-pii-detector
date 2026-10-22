package source

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/config"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func listedSlash(t *testing.T, cfg *config.Config, root string) ([]string, ScanStats) {
	t.Helper()
	files, warnings, stats, err := listFiles(cfg, []string{root})
	if err != nil || len(warnings) > 0 {
		t.Fatalf("listFiles: err=%v warnings=%v", err, warnings)
	}
	var out []string
	for _, f := range files {
		rel, err := filepath.Rel(root, f)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, filepath.ToSlash(rel))
	}
	slices.Sort(out)
	return out, stats
}

// git 管理下では git の判定（未追跡かつ無視対象だけを除外、追跡済みは対象）に従う。
func TestListFilesRespectsGitignoreInRepo(t *testing.T) {
	repo := initTestRepo(t)
	writeTree(t, repo, map[string]string{
		".gitignore":        "*.log\ntmp/\n!keep.log\n",
		"main.go":           "package main\n",
		"debug.log":         "x\n",
		"keep.log":          "x\n",
		"tracked.log":       "x\n",
		"tmp/cache.txt":     "x\n",
		"sub/.gitignore":    "local.txt\n",
		"sub/local.txt":     "x\n",
		"sub/other.txt":     "x\n",
		"sub/deep/app.log":  "x\n",
		"sub/deep/note.txt": "x\n",
	})
	git(t, "add", "-f", "tracked.log")
	git(t, "add", ".gitignore", "main.go", "sub/.gitignore", "sub/other.txt")
	git(t, "commit", "-q", "-m", "init")

	cfg := config.Default()
	got, stats := listedSlash(t, cfg, ".")
	want := []string{".gitignore", "keep.log", "main.go", "sub/.gitignore", "sub/deep/note.txt", "sub/other.txt", "tracked.log"}
	if !slices.Equal(got, want) {
		t.Errorf("files = %v, want %v", got, want)
	}
	if stats.ExcludedGitignored != 4 { // debug.log, tmp/, sub/local.txt, sub/deep/app.log
		t.Errorf("ExcludedGitignored = %d, want 4", stats.ExcludedGitignored)
	}

	cfg.SetRespectGitignore(false)
	got, stats = listedSlash(t, cfg, ".")
	if len(got) != 11 || stats.ExcludedGitignored != 0 {
		t.Errorf("respect_gitignore=false: files = %v (excluded %d), want all 11", got, stats.ExcludedGitignored)
	}
}

// 走査ルートとして明示指定したファイル・ディレクトリは .gitignore にマッチしても走査する。
func TestListFilesExplicitIgnoredRoot(t *testing.T) {
	repo := initTestRepo(t)
	writeTree(t, repo, map[string]string{
		".gitignore":    "*.log\ntmp/\n",
		"debug.log":     "x\n",
		"tmp/cache.txt": "x\n",
	})
	cfg := config.Default()
	for _, root := range []string{"debug.log", "tmp"} {
		files, _, _, err := listFiles(cfg, []string{root})
		if err != nil || len(files) != 1 {
			t.Errorf("listFiles(%q) = %v, %v; want the explicit root to be scanned", root, files, err)
		}
	}
}

// git 管理外では .gitignore を簡易実装で解釈する。
func TestListFilesRespectsGitignoreOutsideGit(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	writeTree(t, root, map[string]string{
		".gitignore":         "# comment\n*.log\n!keep.log\n/out\ncache/\ndocs/**/*.bak\n",
		"a.txt":              "x\n",
		"x.log":              "x\n",
		"keep.log":           "x\n",
		"out/r.txt":          "x\n",
		"sub/out/r.txt":      "x\n",
		"sub/cache/c.txt":    "x\n",
		"sub/cache.txt":      "x\n",
		"docs/a/b/c.bak":     "x\n",
		"docs/c.bak":         "x\n",
		"sub/.gitignore":     "!x2.log\nlocal.txt\n",
		"sub/x2.log":         "x\n",
		"sub/local.txt":      "x\n",
		"sub/nested/y.log":   "x\n",
		"sub/nested/ok.text": "x\n",
	})
	got, _ := listedSlash(t, config.Default(), ".")
	want := []string{".gitignore", "a.txt", "keep.log", "sub/.gitignore", "sub/cache.txt", "sub/nested/ok.text", "sub/out/r.txt", "sub/x2.log"}
	if !slices.Equal(got, want) {
		t.Errorf("files = %v, want %v", got, want)
	}
}

func TestParseGitignoreLine(t *testing.T) {
	cases := []struct {
		line, path string
		want       bool
	}{
		{"*.log", "a.log", true},
		{"*.log", "d/a.log", true},
		{"/build", "build", true},
		{"/build", "d/build", false},
		{"a/b", "a/b", true},
		{"a/b", "x/a/b", false},
		{"**/foo", "x/y/foo", true},
		{"foo/**", "foo/x/y", true},
		{"a/**/b", "a/b", true},
		{"a/**/b", "a/x/y/b", true},
		{"file[0-9].txt", "file3.txt", true},
		{"file[!0-9].txt", "file3.txt", false},
		{"?.md", "a.md", true},
		{"?.md", "ab.md", false},
		{`\#hash`, "#hash", true},
	}
	for _, c := range cases {
		p, ok := parseGitignoreLine(c.line)
		if !ok {
			t.Fatalf("parse %q failed", c.line)
		}
		if got := p.re.MatchString(c.path); got != c.want {
			t.Errorf("%q vs %q = %v, want %v", c.line, c.path, got, c.want)
		}
	}
	for _, line := range []string{"", "# c", "   ", "/"} {
		if _, ok := parseGitignoreLine(line); ok {
			t.Errorf("parse %q should be skipped", line)
		}
	}
}
