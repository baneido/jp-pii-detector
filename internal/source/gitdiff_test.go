package source

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/baneido/jp-pii-detecter/internal/config"
	"github.com/baneido/jp-pii-detecter/internal/detect"
)

func TestParseDiff(t *testing.T) {
	diff := `diff --git a/users.csv b/users.csv
index 1111111..2222222 100644
--- a/users.csv
+++ b/users.csv
@@ -3,0 +4,2 @@ header
+TEL: 090-1234-5678
+name,age
diff --git a/old.txt b/old.txt
deleted file mode 100644
--- a/old.txt
+++ /dev/null
@@ -1 +0,0 @@
-removed line
diff --git a/docs/memo.md b/docs/memo.md
--- a/docs/memo.md
+++ b/docs/memo.md
@@ -9,0 +10 @@
+〒150-0043
`
	got := ParseDiff(diff)
	want := []AddedLine{
		{File: "users.csv", Line: 4, Text: "TEL: 090-1234-5678"},
		{File: "users.csv", Line: 5, Text: "name,age"},
		{File: "docs/memo.md", Line: 10, Text: "〒150-0043"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseDiff = %+v, want %+v", got, want)
	}
}

func TestParseDiffBinaryAndEmpty(t *testing.T) {
	if got := ParseDiff("Binary files a/img.png and b/img.png differ\n"); len(got) != 0 {
		t.Errorf("ParseDiff(binary) = %+v, want empty", got)
	}
	if got := ParseDiff(""); len(got) != 0 {
		t.Errorf("ParseDiff(empty) = %+v, want empty", got)
	}
}

// core.quotePath=false で出力される非 ASCII ファイル名をそのまま扱える。
func TestParseDiffJapaneseFilename(t *testing.T) {
	diff := `diff --git a/顧客リスト.csv b/顧客リスト.csv
--- a/顧客リスト.csv
+++ b/顧客リスト.csv
@@ -0,0 +1 @@
+TEL: 090-1234-5678
`
	got := ParseDiff(diff)
	want := []AddedLine{{File: "顧客リスト.csv", Line: 1, Text: "TEL: 090-1234-5678"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseDiff = %+v, want %+v", got, want)
	}
}

// initTestRepo は一時ディレクトリに git リポジトリを作り、そこへ chdir する。
func initTestRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	repo := t.TempDir()
	t.Chdir(repo)
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "test"},
		{"config", "commit.gpgsign", "false"},
	} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return repo
}

func git(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// ScanStaged が日本語ファイル名でも正しいパスで検出を報告できること
// （core.quotePath 既定値では 8 進エスケープされ壊れていた）。
func TestScanStagedJapaneseFilename(t *testing.T) {
	repo := initTestRepo(t)
	name := "顧客リスト.csv"
	if err := os.WriteFile(filepath.Join(repo, name), []byte("氏名,電話\n山田,090-1234-5678\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", name)

	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := ScanStaged(d, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 1 件", findings)
	}
	if f := findings[0]; f.File != name || f.RuleID != "jp-phone-number" || f.Line != 2 {
		t.Errorf("finding = %+v, want file=%q line=2", f, name)
	}
}

// ScanDiff がコミット間の追加行のみを走査すること。
func TestScanDiffRange(t *testing.T) {
	repo := initTestRepo(t)
	path := filepath.Join(repo, "memo.txt")
	if err := os.WriteFile(path, []byte("既存の電話: 090-1111-2222\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", ".")
	git(t, "commit", "-q", "-m", "base")
	if err := os.WriteFile(path, []byte("既存の電話: 090-1111-2222\n追加の電話: 090-3333-4444\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", ".")
	git(t, "commit", "-q", "-m", "add")

	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := ScanDiff(d, cfg, "HEAD~1...HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 追加行の 1 件のみ", findings)
	}
	if f := findings[0]; f.File != "memo.txt" || f.Line != 2 {
		t.Errorf("finding = %+v, want memo.txt:2", f)
	}
}

func TestScanDiffInvalidRange(t *testing.T) {
	initTestRepo(t)
	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ScanDiff(d, cfg, "no-such-ref...HEAD"); err == nil {
		t.Error("expected error for invalid range")
	}
}
