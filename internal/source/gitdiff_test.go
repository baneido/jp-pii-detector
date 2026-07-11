package source

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/testfixtures"
)

func TestParseDiff(t *testing.T) {
	phone := testfixtures.MustGet(t, "source.phone_mobile_sep")
	diff := `diff --git a/users.csv b/users.csv
index 1111111..2222222 100644
--- a/users.csv
+++ b/users.csv
@@ -3,0 +4,2 @@ header
+TEL: ` + phone + `
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
		{File: "users.csv", Line: 4, Text: "TEL: " + phone},
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
	phone := testfixtures.MustGet(t, "source.phone_mobile_sep")
	diff := `diff --git a/顧客リスト.csv b/顧客リスト.csv
--- a/顧客リスト.csv
+++ b/顧客リスト.csv
@@ -0,0 +1 @@
+TEL: ` + phone + `
`
	got := ParseDiff(diff)
	want := []AddedLine{{File: "顧客リスト.csv", Line: 1, Text: "TEL: " + phone}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseDiff = %+v, want %+v", got, want)
	}
}

// 引用符付きで出力されるパス（引用符・制御文字を含むファイル名は
// core.quotePath=false でも引用される）から b/ 接頭辞が取り除かれること。
// 旧実装は b/ の除去を引用符の除去より先に行っていたため接頭辞が残った。
// なおエスケープシーケンス（\t 等）の復元までは行わない。
func TestParseDiffQuotedFilename(t *testing.T) {
	phone := testfixtures.MustGet(t, "source.phone_mobile_sep")
	diff := "diff --git \"a/tab\\tname.csv\" \"b/tab\\tname.csv\"\n" +
		"--- \"a/tab\\tname.csv\"\n" +
		"+++ \"b/tab\\tname.csv\"\n" +
		"@@ -0,0 +1 @@\n" +
		"+TEL: " + phone + "\n"
	got := ParseDiff(diff)
	want := []AddedLine{{File: `tab\tname.csv`, Line: 1, Text: "TEL: " + phone}}
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
	content := []byte("氏名,電話\n山田," + testfixtures.MustGet(t, "source.phone_mobile_sep") + "\n")
	if err := os.WriteFile(filepath.Join(repo, name), content, 0o644); err != nil {
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

func TestScanStagedSplitLabelAndValue(t *testing.T) {
	repo := initTestRepo(t)
	name := "pii.txt"
	if err := os.WriteFile(filepath.Join(repo, name), []byte("口座番号:\n1234567\n"), 0o644); err != nil {
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
		t.Fatalf("findings = %+v, want split label/value finding", findings)
	}
	if f := findings[0]; f.File != name || f.RuleID != "jp-bank-account" || f.Line != 2 || f.Column != 1 {
		t.Errorf("finding = %+v, want %s:2:1 jp-bank-account", f, name)
	}
}

// ラベルが既存（未変更）行にあり、値だけを追加したケースを検出できること。
// 旧 -U0 実装では文脈行が走査対象に入らず、コンテキスト必須ルール
// （jp-bank-account）が発火しなかった。
func TestScanDiffContextLabelOnUnchangedLine(t *testing.T) {
	repo := initTestRepo(t)
	name := "pii.txt"
	// base: ラベル行のみをコミット。
	if err := os.WriteFile(filepath.Join(repo, name), []byte("口座番号:\nメモ\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", ".")
	git(t, "commit", "-q", "-m", "base")
	// 値だけをラベルの直後（既存ラベル行は未変更）に追加する。
	if err := os.WriteFile(filepath.Join(repo, name), []byte("口座番号:\n1234567\nメモ\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", ".")

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
		t.Fatalf("findings = %+v, want 1 件（ラベルは未変更行・値は追加行）", findings)
	}
	if f := findings[0]; f.File != name || f.RuleID != "jp-bank-account" || f.Line != 2 {
		t.Errorf("finding = %+v, want %s:2 jp-bank-account", f, name)
	}
}

// 文脈行（未変更行）に既存 PII があり、追加行には PII がない場合は報告しない。
// 文脈行は近傍コンテキストの補完にだけ使い、既存 PII は新規追加ではないため。
func TestScanDiffDoesNotReportContextLinePII(t *testing.T) {
	repo := initTestRepo(t)
	name := "pii.txt"
	// base: ラベルと値（既存 PII）をコミット。
	if err := os.WriteFile(filepath.Join(repo, name), []byte("口座番号: 1234567\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", ".")
	git(t, "commit", "-q", "-m", "base")
	// 既存 PII 行の直後に PII でない行を追加する。
	if err := os.WriteFile(filepath.Join(repo, name), []byte("口座番号: 1234567\n備考なし\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", ".")

	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := ScanStaged(d, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want 0 件（既存 PII は文脈行・追加行に PII なし）", findings)
	}
}

// 内容が "++" で始まる追加行（diff 上は "+++ " と出力される）を、diff ヘッダと
// 誤認せず追加行として扱い、後続の追加行 PII を取りこぼさないこと（回帰: #1）。
func TestScanStagedPlusPlusAddedLine(t *testing.T) {
	repo := initTestRepo(t)
	name := "pii.txt"
	// 1 行目の内容が "++ ..." なので diff では "+++ ..." と出力される。
	content := []byte("++ サンプル差分マーカー\n口座番号: 1234567\n")
	if err := os.WriteFile(filepath.Join(repo, name), content, 0o644); err != nil {
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
		t.Fatalf("findings = %+v, want 1 件（++ 始まりの追加行で後続が脱落しない）", findings)
	}
	if f := findings[0]; f.File != name || f.RuleID != "jp-bank-account" || f.Line != 2 {
		t.Errorf("finding = %+v, want %s:2 jp-bank-account", f, name)
	}
}

// 文脈行（未変更行）の負コンテキスト単位（円 等）が、隣の追加行 PII を抑制
// しないこと（回帰: #2）。文脈行はラベル等の正のコンテキスト補完にのみ使う。
func TestScanStagedContextNegativeDoesNotSuppress(t *testing.T) {
	repo := initTestRepo(t)
	name := "pii.txt"
	if err := os.WriteFile(filepath.Join(repo, name), []byte("口座番号:\n円\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", ".")
	git(t, "commit", "-q", "-m", "base")
	// ラベル（文脈）と 円（文脈）の間に値を追加する。
	if err := os.WriteFile(filepath.Join(repo, name), []byte("口座番号:\n1234567\n円\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", ".")

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
		t.Fatalf("findings = %+v, want 1 件（文脈行の円で抑制しない）", findings)
	}
	if f := findings[0]; f.RuleID != "jp-bank-account" || f.Line != 2 {
		t.Errorf("finding = %+v, want pii.txt:2 jp-bank-account", f)
	}
}

// 文脈行（未変更行）に残った古い ignore マーカーが、隣の追加行 PII を抑制
// しないこと（回帰: #3）。一方、値そのものの追加行にマーカーがあれば抑制する。
func TestScanStagedContextIgnoreMarkerScope(t *testing.T) {
	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("文脈行のマーカーでは抑制しない", func(t *testing.T) {
		repo := initTestRepo(t)
		name := "pii.txt"
		if err := os.WriteFile(filepath.Join(repo, name), []byte("口座番号: jp-pii-detector:ignore\nメモ\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		git(t, "add", ".")
		git(t, "commit", "-q", "-m", "base")
		if err := os.WriteFile(filepath.Join(repo, name), []byte("口座番号: jp-pii-detector:ignore\n7654321\nメモ\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		git(t, "add", ".")
		findings, err := ScanStaged(d, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 1 || findings[0].Line != 2 {
			t.Fatalf("findings = %+v, want pii.txt:2 の 1 件（文脈行マーカーは無効）", findings)
		}
	})

	t.Run("値そのものの追加行のマーカーは抑制する", func(t *testing.T) {
		repo := initTestRepo(t)
		name := "pii.txt"
		if err := os.WriteFile(filepath.Join(repo, name), []byte("口座番号:\nメモ\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		git(t, "add", ".")
		git(t, "commit", "-q", "-m", "base")
		if err := os.WriteFile(filepath.Join(repo, name), []byte("口座番号:\n7654321 jp-pii-detector:ignore\nメモ\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		git(t, "add", ".")
		findings, err := ScanStaged(d, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 0 {
			t.Fatalf("findings = %+v, want 0 件（値の行のマーカーで抑制）", findings)
		}
	})
}

// ScanDiff がコミット間の追加行のみを走査すること。
func TestScanDiffRange(t *testing.T) {
	repo := initTestRepo(t)
	base := "既存の電話: " + testfixtures.MustGet(t, "source.phone_mobile_nosep")
	added := "追加の電話: " + testfixtures.MustGet(t, "source.phone_mobile_sep")
	path := filepath.Join(repo, "memo.txt")
	if err := os.WriteFile(path, []byte(base+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", ".")
	git(t, "commit", "-q", "-m", "base")
	if err := os.WriteFile(path, []byte(base+"\n"+added+"\n"), 0o644); err != nil {
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

// diff.mnemonicPrefix=true（ユーザー/CI の gitconfig でよく使われる設定）が
// 立っていると、旧実装は "+++ i/path" と出力され TrimPrefix(file, "b/") が
// 効かず、報告パスに "i/" が残って allowlist.paths（^testdata/ 等）が
// マッチしなくなっていた。--src-prefix=a/ --dst-prefix=b/ を明示することで
// gitconfig に関わらず接頭辞を固定する。
func TestScanStagedMnemonicPrefixIgnored(t *testing.T) {
	repo := initTestRepo(t)
	git(t, "config", "diff.mnemonicPrefix", "true")

	if err := os.MkdirAll(filepath.Join(repo, "testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "testdata", "fixture.txt"), []byte("口座番号: 1234567\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "main.txt"), []byte("口座番号: 7654321\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", ".")

	cfg, err := config.Parse("[allowlist]\npaths = [\"^testdata/\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := ScanStaged(d, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].File != "main.txt" {
		t.Fatalf("findings = %+v, want main.txt の 1 件のみ（diff.mnemonicPrefix=true でも "+
			"allowlist(^testdata/) が効き、報告パスに i/ 接頭辞が残らない）", findings)
	}
}

// git リポジトリでないディレクトリで --staged / --diff を実行した場合、
// パニックせずエラーを返すこと。
func TestScanDiffNonGitDirectory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	t.Chdir(t.TempDir())

	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ScanStaged(d, cfg); err == nil {
		t.Error("expected error for --staged in a non-git directory")
	}
	if _, err := ScanDiff(d, cfg, "HEAD~1...HEAD"); err == nil {
		t.Error("expected error for --diff in a non-git directory")
	}
}

// git バイナリが見つからない環境でもパニックせずエラーを返すこと。
func TestScanStagedMissingGitBinary(t *testing.T) {
	initTestRepo(t) // git が使える環境であることを確認してから PATH を壊す。
	t.Setenv("PATH", "")

	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ScanStaged(d, cfg); err == nil {
		t.Error("expected error when git binary is unavailable")
	}
}
