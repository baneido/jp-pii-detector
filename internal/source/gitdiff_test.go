package source

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
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

// --- CSV/TSV 列コンテキストを --staged / --diff でも効かせる機能 ---
//
// internal/detect/csv_context.go のヘッダ→列文脈の仕組みはフルスキャン限定
// だったが、post-image のヘッダ行を `git show` で個別取得することで
// --staged / --diff でも働くようになった（detect.ScanDiffHunkWithCSVHeader
// 経由）。以下は internal/source/gitdiff.go 側の配線（diffRangePostRevision・
// fetchCSVHeader・scanHunk からの呼び出し）の end-to-end 確認。

// csvColumnContextFixtureCSV は、ヘッダから何行離れていても列コンテキストが
// 追加行まで届くこと（-U3 の文脈行ウィンドウにヘッダが入らないケース）を
// 確認するテスト群の共有セットアップ。5 行の既存データ行を挟むことで、
// 末尾に 1 行追加したときの hunk が（末尾 3 行の文脈行＋追加行のみを含み）
// ヘッダ行（1 行目）を含まないことを保証する。
func csvColumnContextFixtureCSV(t *testing.T) (repo, name, phone string) {
	t.Helper()
	repo = initTestRepo(t)
	name = "data.csv"
	// 区切りなし固定電話（10 桁）。jp-phone-number の他のパターン（携帯・IP・
	// 区切りあり固定電話等）はいずれもコンテキスト不要のため単独でも検出される。
	// 列単位のコンテキスト（RequireContext）が効いていることを確認したいので、
	// あえてコンテキスト必須の区切りなし固定電話パターン（`0\d{9}`）だけが
	// マッチする形にする。
	phone = strings.ReplaceAll(testfixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")

	var base strings.Builder
	base.WriteString("電話番号,金額\n")
	for range 5 {
		base.WriteString("dummy,1000\n")
	}
	if err := os.WriteFile(filepath.Join(repo, name), []byte(base.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", ".")
	git(t, "commit", "-q", "-m", "base")

	// ヘッダから離れた末尾（7 行目）に、電話番号列・金額列とも同じ値を追加する。
	// 同じ値なのに列によって検出結果が変わることが、列コンテキストが
	// 列ごとに正しくスコープされている証拠になる。
	content := base.String() + phone + "," + phone + "\n"
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", ".")
	return repo, name, phone
}

// ヘッダが hunk の外（変更行から 4 行以上手前）にあっても、git show で取得した
// ヘッダにより列コンテキストが追加行まで届くこと。電話番号列の値は検出され、
// 同じ値を金額列に置いても検出されない（RequireContext が列ごとに正しく
// スコープされていることの確認）。
func TestScanStagedCSVColumnContextHeaderOutsideHunk(t *testing.T) {
	_, name, _ := csvColumnContextFixtureCSV(t)

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
		t.Fatalf("findings = %+v, want 1 件（電話番号列のみ検出。金額列の同じ値は検出されない）", findings)
	}
	if f := findings[0]; f.File != name || f.RuleID != "jp-phone-number" || f.Line != 7 || f.Column != 1 {
		t.Errorf("finding = %+v, want %s:7:1 jp-phone-number", f, name)
	}
}

// ScanDiff（コミット範囲）でも同じ列コンテキストが働くこと。diffRangePostRevision
// が "A...B" 形式から post-image（B 側）を正しく解決できることの確認を兼ねる。
func TestScanDiffRangeCSVColumnContext(t *testing.T) {
	_, name, _ := csvColumnContextFixtureCSV(t)
	git(t, "commit", "-q", "-m", "add row")

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
		t.Fatalf("findings = %+v, want 1 件", findings)
	}
	if f := findings[0]; f.File != name || f.RuleID != "jp-phone-number" || f.Line != 7 {
		t.Errorf("finding = %+v, want %s:7 jp-phone-number", f, name)
	}
}

// 新規ファイル（ヘッダ自体が追加行として hunk 内にあるケース）でも、
// git show :<path> によるヘッダ取得は成功し（ステージ済みインデックスに
// 新規ファイルの内容がある）、データ行の列コンテキストが正しく働くこと。
func TestScanStagedCSVColumnContextNewFileHeaderInHunk(t *testing.T) {
	repo := initTestRepo(t)
	name := "data.csv"
	phone := strings.ReplaceAll(testfixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")
	content := "電話番号,金額\n" + phone + "," + phone + "\n"
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644); err != nil {
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
	if f := findings[0]; f.File != name || f.RuleID != "jp-phone-number" || f.Line != 2 || f.Column != 1 {
		t.Errorf("finding = %+v, want %s:2:1 jp-phone-number", f, name)
	}
}

// TSV（タブ区切り）でも同じ列コンテキストの仕組みが働くこと。
func TestScanStagedCSVColumnContextTSV(t *testing.T) {
	repo := initTestRepo(t)
	name := "data.tsv"
	phone := strings.ReplaceAll(testfixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")
	content := "電話番号\t金額\n" + phone + "\t" + phone + "\n"
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644); err != nil {
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
	if len(findings) != 1 || findings[0].RuleID != "jp-phone-number" || findings[0].Line != 2 {
		t.Fatalf("findings = %+v, want 1 件 %s:2 jp-phone-number", findings, name)
	}
}

// --- .sql の INSERT 列コンテキストを --staged でも効かせる機能 ---
//
// internal/detect/sql_context.go の INSERT 列コンテキストは CSV と異なり、
// 列リストと値が同一物理行に同居するため、CSV のような git show による
// post-image ヘッダの個別取得を必要としない（sourceLineContextsForDiff の
// sourceKindSQL 分岐は sqlLineContexts をそのまま呼ぶだけ）。実際の git
// リポジトリを使い、--staged 経由の配線（parseDiffHunks・scanHunk・
// ScanDiffHunkWithCSVHeader を経由して sourceLineContextsForDiff に到達する
// 経路全体）が正しく機能することを end-to-end で確認する
// （internal/detect/sql_context_test.go の
// TestSQLScanDiffHunkOrderIDColumnSuppressesBankAccountFalsePositive の
// 統合テスト版）。

// kouza 列の値は銀行口座番号として検出され、同じ行の order_id 列の 7 桁の
// 値は「注文 ID」を意味する列コンテキストの負文脈により誤検出されない
// （列単位で正負の文脈が独立して効くことの確認）。
func TestScanStagedSQLColumnContext(t *testing.T) {
	repo := initTestRepo(t)
	name := "dump.sql"
	content := "INSERT INTO t (kouza,order_id) VALUES ('1234567',7654321);\n" // jp-pii-detector:ignore
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644); err != nil {
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
		t.Fatalf("findings = %+v, want 1 件（kouza 列のみ検出。order_id 列の 7 桁は銀行口座番号として誤検出されない）", findings)
	}
	if f := findings[0]; f.File != name || f.RuleID != "jp-bank-account" || f.Match != "1234567" || f.Line != 1 {
		t.Errorf("finding = %+v, want %s:1 jp-bank-account match=1234567", f, name)
	}
}

// --diff にドットを含まない裸のリビジョン（例: "HEAD~1"）を渡すと、git diff 的には
// 作業ツリーとの比較になり単一の post-image リビジョンを解決できない
// （diffRangePostRevision が ok=false を返す）。この場合はヘッダ取得を諦め、
// 列コンテキストなしの安全側にフォールバックすること（クラッシュしない・
// ヘッダ行から離れた追加行が検出されないままであることを確認する。従来の
// diff 走査そのものは変わらず正常に動作する）。
func TestScanDiffCSVColumnContextFallsBackWhenPostRevisionUnresolvable(t *testing.T) {
	csvColumnContextFixtureCSV(t)
	git(t, "commit", "-q", "-m", "add row")

	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// "HEAD~1" はドットを含まないため post-image の単一リビジョンとして
	// 解決できない（scanGitDiff 自体は working tree との通常の diff として
	// 変わらず動作する）。
	findings, err := ScanDiff(d, cfg, "HEAD~1")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Line == 7 {
			t.Errorf("header 行から離れた追加行が検出された（列コンテキストの安全側フォールバックが効いていない）: %+v", f)
		}
	}
}

// diffRangePostRevision が "--diff <range>" の各形式から post-image リビジョンを
// 正しく解決すること（ScanDiff は range 文字列をそのまま git diff の 1 引数として
// 渡すため、ここでも同じ文字列を解析する）。
func TestDiffRangePostRevision(t *testing.T) {
	tests := []struct {
		in      string
		wantRev string
		wantOK  bool
	}{
		{"origin/main...HEAD", "HEAD", true},
		{"a..b", "b", true},
		{"a...b", "b", true},
		{"a...", "HEAD", true},
		{"...b", "b", true},
		{"a..", "HEAD", true},
		{"..b", "b", true},
		{"abc123", "", false},
		{"", "", false},
		{"  a...b  ", "b", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			rev, ok := diffRangePostRevision(tt.in)
			if rev != tt.wantRev || ok != tt.wantOK {
				t.Errorf("diffRangePostRevision(%q) = (%q, %v), want (%q, %v)", tt.in, rev, ok, tt.wantRev, tt.wantOK)
			}
		})
	}
}

// fetchCSVHeader の取得失敗（存在しないパス・存在しないリビジョン）が
// パニックせず "" にフォールバックすること、および --staged
// （revSpec=""）・コミット済み（revSpec="HEAD"）の双方でヘッダを取得
// できることを直接確認する（scanHunk 経由の end-to-end テストとは別に、
// この関数単体の境界条件を確認する）。
func TestFetchCSVHeader(t *testing.T) {
	repo := initTestRepo(t)
	name := "data.csv"
	if err := os.WriteFile(filepath.Join(repo, name), []byte("郵便番号,口座番号\n100-0001,1234567\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", name)
	git(t, "commit", "-q", "-m", "base")

	const want = "郵便番号,口座番号"
	if got := fetchCSVHeader("HEAD", name); got != want {
		t.Errorf("fetchCSVHeader(HEAD, %q) = %q, want %q", name, got, want)
	}
	if got := fetchCSVHeader("", name); got != want {
		t.Errorf("fetchCSVHeader(\"\", %q) = %q, want %q (index stage 0)", name, got, want)
	}
	if got := fetchCSVHeader("HEAD", "does-not-exist.csv"); got != "" {
		t.Errorf("fetchCSVHeader for a missing path = %q, want empty (git show failure falls back safely)", got)
	}
	if got := fetchCSVHeader("no-such-rev", name); got != "" {
		t.Errorf("fetchCSVHeader for a missing revision = %q, want empty", got)
	}
}

// firstLine が改行・CRLF を正しく処理すること。
func TestFirstLine(t *testing.T) {
	tests := []struct {
		in   []byte
		want string
	}{
		{[]byte("a,b\nc,d\n"), "a,b"},
		{[]byte("a,b\r\nc,d\r\n"), "a,b"},
		{[]byte("onlyline"), "onlyline"},
		{[]byte(""), ""},
	}
	for _, tt := range tests {
		if got := firstLine(tt.in); got != tt.want {
			t.Errorf("firstLine(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// --- .json/.yaml/.yml のオブジェクトスコープ親キー文脈を --staged / --diff でも
// 効かせる機能 ---
//
// internal/detect/object_scope.go の親キー文脈（applyObjectScopeContext）は
// フルスキャン限定だったが、post-image 全文を `git show` で個別取得すること
// （fetchPostImage）で --staged / --diff でも働くようになった
// （detect.ScanDiffHunkOpts 経由）。以下は internal/source/gitdiff.go 側の配線
// （fetchPostImage・cachedPostImage・scanHunk からの呼び出し、fileHunk.NewStart
// の受け渡し）の end-to-end 確認。csvColumnContextFixtureCSV と同じ発想で、
// ヘッダ相当の親キーをわざと -U3 の文脈行ウィンドウの外へ押し出す。

// 親キー "phone:" が hunk の外（変更行から 4 行以上手前）にあっても、
// git show で取得した post-image から親キー文脈が追加行まで届くこと。
func TestScanStagedYAMLObjectScopeParentKeyOutsideHunk(t *testing.T) {
	repo := initTestRepo(t)
	name := "config.yaml"
	// 区切りなし固定電話（10 桁）。RequireContext のパターンが対象なので、
	// 親キー文脈が届かない限り検出されない（csvColumnContextFixtureCSV と同じ理由）。
	phone := strings.ReplaceAll(testfixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")

	base := "phone:\n" + strings.Repeat("  filler: x\n", 5)
	if err := os.WriteFile(filepath.Join(repo, name), []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", ".")
	git(t, "commit", "-q", "-m", "base")

	// ヘッダ（1 行目の "phone:"）から離れた末尾（7 行目）に値を追加する。
	content := base + "  home: " + phone + "\n"
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644); err != nil {
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
		t.Fatalf("findings = %+v, want 1 件（親キー phone が hunk 外でも post-image から復元されて検出）", findings)
	}
	if f := findings[0]; f.File != name || f.RuleID != "jp-phone-number" || f.Line != 7 {
		t.Errorf("finding = %+v, want %s:7 jp-phone-number", f, name)
	}
}

// ScanDiff（コミット範囲）でも同じ親キー文脈が働くこと。diffRangePostRevision が
// "A...B" 形式から post-image（B 側）を正しく解決できることの確認を兼ねる
// （TestScanDiffRangeCSVColumnContext と対称）。
func TestScanDiffRangeYAMLObjectScopeParentKeyOutsideHunk(t *testing.T) {
	repo := initTestRepo(t)
	name := "config.yaml"
	phone := strings.ReplaceAll(testfixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")

	base := "phone:\n" + strings.Repeat("  filler: x\n", 5)
	if err := os.WriteFile(filepath.Join(repo, name), []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", ".")
	git(t, "commit", "-q", "-m", "base")

	content := base + "  home: " + phone + "\n"
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644); err != nil {
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
		t.Fatalf("findings = %+v, want 1 件", findings)
	}
	if f := findings[0]; f.File != name || f.RuleID != "jp-phone-number" || f.Line != 7 {
		t.Errorf("finding = %+v, want %s:7 jp-phone-number", f, name)
	}
}

// --- ゆうちょ別行ペアを --staged でも効かせる機能 ---
//
// internal/detect/yucho_pair.go の scanCrossLineYuchoPairsDiff（最小案、
// issue #134）の end-to-end 確認。記号・番号ラベルの一方が既存（未変更）行、
// もう一方が追加行というケースを含めて確認する。

// 記号・番号の両方を新規追加した場合、両方とも検出される。
func TestScanStagedYuchoPairBothAdded(t *testing.T) {
	repo := initTestRepo(t)
	name := "pii.txt"
	content := []byte("記号: 14030\n番号: 12345671\n") // jp-pii-detector:ignore
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
	if len(findings) != 2 {
		t.Fatalf("findings = %+v, want 2 件（記号・番号ともに新規追加）", findings)
	}
	if f := findings[0]; f.File != name || f.RuleID != "jp-yucho-account" || f.Line != 1 {
		t.Errorf("findings[0] = %+v, want %s:1 jp-yucho-account", f, name)
	}
	if f := findings[1]; f.File != name || f.RuleID != "jp-yucho-account" || f.Line != 2 {
		t.Errorf("findings[1] = %+v, want %s:2 jp-yucho-account", f, name)
	}
}

// 記号行が既存（未変更）、番号行だけを新規追加した場合、番号側の値だけが
// 検出される（記号側は「既存 PII」として報告しない。ScanContent 側の
// jp-pii-detector:ignore 抑制と対称的に、diff 走査は追加行のみ報告するという
// 原則そのものが記号側を除外する）。
func TestScanStagedYuchoPairOnlyAddedSideReported(t *testing.T) {
	repo := initTestRepo(t)
	name := "pii.txt"
	if err := os.WriteFile(filepath.Join(repo, name), []byte("記号: 14030\n"), 0o644); err != nil { // jp-pii-detector:ignore
		t.Fatal(err)
	}
	git(t, "add", ".")
	git(t, "commit", "-q", "-m", "base")
	if err := os.WriteFile(filepath.Join(repo, name), []byte("記号: 14030\n番号: 12345671\n"), 0o644); err != nil { // jp-pii-detector:ignore
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
		t.Fatalf("findings = %+v, want 1 件（番号のみ新規追加、記号は既存の文脈行）", findings)
	}
	if f := findings[0]; f.File != name || f.RuleID != "jp-yucho-account" || f.Line != 2 || f.Match != "12345671" {
		t.Errorf("finding = %+v, want %s:2 jp-yucho-account match=12345671", f, name)
	}
}

// --- .json/.yaml/.yml の post-image 全文を git show で取得する fetchPostImage ---

// fetchPostImage の取得失敗（存在しないパス・存在しないリビジョン）・サイズ
// 上限超過が、パニックせず "" にフォールバックすること、および --staged
// （revSpec=""）・コミット済み（revSpec="HEAD"）の双方で post-image全文を
// 取得できることを直接確認する（TestFetchCSVHeader と同じ発想。scanHunk 経由の
// end-to-end テストとは別に、この関数単体の境界条件を確認する）。
func TestFetchPostImage(t *testing.T) {
	repo := initTestRepo(t)
	name := "data.yaml"
	const content = "phone:\n  home: dummy\n"
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", name)
	git(t, "commit", "-q", "-m", "base")

	if got := fetchPostImage("HEAD", name); got != content {
		t.Errorf("fetchPostImage(HEAD, %q) = %q, want %q", name, got, content)
	}
	if got := fetchPostImage("", name); got != content {
		t.Errorf("fetchPostImage(\"\", %q) = %q, want %q (index stage 0)", name, got, content)
	}
	if got := fetchPostImage("HEAD", "does-not-exist.yaml"); got != "" {
		t.Errorf("fetchPostImage for a missing path = %q, want empty (git show failure falls back safely)", got)
	}
	if got := fetchPostImage("no-such-rev", name); got != "" {
		t.Errorf("fetchPostImage for a missing revision = %q, want empty", got)
	}

	// MaxFileSize（files.go）を超えるファイルは "" にフォールバックする
	// （通常のフルスキャン走査と同じサイズ上限を流用しているため）。
	bigName := "big.yaml"
	big := bigYAMLOverMaxFileSize()
	if err := os.WriteFile(filepath.Join(repo, bigName), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", bigName)
	git(t, "commit", "-q", "-m", "big")
	if got := fetchPostImage("HEAD", bigName); got != "" {
		t.Errorf("fetchPostImage for a file over MaxFileSize (%d bytes) = %d bytes, want empty (safe fallback)", len(big), len(got))
	}
}

// サイズ上限超過時、ScanStaged 経由でも安全にフォールバックする（親キー文脈
// なしとなり、home の値は自己文脈だけでは検出されないが、クラッシュしたり
// 誤って検出されたりしない）ことを end-to-end で確認する。
func TestScanStagedObjectScopePostImageSizeLimitFallback(t *testing.T) {
	repo := initTestRepo(t)
	name := "big.yaml"
	phone := strings.ReplaceAll(testfixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")

	base := bigYAMLOverMaxFileSize()
	if err := os.WriteFile(filepath.Join(repo, name), []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", ".")
	git(t, "commit", "-q", "-m", "base")

	content := base + "  home: " + phone + "\n"
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644); err != nil {
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
		t.Fatalf("findings = %+v, want 0 件（post-image がサイズ上限超過でフォールバックし、親キー phone を復元できない）", findings)
	}
}

// bigYAMLOverMaxFileSize は MaxFileSize（files.go）を超える YAML テキストを
// 生成する。"phone:" トップレベルキー配下に PII を含まない filler 行を必要な
// だけ繰り返すだけの、サイズ上限超過フォールバック専用の固定データ。
func bigYAMLOverMaxFileSize() string {
	line := "  filler: " + strings.Repeat("x", 100) + "\n"
	var b strings.Builder
	b.WriteString("phone:\n")
	for b.Len() <= MaxFileSize {
		b.WriteString(line)
	}
	return b.String()
}
