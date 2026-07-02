package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/piifixtures"
)

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanPaths(t *testing.T) {
	piifixtures.Require(t)
	tmp := t.TempDir()
	phone := []byte("TEL: " + piifixtures.MustGet(t, "source.phone_mobile_sep") + "\n")
	writeFile(t, filepath.Join(tmp, "pii.txt"), phone)
	writeFile(t, filepath.Join(tmp, "clean.txt"), []byte("no pii here\n"))
	// NUL バイトを含むバイナリは走査しない。
	writeFile(t, filepath.Join(tmp, "binary.bin"), append([]byte{0x00, 0x01}, phone...))
	// 5MB 超は走査しない。
	big := make([]byte, MaxFileSize+1)
	copy(big, phone)
	writeFile(t, filepath.Join(tmp, "big.txt"), big)
	// 依存ディレクトリは走査しない。
	writeFile(t, filepath.Join(tmp, "node_modules", "leak.txt"), phone)
	// allowlist.paths で除外されるパス。
	writeFile(t, filepath.Join(tmp, "excluded", "secret.txt"), phone)

	cfg, err := config.Parse("[allowlist]\npaths = [\"/excluded/\"]\n")
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
		t.Fatalf("warnings = %+v, want なし", warnings)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d 件 %+v, want 1", len(findings), findings)
	}
	f := findings[0]
	if !strings.HasSuffix(f.File, "/pii.txt") {
		t.Errorf("File = %q, want .../pii.txt", f.File)
	}
	if strings.Contains(f.File, `\`) {
		t.Errorf("File = %q, want slash-separated", f.File)
	}
	if f.RuleID != "jp-phone-number" || f.Line != 1 {
		t.Errorf("finding = %+v", f)
	}
}

// allowlist.paths は検出結果に報告されるパスと同じ表記で照合される。
func TestScanPathsAllowlistMatchesReportedPath(t *testing.T) {
	piifixtures.Require(t)
	tmp := t.TempDir()
	phone := []byte("TEL: " + piifixtures.MustGet(t, "source.phone_mobile_sep") + "\n")
	writeFile(t, filepath.Join(tmp, "src", "testdata", "fixture.txt"), phone)
	writeFile(t, filepath.Join(tmp, "src", "main.txt"), phone)

	cfg, err := config.Parse("[allowlist]\npaths = [\"/testdata/\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// サブディレクトリを走査ルートに指定しても、報告パス基準で除外される。
	findings, _, err := ScanPaths(d, cfg, []string{filepath.Join(tmp, "src")})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || !strings.HasSuffix(findings[0].File, "/src/main.txt") {
		t.Fatalf("findings = %+v, want only src/main.txt", findings)
	}
}

// サブディレクトリから実行しても、リポジトリルート相対の allowlist.paths
// （^testdata/ 等）が機能すること。旧実装は走査時のパス表記
// （../testdata/...）だけで照合していたためアンカーが効かなかった。
func TestScanPathsAllowlistRepoRootRelative(t *testing.T) {
	piifixtures.Require(t)
	repo := t.TempDir()
	phone := []byte("TEL: " + piifixtures.MustGet(t, "source.phone_mobile_sep") + "\n")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(repo, "testdata", "fixture.txt"), phone)
	writeFile(t, filepath.Join(repo, "src", "main.txt"), phone)
	t.Chdir(filepath.Join(repo, "src"))

	cfg, err := config.Parse("[allowlist]\npaths = [\"^testdata/\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings, _, err := ScanPaths(d, cfg, []string{".."})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || !strings.HasSuffix(findings[0].File, "/src/main.txt") {
		t.Fatalf("findings = %+v, want only src/main.txt", findings)
	}
}

// 複数ファイルの検出結果が walk 順（=決定的な順序）で返ること。
// 並列化後の順序保証の回帰テスト。
func TestScanPathsDeterministicOrder(t *testing.T) {
	piifixtures.Require(t)
	tmp := t.TempDir()
	phone := []byte("TEL: " + piifixtures.MustGet(t, "source.phone_mobile_sep") + "\n")
	for _, name := range []string{"a.txt", "b.txt", "c.txt", "d.txt"} {
		writeFile(t, filepath.Join(tmp, name), phone)
	}
	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		findings, _, err := ScanPaths(d, cfg, []string{tmp})
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 4 {
			t.Fatalf("findings = %d, want 4", len(findings))
		}
		for i, base := range []string{"a.txt", "b.txt", "c.txt", "d.txt"} {
			if !strings.HasSuffix(findings[i].File, "/"+base) {
				t.Fatalf("findings[%d].File = %q, want %s", i, findings[i].File, base)
			}
		}
	}
}

// 個々のファイルの読み取りエラー（権限拒否等）は致命的にせず、そのファイルを
// スキップして走査を継続すること。他ファイルの収集済み findings は失われず、
// エラーは戻り値の warnings に集約される（err は nil のまま）。
func TestScanPathsUnreadableFileDoesNotAbortOthers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root では読み取り権限のチェックが効かないためスキップ")
	}
	content := []byte("口座番号: 1234567\n")
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "ok.txt"), content)
	denied := filepath.Join(tmp, "denied.txt")
	writeFile(t, denied, content)
	if err := os.Chmod(denied, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(denied, 0o644) })

	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings, warnings, err := ScanPaths(d, cfg, []string{tmp})
	if err != nil {
		t.Fatalf("ScanPaths エラー: %v（個別ファイルの読み取りエラーは致命的にしない）", err)
	}
	if len(findings) != 1 || !strings.HasSuffix(findings[0].File, "/ok.txt") {
		t.Fatalf("findings = %+v, want ok.txt の 1 件のみ", findings)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0].Error(), "denied.txt") {
		t.Fatalf("warnings = %+v, want denied.txt の読み取りエラー 1 件", warnings)
	}
}

func TestIsBinary(t *testing.T) {
	if isBinary([]byte("plain text")) {
		t.Error("plain text should not be binary")
	}
	if !isBinary([]byte{'a', 0x00, 'b'}) {
		t.Error("NUL byte should be binary")
	}
}
