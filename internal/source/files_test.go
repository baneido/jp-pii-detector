package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
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
	tmp := t.TempDir()
	phone := []byte("TEL: 090-1234-5678\n")
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
	findings, err := ScanPaths(d, cfg, []string{tmp})
	if err != nil {
		t.Fatal(err)
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
	tmp := t.TempDir()
	phone := []byte("TEL: 090-1234-5678\n")
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
	findings, err := ScanPaths(d, cfg, []string{filepath.Join(tmp, "src")})
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
	repo := t.TempDir()
	phone := []byte("TEL: 090-1234-5678\n")
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
	findings, err := ScanPaths(d, cfg, []string{".."})
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
	tmp := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt", "c.txt", "d.txt"} {
		writeFile(t, filepath.Join(tmp, name), []byte("TEL: 090-1234-5678\n"))
	}
	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		findings, err := ScanPaths(d, cfg, []string{tmp})
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

func TestIsBinary(t *testing.T) {
	if isBinary([]byte("plain text")) {
		t.Error("plain text should not be binary")
	}
	if !isBinary([]byte{'a', 0x00, 'b'}) {
		t.Error("NUL byte should be binary")
	}
}
