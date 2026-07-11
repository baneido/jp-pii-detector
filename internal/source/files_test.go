package source

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

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

func TestScanPathsUnreadableDirectoryDoesNotAbortOthers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root では読み取り権限のチェックが効かないためスキップ")
	}
	tmp := t.TempDir()
	content := []byte("口座番号: 1234567\n")
	writeFile(t, filepath.Join(tmp, "ok", "a.txt"), content)
	denied := filepath.Join(tmp, "denied")
	if err := os.Mkdir(denied, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(denied, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(denied, 0o755) })

	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings, warnings, err := ScanPaths(d, cfg, []string{tmp})
	if err != nil {
		t.Fatalf("ScanPaths エラー: %v（個別ディレクトリの走査エラーは致命的にしない）", err)
	}
	if len(findings) != 1 || !strings.HasSuffix(findings[0].File, "/ok/a.txt") {
		t.Fatalf("findings = %+v, want ok/a.txt の 1 件のみ", findings)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0].Error(), "denied") {
		t.Fatalf("warnings = %+v, want denied ディレクトリの走査エラー 1 件", warnings)
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

// utf16WithBOM は s を BOM 付き UTF-16（order で指定したバイト順）へ
// エンコードする（テスト用ヘルパー。実ファイルをコミットせず実行時に生成する）。
func utf16WithBOM(s string, order binary.ByteOrder) []byte {
	units := utf16.Encode([]rune(s))
	buf := make([]byte, 2+2*len(units))
	if order == binary.LittleEndian {
		buf[0], buf[1] = 0xFF, 0xFE
	} else {
		buf[0], buf[1] = 0xFE, 0xFF
	}
	for i, u := range units {
		order.PutUint16(buf[2+i*2:], u)
	}
	return buf
}

// decodeUTF16 の往復（LE/BE）を検証する。UTF-16 は半角文字の直後に NUL
// バイトが並ぶため、BOM チェックより先に isBinary を通すと確実にバイナリ
// 扱いされる（decodeUTF16 が isBinary より前に呼ばれることの回帰確認も兼ねる）。
func TestDecodeUTF16RoundTrip(t *testing.T) {
	text := "口座番号: 1234567\n有効な本文です。"
	for _, tc := range []struct {
		name  string
		order binary.ByteOrder
	}{
		{"リトルエンディアン", binary.LittleEndian},
		{"ビッグエンディアン", binary.BigEndian},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := utf16WithBOM(text, tc.order)
			// BOM 付き UTF-16 は半角文字の隣に NUL バイトが並ぶため、
			// decodeUTF16 を経ない従来判定ではバイナリ扱いされることを確認する
			// （BOM チェックが isBinary より先である必要性の裏取り）。
			if !isBinary(data) {
				t.Fatal("UTF-16 encoded data should look binary under the NUL-byte heuristic alone")
			}
			got, ok := decodeUTF16(data)
			if !ok {
				t.Fatalf("decodeUTF16(%s) ok = false, want true", tc.name)
			}
			if got != text {
				t.Fatalf("decodeUTF16(%s) = %q, want %q", tc.name, got, text)
			}
		})
	}
}

// BOM が無い通常の UTF-8/ASCII は decodeUTF16 の対象外（ok=false）で、
// 従来どおり isBinary 判定に委ねられること。
func TestDecodeUTF16NoBOMIsNotUTF16(t *testing.T) {
	if _, ok := decodeUTF16([]byte("plain ascii, no bom")); ok {
		t.Fatal("data without a UTF-16 BOM should not be decoded as UTF-16")
	}
}

// 不正なバイト列（奇数長・孤立サロゲート）はデコード失敗として
// 従来のバイナリ判定へフォールバックすること。
func TestDecodeUTF16InvalidFallsBack(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"奇数長の本文", []byte{0xFF, 0xFE, 'a', 0, 'b'}},
		{"孤立した上位サロゲート", []byte{0xFF, 0xFE, 0x00, 0xD8, 0x41, 0x00}},
		{"孤立した下位サロゲート", []byte{0xFF, 0xFE, 0x00, 0xDC, 0x41, 0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := decodeUTF16(tt.data); ok {
				t.Fatalf("decodeUTF16(%v) ok = true, want false (fallback to binary handling)", tt.data)
			}
		})
	}
}

// ScanPaths が UTF-16LE/BE ファイルを検出できること（フル走査の end-to-end）。
// UTF-16 フィクスチャは本変更後にドッグフード走査対象化するため、コミットせず
// t.TempDir() に実行時生成する。
func TestScanPathsDecodesUTF16(t *testing.T) {
	tmp := t.TempDir()
	text := "口座番号: 1234567\n"
	writeFile(t, filepath.Join(tmp, "utf16le.txt"), utf16WithBOM(text, binary.LittleEndian))
	writeFile(t, filepath.Join(tmp, "utf16be.txt"), utf16WithBOM(text, binary.BigEndian))
	// 通常の UTF-8（BOM 無し）は従来どおり検出できること（回帰確認）。
	writeFile(t, filepath.Join(tmp, "utf8.txt"), []byte(text))

	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings, warnings, err := ScanPaths(d, cfg, []string{tmp})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if len(findings) != 3 {
		t.Fatalf("findings = %d 件 %+v, want 3", len(findings), findings)
	}
	for _, f := range findings {
		if f.RuleID != "jp-bank-account" || f.Line != 1 {
			t.Errorf("finding = %+v, want jp-bank-account at line 1", f)
		}
	}
}
