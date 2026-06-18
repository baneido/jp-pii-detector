package scripts_test

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	testVersion = "v1.2.3"
	testOS      = "linux"
	testArch    = "amd64"
	testAsset   = "jp-pii-detect_linux_amd64.tar.gz"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(dir)
}

func runScript(t *testing.T, script string, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{script}, args...)...)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	exit, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("%s %v: %v\n%s", script, args, err, out)
	}
	return string(out), exit.ExitCode()
}

func writeFakeReleaseArchive(t *testing.T, root string) string {
	return writeFakeReleaseArchiveFor(t, root, testVersion, "#!/bin/sh\necho fake-jp-pii-detect \"$@\"\n")
}

func writeFakeReleaseArchiveFor(t *testing.T, root, version, body string) string {
	t.Helper()
	releaseDir := filepath.Join(root, version)
	if err := os.MkdirAll(releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(releaseDir, testAsset)
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	if err := tw.WriteHeader(&tar.Header{
		Name: "jp-pii-detect",
		Mode: 0o755,
		Size: int64(len(body)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	writeChecksums(t, releaseDir, map[string]string{
		testAsset: sha256File(t, archivePath),
	})
	return archivePath
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeChecksums(t *testing.T, dir string, sums map[string]string) {
	t.Helper()
	var b strings.Builder
	for name, sum := range sums {
		b.WriteString(sum)
		b.WriteString("  ")
		b.WriteString(name)
		b.WriteString("\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func distributionEnv(baseURL, installDir string) []string {
	return []string{
		"JP_PII_DETECT_VERSION=" + testVersion,
		"JP_PII_DETECT_OS=" + testOS,
		"JP_PII_DETECT_ARCH=" + testArch,
		"JP_PII_DETECT_RELEASE_BASE_URL=" + baseURL,
		"JP_PII_DETECT_INSTALL_DIR=" + installDir,
		"JP_PII_DETECT_CACHE_DIR=" + installDir,
	}
}

func TestInstallScriptPrintsReleaseAssetURL(t *testing.T) {
	out, code := runScript(t, "scripts/install.sh", distributionEnv("https://example.test/releases", t.TempDir()), "--print-url")
	if code != 0 {
		t.Fatalf("install.sh --print-url exit=%d\n%s", code, out)
	}
	want := "https://example.test/releases/" + testVersion + "/" + testAsset
	if strings.TrimSpace(out) != want {
		t.Fatalf("URL = %q, want %q", strings.TrimSpace(out), want)
	}
}

func TestInstallScriptInstallsFromReleaseArchive(t *testing.T) {
	releases := t.TempDir()
	writeFakeReleaseArchive(t, releases)
	installDir := filepath.Join(t.TempDir(), "bin")

	out, code := runScript(t, "scripts/install.sh", distributionEnv("file://"+releases, installDir))
	if code != 0 {
		t.Fatalf("install.sh exit=%d\n%s", code, out)
	}

	bin := filepath.Join(installDir, "jp-pii-detect")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	info, err := os.Stat(bin)
	if err != nil {
		t.Fatalf("installed binary missing: %v\n%s", err, out)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("installed binary is not executable: %v", info.Mode())
	}
}

func TestInstallScriptRejectsChecksumMismatch(t *testing.T) {
	releases := t.TempDir()
	archive := writeFakeReleaseArchive(t, releases)
	if err := os.WriteFile(archive, []byte("tampered archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	installDir := filepath.Join(t.TempDir(), "bin")

	out, code := runScript(t, "scripts/install.sh", distributionEnv("file://"+releases, installDir))
	if code == 0 {
		t.Fatalf("install.sh should reject checksum mismatch\n%s", out)
	}
	if !strings.Contains(out, "checksum verification failed") {
		t.Fatalf("install.sh should explain checksum failure, got:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(installDir, "jp-pii-detect")); !os.IsNotExist(err) {
		t.Fatalf("binary should not be installed after checksum failure: %v", err)
	}
}

func TestPreCommitScriptInstallsAndRunsScanner(t *testing.T) {
	releases := t.TempDir()
	writeFakeReleaseArchive(t, releases)
	cacheDir := filepath.Join(t.TempDir(), "cache")

	out, code := runScript(t, "scripts/pre-commit.sh", distributionEnv("file://"+releases, cacheDir))
	if code != 0 {
		t.Fatalf("pre-commit.sh exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "fake-jp-pii-detect scan --staged") {
		t.Fatalf("pre-commit should run scanner with scan --staged, got:\n%s", out)
	}
}

func TestPreCommitLatestRefetchesOnEveryRun(t *testing.T) {
	releases := t.TempDir()
	writeFakeReleaseArchiveFor(t, releases, "latest", "#!/bin/sh\necho old-latest \"$@\"\n")
	cacheDir := filepath.Join(t.TempDir(), "cache")
	env := []string{
		"JP_PII_DETECT_VERSION=latest",
		"JP_PII_DETECT_OS=" + testOS,
		"JP_PII_DETECT_ARCH=" + testArch,
		"JP_PII_DETECT_RELEASE_BASE_URL=file://" + releases,
		"JP_PII_DETECT_CACHE_DIR=" + cacheDir,
	}

	out, code := runScript(t, "scripts/pre-commit.sh", env)
	if code != 0 {
		t.Fatalf("first pre-commit.sh exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "old-latest scan --staged") {
		t.Fatalf("first run should use old latest binary, got:\n%s", out)
	}

	writeFakeReleaseArchiveFor(t, releases, "latest", "#!/bin/sh\necho new-latest \"$@\"\n")
	out, code = runScript(t, "scripts/pre-commit.sh", env)
	if code != 0 {
		t.Fatalf("second pre-commit.sh exit=%d\n%s", code, out)
	}
	if !strings.Contains(out, "new-latest scan --staged") {
		t.Fatalf("latest should be re-fetched on second run, got:\n%s", out)
	}
}

func TestActionUsesPrebuiltBinaryInstaller(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, forbidden := range []string{"actions/setup-go", "go install", "go env"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("action.yml should not require Go toolchain; found %q", forbidden)
		}
	}
	if !strings.Contains(text, "scripts/install.sh") || !strings.Contains(text, "jp-pii-detect ${{ inputs.args }}") {
		t.Fatalf("action.yml should install a release binary and run it:\n%s", text)
	}
}

func TestPreCommitHookUsesScriptWrapper(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), ".pre-commit-hooks.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"entry: scripts/pre-commit.sh",
		"language: script",
		"pass_filenames: false",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf(".pre-commit-hooks.yaml missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "language: golang") {
		t.Fatalf(".pre-commit-hooks.yaml should not use language: golang")
	}
}

func TestReleaseWorkflowPublishesPrebuiltAssets(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"tags:",
		"'v*'",
		"GOOS=\"$GOOS\"",
		"GOARCH=\"$GOARCH\"",
		"jp-pii-detect_${GOOS}_${GOARCH}",
		"go test ./...",
		"gh release create",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("release workflow missing %q:\n%s", want, text)
		}
	}
}

func TestReadmeDocumentsTagPinnedInstaller(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "main/scripts/install.sh | sh") {
		t.Fatalf("README should not recommend executing the mutable main installer URL")
	}
	if !strings.Contains(text, "v0.1.8/scripts/install.sh") || !strings.Contains(text, "JP_PII_DETECT_VERSION=v0.1.8") {
		t.Fatalf("README should show a tag-pinned installer URL and matching binary version")
	}
}

// homebrewTemplatePlaceholders はテンプレートとリリースワークフローの両方が
// 参照するプレースホルダ。片方だけ変更すると formula が壊れるため一覧で固定する。
var homebrewTemplatePlaceholders = []string{
	"{{VERSION}}",
	"{{TAG}}",
	"{{SHA256_DARWIN_ARM64}}",
	"{{SHA256_DARWIN_AMD64}}",
	"{{SHA256_LINUX_ARM64}}",
	"{{SHA256_LINUX_AMD64}}",
}

func renderHomebrewFormula(t *testing.T, tmpl, version, tag string) string {
	t.Helper()
	r := strings.NewReplacer(
		"{{VERSION}}", version,
		"{{TAG}}", tag,
		"{{SHA256_DARWIN_ARM64}}", "1111111111111111111111111111111111111111111111111111111111111111",
		"{{SHA256_DARWIN_AMD64}}", "2222222222222222222222222222222222222222222222222222222222222222",
		"{{SHA256_LINUX_ARM64}}", "3333333333333333333333333333333333333333333333333333333333333333",
		"{{SHA256_LINUX_AMD64}}", "4444444444444444444444444444444444444444444444444444444444444444",
	)
	return r.Replace(tmpl)
}

func TestHomebrewTemplateRendersPrebuiltBinaryFormula(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "jp-pii-detect.rb.tmpl"))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := string(data)

	// テンプレート単体では全プレースホルダが存在しているべき。
	for _, p := range homebrewTemplatePlaceholders {
		if !strings.Contains(tmpl, p) {
			t.Fatalf("formula template missing placeholder %s", p)
		}
	}

	const tag = "v9.9.9"
	rendered := renderHomebrewFormula(t, tmpl, strings.TrimPrefix(tag, "v"), tag)

	// 埋めたあとはプレースホルダが残っていてはいけない。
	if strings.Contains(rendered, "{{") {
		t.Fatalf("rendered formula still contains a placeholder:\n%s", rendered)
	}

	wants := []string{
		"class JpPiiDetect < Formula",
		`version "9.9.9"`,
		`bin.install "jp-pii-detect"`,
		`shell_output("#{bin}/jp-pii-detect version")`,
		"on_macos do",
		"on_linux do",
	}
	for _, w := range wants {
		if !strings.Contains(rendered, w) {
			t.Fatalf("rendered formula missing %q:\n%s", w, rendered)
		}
	}

	// プレースホルダ版ではなく、Go のリリースアセット 4 種を tag 付き URL で指す。
	for _, asset := range []string{
		"jp-pii-detect_darwin_arm64.tar.gz",
		"jp-pii-detect_darwin_amd64.tar.gz",
		"jp-pii-detect_linux_arm64.tar.gz",
		"jp-pii-detect_linux_amd64.tar.gz",
	} {
		url := "https://github.com/baneido/jp-pii-detector/releases/download/" + tag + "/" + asset
		if !strings.Contains(rendered, url) {
			t.Fatalf("rendered formula missing asset URL %q:\n%s", url, rendered)
		}
	}

	// ソースからビルドしない（Go 不要の方針）。
	for _, forbidden := range []string{"depends_on", "go build", "go install"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("prebuilt-binary formula should not contain %q:\n%s", forbidden, rendered)
		}
	}
}

func TestReleaseWorkflowUpdatesHomebrewTap(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"needs: release",
		"secrets.TAP_GITHUB_TOKEN",
		"github.com/baneido/homebrew-tap.git",
		"tap/Formula/jp-pii-detect.rb",
		"scripts/jp-pii-detect.rb.tmpl",
		// tap の main はレビュー必須のため直接 push せず PR を作る。
		"gh pr create --repo baneido/homebrew-tap",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("release workflow homebrew job missing %q", want)
		}
	}
	// ワークフローはテンプレートと同じプレースホルダを sed で埋める。
	for _, p := range homebrewTemplatePlaceholders {
		if !strings.Contains(text, p) {
			t.Fatalf("release workflow does not substitute placeholder %s", p)
		}
	}
}

func TestReadmeDocumentsHomebrewInstall(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "brew install baneido/tap/jp-pii-detect") {
		t.Fatalf("README should document the Homebrew install command")
	}
}
