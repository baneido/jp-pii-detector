package jppii

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// ダミー値のみを使う。
const dummy = "連絡先 電話番号: 090-1234-5678\nメール: taro@example.com\n" // jp-pii-detector:ignore 架空のテスト値

func TestScanTextFindsDummyPhone(t *testing.T) {
	s, err := NewScanner(Options{ConfigTOML: ptr("")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	res := s.ScanText("<test>", dummy)
	var phone *Finding
	for i := range res.Findings {
		if res.Findings[i].RuleID == "jp-phone-number" {
			phone = &res.Findings[i]
		}
	}
	if phone == nil {
		t.Fatalf("jp-phone-number not found: %+v", res.Findings)
	}
	if phone.Masked() == phone.Match {
		t.Fatalf("Masked must hide the value")
	}
	if got, want := phone.Fingerprint("salt"), Fingerprint("salt", phone.RuleID, phone.RepoPath, phone.Match); got != want {
		t.Fatalf("fingerprint mismatch %s %s", got, want)
	}
}

func TestScanPathsAndConfigTOML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte(dummy), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := "[rules]\ndisabled = [\"jp-phone-number\"]\n"
	s, err := NewScanner(Options{ConfigTOML: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.ScanPaths([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.RuleID == "jp-phone-number" {
			t.Fatalf("disabled rule reported: %+v", f)
		}
	}
	if res.Stats.FilesScanned != 1 {
		t.Fatalf("FilesScanned = %d", res.Stats.FilesScanned)
	}
	var enabled bool
	for _, r := range s.Rules() {
		if r.ID == "jp-phone-number" {
			enabled = r.Enabled
		}
	}
	if enabled {
		t.Fatal("jp-phone-number should be listed as disabled")
	}
}

func TestValidateConfig(t *testing.T) {
	if _, err := ValidateConfig("min_confidence = 1"); err == nil {
		t.Fatal("expected error")
	}
	w, err := ValidateConfig("unknown_key = true")
	if err != nil || len(w) == 0 {
		t.Fatalf("want warning, got %v %v", w, err)
	}
}

func ptr(s string) *string { return &s }

func TestAddedLinesStaged(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile("a.txt", []byte("one\ntwo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "a.txt")
	lines, err := AddedLines(true, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[1].File != "a.txt" || lines[1].Line != 2 || lines[1].Text != "two" {
		t.Fatalf("unexpected %+v", lines)
	}
	s, err := NewScanner(Options{ConfigTOML: ptr("[allowlist]\npaths = [\"^vendor/\"]\nstopwords = [\"dummy\"]\n")})
	if err != nil {
		t.Fatal(err)
	}
	if s.PathAllowed("vendor/x/y.go") || !s.PathAllowed("src/y.go") {
		t.Fatal("PathAllowed")
	}
	if s.ValueAllowed("dummy") || !s.ValueAllowed("other") {
		t.Fatal("ValueAllowed")
	}
}
