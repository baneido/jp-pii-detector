package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/detect"
)

// sample はテスト用の検出結果 1 件を返す。Fingerprint は実際の検出値の形式に
// 依存しないため、PII らしくないダミー文字列で十分（fixture 不要）。
func sample(ruleID, file, match string) detect.Finding {
	return detect.Finding{RuleID: ruleID, File: file, Line: 4, Column: 6, Match: match}
}

func TestFingerprintStable(t *testing.T) {
	a := Fingerprint("salt1", "jp-phone-number", "app/users.csv", "dummy-value-1")
	b := Fingerprint("salt1", "jp-phone-number", "app/users.csv", "dummy-value-1")
	if a != b {
		t.Fatalf("fingerprint not stable: %q != %q", a, b)
	}
	if a == "" {
		t.Fatal("fingerprint is empty")
	}
}

// 行番号は Fingerprint の入力に含まれないため、同じ (rule, file, match) の
// finding が別の行に移動しても fingerprint は変わらない。
func TestFindingFingerprintLineIndependent(t *testing.T) {
	f1 := sample("jp-phone-number", "app/users.csv", "dummy-value-1")
	f2 := f1
	f2.Line = 999
	f2.Column = 1
	if FindingFingerprint("salt1", f1) != FindingFingerprint("salt1", f2) {
		t.Fatal("fingerprint should be independent of line/column")
	}
}

func TestFingerprintChangesWithInputs(t *testing.T) {
	base := Fingerprint("salt1", "jp-phone-number", "app/users.csv", "dummy-value-1")
	cases := map[string]string{
		"rule changed":  Fingerprint("salt1", "jp-my-number", "app/users.csv", "dummy-value-1"),
		"file changed":  Fingerprint("salt1", "jp-phone-number", "app/other.csv", "dummy-value-1"),
		"value changed": Fingerprint("salt1", "jp-phone-number", "app/users.csv", "dummy-value-2"),
		"salt changed":  Fingerprint("salt2", "jp-phone-number", "app/users.csv", "dummy-value-1"),
	}
	for name, got := range cases {
		if got == base {
			t.Errorf("%s: fingerprint unexpectedly unchanged", name)
		}
	}
}

// ハイフン結合のような単純な文字列連結だと "a"+"bc" と "ab"+"c" が衝突しうる
// ケースでも、区切りに \x00 を挟むことで区別できることを確認する。
func TestFingerprintSeparatorAvoidsAmbiguity(t *testing.T) {
	a := Fingerprint("salt", "ruleA", "fileB", "valueC")
	b := Fingerprint("salt", "ruleAf", "ileB", "valueC") // "ruleA"+"fileB" 相当の別分割
	if a == b {
		t.Fatal("differently-segmented inputs should not collide")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	bf := &File{
		Version: CurrentVersion,
		Salt:    "test-salt",
		Entries: []Entry{{Fingerprint: "abc123"}, {Fingerprint: "def456"}},
	}
	if err := Save(path, bf); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != bf.Version || got.Salt != bf.Salt || len(got.Entries) != len(bf.Entries) {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if got.Entries[0].Fingerprint != "abc123" || got.Entries[1].Fingerprint != "def456" {
		t.Fatalf("entries mismatch: %+v", got.Entries)
	}

	// 保存されたファイルが安定した JSON スキーマ（バージョン管理された
	// フィールド名）であることも確認する。
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "salt", "entries"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("missing top-level key %q in saved JSON: %s", key, raw)
		}
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nonexistent.json"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !IsNotExist(err) {
		t.Fatalf("expected IsNotExist(err) to be true, got err = %v", err)
	}
}

func TestLoadCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for corrupt JSON")
	}
	if IsNotExist(err) {
		t.Fatal("corrupt JSON should not be classified as not-exist")
	}
}

func TestLoadUnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, []byte(`{"version":99,"salt":"x","entries":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestLoadMissingSalt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"entries":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing salt")
	}
}

func TestNewSaltIsRandomAndHex(t *testing.T) {
	a, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two generated salts should not be equal")
	}
	if len(a) != 32 { // 16 bytes hex-encoded
		t.Errorf("salt length = %d, want 32", len(a))
	}
}

func TestFromFindingsGeneratesSaltWhenEmpty(t *testing.T) {
	findings := []detect.Finding{sample("jp-phone-number", "app/users.csv", "dummy-value-1")}
	bf, err := FromFindings(findings, "")
	if err != nil {
		t.Fatal(err)
	}
	if bf.Salt == "" {
		t.Fatal("expected auto-generated salt")
	}
	if bf.Version != CurrentVersion {
		t.Errorf("version = %d, want %d", bf.Version, CurrentVersion)
	}
	if len(bf.Entries) != 1 {
		t.Fatalf("entries = %v, want 1", bf.Entries)
	}
}

func TestFromFindingsDeduplicates(t *testing.T) {
	findings := []detect.Finding{
		sample("jp-phone-number", "app/users.csv", "dummy-value-1"),
		sample("jp-phone-number", "app/users.csv", "dummy-value-1"), // 同一値の重複（別行想定）
	}
	bf, err := FromFindings(findings, "fixed-salt")
	if err != nil {
		t.Fatal(err)
	}
	if len(bf.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (deduplicated)", len(bf.Entries))
	}
}

func TestMergeAppendsWithoutDuplicating(t *testing.T) {
	bf := &File{Version: CurrentVersion, Salt: "fixed-salt"}
	Merge(bf, []detect.Finding{sample("jp-phone-number", "app/users.csv", "dummy-value-1")})
	if len(bf.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(bf.Entries))
	}
	// 同じ finding を再度 merge しても増えない。
	Merge(bf, []detect.Finding{sample("jp-phone-number", "app/users.csv", "dummy-value-1")})
	if len(bf.Entries) != 1 {
		t.Fatalf("entries after re-merge = %d, want 1 (no duplicate)", len(bf.Entries))
	}
	// 新規 finding は追記される。
	Merge(bf, []detect.Finding{sample("email-address", "app/users.csv", "dummy-value-2")})
	if len(bf.Entries) != 2 {
		t.Fatalf("entries after new merge = %d, want 2", len(bf.Entries))
	}
}

// TestFilterSuppressesKnownFindings は「既知の finding」= 前提の positive ケース。
func TestFilterSuppressesKnownFindings(t *testing.T) {
	known := sample("jp-phone-number", "app/users.csv", "dummy-value-1")
	bf, err := FromFindings([]detect.Finding{known}, "fixed-salt")
	if err != nil {
		t.Fatal(err)
	}
	kept, baselined := Filter([]detect.Finding{known}, bf)
	if len(kept) != 0 {
		t.Errorf("kept = %v, want empty (known finding should be baselined)", kept)
	}
	if len(baselined) != 1 {
		t.Fatalf("baselined = %v, want 1", baselined)
	}
}

// TestFilterKeepsNewFindings は「新規に追加された finding」= negative ケース。
func TestFilterKeepsNewFindings(t *testing.T) {
	known := sample("jp-phone-number", "app/users.csv", "dummy-value-1")
	bf, err := FromFindings([]detect.Finding{known}, "fixed-salt")
	if err != nil {
		t.Fatal(err)
	}
	newFinding := sample("email-address", "app/users.csv", "dummy-value-2")
	kept, baselined := Filter([]detect.Finding{known, newFinding}, bf)
	if len(kept) != 1 || kept[0].RuleID != "email-address" {
		t.Fatalf("kept = %v, want only the new finding", kept)
	}
	if len(baselined) != 1 {
		t.Fatalf("baselined = %v, want 1", baselined)
	}
}

// TestFilterValueChangeStillFires は「baseline 済みだった値が実際に変わった」
// ケース: fingerprint が値に依存するため、1 文字でも変われば新規扱いになる。
func TestFilterValueChangeStillFires(t *testing.T) {
	original := sample("jp-phone-number", "app/users.csv", "dummy-value-1")
	bf, err := FromFindings([]detect.Finding{original}, "fixed-salt")
	if err != nil {
		t.Fatal(err)
	}
	changed := sample("jp-phone-number", "app/users.csv", "dummy-value-1-changed")
	kept, baselined := Filter([]detect.Finding{changed}, bf)
	if len(kept) != 1 {
		t.Fatalf("kept = %v, want the changed finding to be reported", kept)
	}
	if len(baselined) != 0 {
		t.Fatalf("baselined = %v, want empty", baselined)
	}
}

func TestFilterNilBaselineKeepsAll(t *testing.T) {
	findings := []detect.Finding{sample("jp-phone-number", "app/users.csv", "dummy-value-1")}
	kept, baselined := Filter(findings, nil)
	if len(kept) != 1 || len(baselined) != 0 {
		t.Fatalf("kept=%v baselined=%v, want all kept", kept, baselined)
	}
}

func TestFilterPreservesOrder(t *testing.T) {
	a := sample("jp-phone-number", "app/a.csv", "value-a")
	b := sample("email-address", "app/b.csv", "value-b")
	c := sample("jp-my-number", "app/c.csv", "value-c")
	bf, err := FromFindings([]detect.Finding{b}, "fixed-salt")
	if err != nil {
		t.Fatal(err)
	}
	kept, _ := Filter([]detect.Finding{a, b, c}, bf)
	if len(kept) != 2 || kept[0].RuleID != "jp-phone-number" || kept[1].RuleID != "jp-my-number" {
		t.Fatalf("kept order = %v, want [jp-phone-number, jp-my-number]", ruleIDs(kept))
	}
}

func ruleIDs(fs []detect.Finding) []string {
	ids := make([]string, len(fs))
	for i, f := range fs {
		ids[i] = f.RuleID
	}
	return ids
}
