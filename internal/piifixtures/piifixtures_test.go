package piifixtures

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCaseTagsRoundTrip は issue #42 の対応方針 1(a) で追加した Case.Tags
// フィールドの読み込みを検証する。Span は陽性期待値専用（rule_id 必須）のため、
// Want:[] の陰性ケース（FP プローブ等）にタグを付けるには Case 単位の Tags が
// 必要という issue の指摘に対応する変更。
func TestCaseTagsRoundTrip(t *testing.T) {
	raw := `{
		"strings": {},
		"dataset": [
			{
				"line": "ジョブID: 202507000004",
				"want": ["jp-my-number"],
				"tags": ["probe-fp:mynumber-lookalike-job-id"],
				"spans": [
					{"rule_id": "jp-my-number", "start": 6, "end": 18, "tags": ["probe-fp"]}
				]
			},
			{
				"line": "郵便番号 1000001",
				"want": [],
				"tags": ["probe-fn:postal-bare-7digit-no-hyphen", "known-limitation"]
			},
			{
				"line": "no tags here",
				"want": []
			}
		]
	}`

	dir := t.TempDir()
	path := filepath.Join(dir, "pii-fixtures.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvVar, path)

	if !Available() {
		t.Fatal("Available() = false, want true")
	}
	dataset, ok := Dataset()
	if !ok {
		t.Fatal("Dataset() ok = false, want true")
	}
	if len(dataset) != 3 {
		t.Fatalf("len(dataset) = %d, want 3", len(dataset))
	}

	fp := dataset[0]
	wantTags := []string{"probe-fp:mynumber-lookalike-job-id"}
	if !equalStrings(fp.Tags, wantTags) {
		t.Errorf("dataset[0].Tags = %v, want %v", fp.Tags, wantTags)
	}
	if len(fp.Spans) != 1 || !equalStrings(fp.Spans[0].Tags, []string{"probe-fp"}) {
		t.Errorf("dataset[0].Spans[0].Tags = %v, want [probe-fp]", fp.Spans[0].Tags)
	}

	fn := dataset[1]
	wantFNTags := []string{"probe-fn:postal-bare-7digit-no-hyphen", "known-limitation"}
	if !equalStrings(fn.Tags, wantFNTags) {
		t.Errorf("dataset[1].Tags = %v, want %v", fn.Tags, wantFNTags)
	}
	if len(fn.Spans) != 0 {
		t.Errorf("dataset[1].Spans = %v, want empty (Want:[] の陰性ケースは Span を持たない)", fn.Spans)
	}

	// 後方互換: tags フィールドが無いケースは nil のまま（既存データセットに影響しない）。
	if dataset[2].Tags != nil {
		t.Errorf("dataset[2].Tags = %v, want nil (tags フィールド省略時)", dataset[2].Tags)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
