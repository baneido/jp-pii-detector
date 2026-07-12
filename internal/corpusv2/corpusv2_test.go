package corpusv2

import (
	"reflect"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/checksum"
	"github.com/baneido/jp-pii-detector/internal/evalcase"
)

func TestBuildMeetsV2CoverageContract(t *testing.T) {
	base := []evalcase.Case{{
		ID: "legacy-negative-1", SourceClass: "legacy-curated", Line: "識別情報を含まない行",
	}}
	got, summary, err := Build(base)
	if err != nil {
		t.Fatal(err)
	}
	if summary.SpanlessPairs != 0 || summary.AddedNegatives < 40 {
		t.Fatalf("unexpected quality summary: %+v", summary)
	}
	for _, id := range allRuleIDs() {
		if n := summary.PerRulePositive[id]; n < MinPositiveCasesPerRule {
			t.Errorf("%s positive cases = %d, want >= %d", id, n, MinPositiveCasesPerRule)
		}
	}

	var content, diff, csv, sql, json bool
	for _, c := range got {
		content = content || c.Content != ""
		diff = diff || len(c.Diff) > 0
		csv = csv || strings.HasSuffix(c.File, ".csv")
		sql = sql || strings.HasSuffix(c.File, ".sql")
		json = json || strings.HasSuffix(c.File, ".json")
	}
	if !content || !diff || !csv || !sql || !json {
		t.Fatalf("input coverage: content=%t diff=%t csv=%t sql=%t json=%t", content, diff, csv, sql, json)
	}
	if !reflect.DeepEqual(base, []evalcase.Case{{
		ID: "legacy-negative-1", SourceClass: "legacy-curated", Line: "識別情報を含まない行",
	}}) {
		t.Fatal("Build mutated its input")
	}
}

func TestHardNegativePANsAreTheExplicitKnownTestSet(t *testing.T) {
	seen := map[string]bool{}
	for _, pan := range wellKnownTestPANs() {
		if seen[pan] || !checksum.CreditCard(pan) {
			t.Fatalf("test PAN set contains duplicate or structurally invalid value")
		}
		seen[pan] = true
	}
	if len(seen) != 5 {
		t.Fatalf("known test PAN count = %d, want 5", len(seen))
	}
}

func TestGeneratedDigitsDependDeterministicallyOnPrivateBase(t *testing.T) {
	a := []evalcase.Case{{ID: "a", Line: "private-base-a"}}
	b := []evalcase.Case{{ID: "b", Line: "private-base-b"}}
	seedA := corpusSeed(a)
	if seedA != corpusSeed(a) {
		t.Fatal("same private base produced a different seed")
	}
	if seedA == corpusSeed(b) {
		t.Fatal("different private bases produced the same test seed")
	}
	if digitRun(seedA, 20) == digitRun(corpusSeed(b), 20) {
		t.Fatal("generated digits do not depend on the private base")
	}
}
