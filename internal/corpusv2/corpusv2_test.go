package corpusv2

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

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

func TestUpgradePublishedV2AddsEAIAndConfusableCoverageIdempotently(t *testing.T) {
	complete, _, err := Build([]evalcase.Case{{
		ID: "legacy-negative-1", SourceClass: "legacy-curated", Line: "識別情報を含まない行",
	}})
	if err != nil {
		t.Fatal(err)
	}
	var base []evalcase.Case
	hardNegatives := 0
	for _, c := range complete {
		if c.SourceClass == "hard-negative" {
			hardNegatives++
		}
		remove := false
		for _, id := range c.Want {
			remove = remove || id == "email-address-eai" || id == "email-address-confusable"
		}
		if !remove {
			base = append(base, c)
		}
	}
	got, err := UpgradePublishedV2(base)
	if err != nil {
		t.Fatal(err)
	}
	counts := positiveCounts(got)
	if counts["email-address-eai"] != MinPositiveCasesPerRule ||
		counts["email-address-confusable"] != MinPositiveCasesPerRule ||
		len(got) != len(base)+2*MinPositiveCasesPerRule {
		t.Fatalf("missing coverage was not supplemented: counts=%v len=%d base=%d", counts, len(got), len(base))
	}
	gotHardNegatives := 0
	for _, c := range got {
		if c.SourceClass == "hard-negative" {
			gotHardNegatives++
		}
	}
	if gotHardNegatives != hardNegatives {
		t.Fatalf("hard negatives = %d, want unchanged %d", gotHardNegatives, hardNegatives)
	}
	again, err := UpgradePublishedV2(got)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, got) {
		t.Fatal("UpgradePublishedV2 must be idempotent after filling missing coverage")
	}
}

func TestHardNegativePANsAreTheExplicitKnownTestSet(t *testing.T) {
	seen := map[string]bool{}
	for _, pan := range wellKnownTestPANs() {
		if seen[pan] || !checksum.Luhn(pan) || !checksum.KnownTestPAN(pan) || checksum.CreditCard(pan) {
			t.Fatalf("公知テストPAN集合に重複または構造不正な値がある")
		}
		seen[pan] = true
	}
	if len(seen) != 5 {
		t.Fatalf("known test PAN count = %d, want 5", len(seen))
	}
}

func TestUpgradePublishedV2ReclassifiesKnownTestPANAndRefillsCoverage(t *testing.T) {
	pan := strings.Join([]string{"4242", "4242", "4242", "4242"}, "")
	prefix := "カード番号: "
	base := []evalcase.Case{{
		ID: "legacy-test-pan", SourceClass: "legacy-curated", Line: prefix + pan,
		Want: []string{"credit-card"},
		Spans: []evalcase.Span{{
			RuleID: "credit-card", Line: 1,
			Start: utf8.RuneCountInString(prefix), End: utf8.RuneCountInString(prefix) + len(pan),
		}},
	}}
	wantInput := cloneCases(base)

	got, err := UpgradePublishedV2(base)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(base, wantInput) {
		t.Fatal("UpgradePublishedV2 が入力を変更した")
	}
	if len(got[0].Want) != 0 || len(got[0].Spans) != 0 || !hasTag(got[0].Tags, "polarity:negative") {
		t.Fatalf("公知テストPANが陰性へ再分類されていない: %+v", got[0])
	}
	if n := positiveCounts(got)["credit-card"]; n < MinPositiveCasesPerRule {
		t.Fatalf("credit-card positives = %d, want >= %d", n, MinPositiveCasesPerRule)
	}
	if len(got) <= len(base) {
		t.Fatal("不足した陽性カバレッジが補完されていない")
	}
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
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
