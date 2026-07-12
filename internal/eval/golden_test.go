package eval

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func mkScore(tp, fp, fn int) Score {
	s := Score{TP: tp, FP: fp, FN: fn}
	fillScore(&s)
	return s
}

func sampleResults() []Result {
	return []Result{
		{
			RuleID: "email-address",
			TP:     4, FP: 0, FN: 0,
			Precision: 1, Recall: 1, F1: 1,
			SpanExact:   mkScore(1, 0, 0),
			SpanRelaxed: mkScore(1, 0, 0),
		},
		{
			RuleID: "jp-address",
			TP:     4, FP: 0, FN: 1,
			Precision: 1, Recall: 0.8, F1: 0.888888888888889,
			SpanExact:   mkScore(0, 0, 1),
			SpanRelaxed: mkScore(0, 0, 1),
		},
	}
}

func sampleGolden(results []Result, spanless int) Golden {
	return Golden{
		Profiles:       []GoldenProfile{BuildGoldenProfile(ProfileSpec{ID: "low", Options: Options{MinConfidence: "low"}}, results)},
		DatasetQuality: GoldenDatasetQuality{SpanlessPositiveCount: spanless},
	}
}

func TestBuildGoldenSortsRulesAndFillsAggregates(t *testing.T) {
	results := sampleResults()
	g := sampleGolden(results, 3)
	p := g.Profiles[0]

	if len(p.Rules) != 2 {
		t.Fatalf("len(Rules) = %d, want 2", len(p.Rules))
	}
	// jp-address < email-address のはずが、辞書順は "email-address" < "jp-address"。
	if p.Rules[0].RuleID != "email-address" || p.Rules[1].RuleID != "jp-address" {
		t.Fatalf("Rules order = [%s, %s], want sorted by rule id",
			p.Rules[0].RuleID, p.Rules[1].RuleID)
	}
	if p.Rules[1].Row.FN != 1 {
		t.Fatalf("jp-address row FN = %d, want 1", p.Rules[1].Row.FN)
	}

	wantMicro := Micro(results)
	if p.Micro.TP != wantMicro.TP || p.Micro.F1 != wantMicro.F1 {
		t.Fatalf("Micro = %+v, want TP:%d F1:%.6f", p.Micro, wantMicro.TP, wantMicro.F1)
	}
	if g.DatasetQuality.SpanlessPositiveCount != 3 {
		t.Fatalf("SpanlessPositiveCount = %d, want 3", g.DatasetQuality.SpanlessPositiveCount)
	}
}

func TestBuildGoldenPersistsContainmentAndAuxiliaryMetrics(t *testing.T) {
	results := sampleResults()
	results[0].SpanContainment = mkScore(2, 1, 1)
	results[0].Negatives = 70
	results[0].FindingFP = 3
	results[0].ConfidenceMiss = 2
	g := sampleGolden(results, 0)
	p := g.Profiles[0]
	var email GoldenRule
	for _, r := range p.Rules {
		if r.RuleID == "email-address" {
			email = r
		}
	}
	if email.SpanContainment.TP != 2 || email.Auxiliary.FindingFP != 3 || email.Auxiliary.ConfidenceMiss != 2 {
		t.Fatalf("rule metrics not persisted: %+v", email)
	}
	if p.Auxiliary.Negatives != 70 || p.Auxiliary.FindingFP != 3 || p.Auxiliary.ConfidenceMiss != 2 {
		t.Fatalf("profile auxiliary metrics not persisted: %+v", p.Auxiliary)
	}
}

func TestSaveGoldenLoadGoldenRoundTrips(t *testing.T) {
	g := sampleGolden(sampleResults(), 5)
	path := filepath.Join(t.TempDir(), "accuracy.json")

	if err := SaveGolden(path, g); err != nil {
		t.Fatalf("SaveGolden: %v", err)
	}
	got, err := LoadGolden(path)
	if err != nil {
		t.Fatalf("LoadGolden: %v", err)
	}
	if diffs := DiffGolden(got, g); len(diffs) != 0 {
		t.Fatalf("round-tripped golden differs: %v", diffs)
	}
}

func TestLoadGoldenMissingFileReturnsError(t *testing.T) {
	if _, err := LoadGolden(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Fatal("LoadGolden accepted a missing file")
	}
}

func TestDiffGoldenReportsRuleMismatch(t *testing.T) {
	want := sampleGolden(sampleResults(), 3)
	results := sampleResults()
	results[0].TP = 999 // 実測がドリフトしたことを模す
	got := sampleGolden(results, 3)

	diffs := DiffGolden(got, want)
	if len(diffs) == 0 {
		t.Fatal("DiffGolden did not report the TP drift")
	}
	found := false
	for _, d := range diffs {
		if containsAll(d, "email-address") {
			found = true
		}
	}
	if !found {
		t.Fatalf("diffs = %v, want a message mentioning email-address", diffs)
	}
}

func TestDiffGoldenReportsMissingAndExtraRules(t *testing.T) {
	results := sampleResults()
	want := sampleGolden(results[:1], 0) // email-address のみ
	got := sampleGolden(results[1:], 0)  // jp-address のみ

	diffs := DiffGolden(got, want)
	var sawMissing, sawExtra bool
	for _, d := range diffs {
		if containsAll(d, "email-address") {
			sawMissing = true
		}
		if containsAll(d, "jp-address") {
			sawExtra = true
		}
	}
	if !sawMissing || !sawExtra {
		t.Fatalf("diffs = %v, want messages for both the missing and the extra rule", diffs)
	}
}

func TestDiffGoldenIgnoresDatasetQuality(t *testing.T) {
	results := sampleResults()
	got := sampleGolden(results, 1)
	want := sampleGolden(results, 999)

	if diffs := DiffGolden(got, want); len(diffs) != 0 {
		t.Fatalf("DiffGolden compared DatasetQuality, which TestDatasetQuality owns: %v", diffs)
	}
}

func TestDiffGoldenReportsDatasetStatsMismatch(t *testing.T) {
	results := sampleResults()
	spec := ProfileSpec{ID: "low", Options: Options{MinConfidence: "low"}}
	gotCases := []Case{{Line: "positive", Want: []string{"email-address"}}}
	wantCases := []Case{{Line: "negative"}}
	got := BuildGolden([]ProfileEvaluation{{Spec: spec, Stratified: Stratified{Results: results}}}, gotCases, "")
	want := BuildGolden([]ProfileEvaluation{{Spec: spec, Stratified: Stratified{Results: results}}}, wantCases, "")

	diffs := DiffGolden(got, want)
	if len(diffs) == 0 || !strings.Contains(strings.Join(diffs, "\n"), "dataset") {
		t.Fatalf("DiffGolden did not report dataset stats drift: %v", diffs)
	}
}

func TestComputeDatasetStatsCountsPositiveNegativeAndSpans(t *testing.T) {
	cases := []Case{
		{File: "input.txt", SourceClass: "legacy", Line: "TEL: 090-1234-5678", Want: []string{"jp-phone-number"}},
		{
			File: "input.csv", SourceClass: "generated", Content: "TEL: 090-1234-5678",
			Want: []string{"jp-phone-number"}, Spans: []Span{{RuleID: "jp-phone-number", Start: 5, End: 18}},
		},
		{File: "input.txt", SourceClass: "legacy", Diff: []DiffLine{{Text: "memo only", Added: true}}}, // 陰性ケース
	}

	stats := ComputeDatasetStats(cases)
	if stats.TotalCases != 3 {
		t.Fatalf("TotalCases = %d, want 3", stats.TotalCases)
	}
	if stats.PositiveCases != 2 {
		t.Fatalf("PositiveCases = %d, want 2", stats.PositiveCases)
	}
	if stats.NegativeCases != 1 {
		t.Fatalf("NegativeCases = %d, want 1", stats.NegativeCases)
	}
	if stats.SpanAnnotatedCases != 1 {
		t.Fatalf("SpanAnnotatedCases = %d, want 1", stats.SpanAnnotatedCases)
	}
	if len(stats.PerRule) != 1 || stats.PerRule[0].RuleID != "jp-phone-number" || stats.PerRule[0].Cases != 2 {
		t.Fatalf("PerRule = %+v, want [{jp-phone-number 2}]", stats.PerRule)
	}
	if !reflect.DeepEqual(stats.PerKind, []DatasetDimensionCount{{Name: "content", Cases: 1}, {Name: "diff", Cases: 1}, {Name: "line", Cases: 1}}) {
		t.Fatalf("PerKind = %+v", stats.PerKind)
	}
	if !reflect.DeepEqual(stats.PerFormat, []DatasetDimensionCount{{Name: "csv", Cases: 1}, {Name: "txt", Cases: 2}}) {
		t.Fatalf("PerFormat = %+v", stats.PerFormat)
	}
	if !reflect.DeepEqual(stats.PerSourceClass, []DatasetDimensionCount{{Name: "generated", Cases: 1}, {Name: "legacy", Cases: 2}}) {
		t.Fatalf("PerSourceClass = %+v", stats.PerSourceClass)
	}
}

func TestSpanlessPositiveCountCountsWantAndSpanRulePairsWithoutASpan(t *testing.T) {
	cases := []Case{
		// Want のみ（スパンなし） → spanless 1 件。
		{Line: "TEL: 090-1234-5678", Want: []string{"jp-phone-number"}},
		// Want と一致するスパンあり → spanless 0 件。
		{
			Line:  "TEL: 090-1234-5678",
			Want:  []string{"jp-phone-number"},
			Spans: []Span{{RuleID: "jp-phone-number", Start: 5, End: 18}},
		},
		// 複数ルールを期待し、片方だけスパンあり → spanless 1 件。
		{
			Content: "memo\n連絡先: taro@gmail.com",
			Want:    []string{"email-address", "jp-address"},
			Spans:   []Span{{RuleID: "email-address", Line: 2, Start: 5, End: 19}},
		},
		// 陰性ケース → 0 件。
		{Line: "memo only"},
	}

	if got := SpanlessPositiveCount(cases); got != 2 {
		t.Fatalf("SpanlessPositiveCount = %d, want 2", got)
	}
}

func TestDatasetQualityProblemsDetectsUnknownIDsAndDuplicatesWithoutLeakingContent(t *testing.T) {
	cases := []Case{
		{ID: "case-1", Line: "private value", Want: []string{"known"}},
		{ID: "case-2", Line: "private value", Want: []string{"known"}},
		{Line: "another private value", Spans: []Span{{RuleID: "typo", Start: 0, End: 1}}},
	}
	problems := DatasetQualityProblems(cases, map[string]bool{"known": true})
	joined := strings.Join(problems, "\n")
	if !containsAll(joined, "完全に重複", "未知のルール ID") {
		t.Fatalf("problems = %v", problems)
	}
	if strings.Contains(joined, "private value") {
		t.Fatalf("エラーにケース本文が漏れています: %s", joined)
	}
}

func containsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
