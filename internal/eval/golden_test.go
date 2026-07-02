package eval

import (
	"path/filepath"
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

func TestBuildGoldenSortsRulesAndFillsAggregates(t *testing.T) {
	results := sampleResults()
	g := BuildGolden(results, 3)

	if len(g.Rules) != 2 {
		t.Fatalf("len(Rules) = %d, want 2", len(g.Rules))
	}
	// jp-address < email-address のはずが、辞書順は "email-address" < "jp-address"。
	if g.Rules[0].RuleID != "email-address" || g.Rules[1].RuleID != "jp-address" {
		t.Fatalf("Rules order = [%s, %s], want sorted by rule id",
			g.Rules[0].RuleID, g.Rules[1].RuleID)
	}
	if g.Rules[1].Row.FN != 1 {
		t.Fatalf("jp-address row FN = %d, want 1", g.Rules[1].Row.FN)
	}

	wantMicro := Micro(results)
	if g.Micro.TP != wantMicro.TP || g.Micro.F1 != wantMicro.F1 {
		t.Fatalf("Micro = %+v, want TP:%d F1:%.6f", g.Micro, wantMicro.TP, wantMicro.F1)
	}
	if g.DatasetQuality.SpanlessPositiveCount != 3 {
		t.Fatalf("SpanlessPositiveCount = %d, want 3", g.DatasetQuality.SpanlessPositiveCount)
	}
}

func TestSaveGoldenLoadGoldenRoundTrips(t *testing.T) {
	g := BuildGolden(sampleResults(), 5)
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
	want := BuildGolden(sampleResults(), 3)
	results := sampleResults()
	results[0].TP = 999 // 実測がドリフトしたことを模す
	got := BuildGolden(results, 3)

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
	want := BuildGolden(results[:1], 0) // email-address のみ
	got := BuildGolden(results[1:], 0)  // jp-address のみ

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
	got := BuildGolden(results, 1)
	want := BuildGolden(results, 999)

	if diffs := DiffGolden(got, want); len(diffs) != 0 {
		t.Fatalf("DiffGolden compared DatasetQuality, which TestDatasetQuality owns: %v", diffs)
	}
}

func TestComputeDatasetStatsCountsPositiveNegativeAndSpans(t *testing.T) {
	cases := []Case{
		{Line: "TEL: 090-1234-5678", Want: []string{"jp-phone-number"}},
		{
			Line:  "TEL: 090-1234-5678",
			Want:  []string{"jp-phone-number"},
			Spans: []Span{{RuleID: "jp-phone-number", Start: 5, End: 18}},
		},
		{Line: "memo only, nothing sensitive here"}, // 陰性ケース
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

func containsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
