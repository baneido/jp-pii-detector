package eval

import (
	"sort"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/privatecorpus"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// TestDatasetQuality は評価データセット自体の品質を検証する。実測 F1 が
// docs/accuracy.json と一致するだけでは検出できない、データセット側の劣化
// （ルール ID の typo・完全一致の重複ケース・スパン付与の後退）を拾う。
// wantF1 map の撤去で失われた「未知のルール ID の検出」の代替も兼ねる。
func TestDatasetQuality(t *testing.T) {
	corpus := privatecorpus.Require(t)
	cases := corpus.Dataset

	knownRules := map[string]bool{}
	for _, r := range rule.Builtin() {
		knownRules[r.ID] = true
	}
	for _, id := range rule.HighRecallRuleIDs() {
		knownRules[id] = true
	}

	for _, problem := range DatasetQualityProblems(cases, knownRules) {
		t.Error(problem)
	}

	// v2の契約: 高再現率を含む全ルールに10件以上の陽性を必須とする。
	const minPositiveCases = 10
	stats := ComputeDatasetStats(cases)
	perRule := map[string]int{}
	for _, rc := range stats.PerRule {
		perRule[rc.RuleID] = rc.Cases
	}
	ids := make([]string, 0, len(knownRules))
	for id := range knownRules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if perRule[id] < minPositiveCases {
			t.Errorf("ルール %q の陽性ケース数が %d 件（最低 %d 件）", id, perRule[id], minPositiveCases)
		}
	}

	if spanless := SpanlessPositiveCount(cases); spanless != 0 {
		t.Errorf("全陽性にspansが必要です: 未付与の(case, rule)が%d件", spanless)
	}

	for i, c := range cases {
		if c.ID == "" {
			t.Errorf("dataset[%d]のidが空です", i)
		}
		if c.SourceClass == "" {
			t.Errorf("dataset[%d]のsource_classが空です", i)
		}
	}

	requireDimension(t, stats.PerKind, map[string]int{"line": 1, "content": 1, "diff": 1})
	requireDimension(t, stats.PerFormat, map[string]int{"csv": 1, "sql": 1, "json": 1})
	requireDimension(t, stats.PerSourceClass, map[string]int{"hard-negative": 40})
	if stats.NegativeCases < 100 {
		t.Errorf("陰性ケース数が%d件です（最低100件）", stats.NegativeCases)
	}
}

func requireDimension(t *testing.T, got []DatasetDimensionCount, minimum map[string]int) {
	t.Helper()
	counts := map[string]int{}
	for _, item := range got {
		counts[item.Name] = item.Cases
	}
	for name, want := range minimum {
		if counts[name] < want {
			t.Errorf("データセット区分 %q が%d件です（最低%d件）", name, counts[name], want)
		}
	}
}
