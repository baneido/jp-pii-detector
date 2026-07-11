package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// GoldenScore は Score のうち docs/accuracy.json へシリアライズする部分。
type GoldenScore struct {
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

func toGoldenScore(s Score) GoldenScore {
	return GoldenScore{TP: s.TP, FP: s.FP, FN: s.FN, Precision: s.Precision, Recall: s.Recall, F1: s.F1}
}

// GoldenRule は 1 ルール分の行スコアとスパンスコア。
type GoldenRule struct {
	RuleID      string      `json:"rule_id"`
	Row         GoldenScore `json:"row"`
	SpanExact   GoldenScore `json:"span_exact"`
	SpanRelaxed GoldenScore `json:"span_relaxed"`
}

// GoldenDatasetQuality はデータセット品質ガード用の集計値。件数のみを保持し、
// PII・ケース本文・ハッシュは含めない。
type GoldenDatasetQuality struct {
	// SpanlessPositiveCount は、期待スパンが付いていない陽性 (ケース, ルール) の
	// 組の総数。TestDatasetQuality がラチェット方式で監視し、増加のみをエラーに
	// する（減少は -update で自動的にこの値へ反映される）。
	SpanlessPositiveCount int `json:"spanless_positive_count"`
}

// Golden は docs/accuracy.json のスキーマ。README バッジ・docs/accuracy.md・
// TestAccuracy の回帰ガードの単一の情報源になる。件数と集計値のみを保持し、
// PII・ケース本文・ハッシュは含めない。
type Golden struct {
	Rules            []GoldenRule         `json:"rules"`
	Micro            GoldenScore          `json:"micro"`
	MicroSpanExact   GoldenScore          `json:"micro_span_exact"`
	MicroSpanRelaxed GoldenScore          `json:"micro_span_relaxed"`
	MacroSpanExact   GoldenScore          `json:"macro_span_exact"`
	MacroSpanRelaxed GoldenScore          `json:"macro_span_relaxed"`
	Dataset          DatasetStats         `json:"dataset"`
	DatasetQuality   GoldenDatasetQuality `json:"dataset_quality"`
}

// BuildGolden は評価結果と、期待スパンなし陽性件数（SpanlessPositiveCount 参照）
// から docs/accuracy.json の内容を組み立てる。
func BuildGolden(results []Result, spanlessPositiveCount int) Golden {
	rules := make([]GoldenRule, 0, len(results))
	for _, r := range results {
		rules = append(rules, GoldenRule{
			RuleID: r.RuleID,
			Row: GoldenScore{
				TP: r.TP, FP: r.FP, FN: r.FN,
				Precision: r.Precision, Recall: r.Recall, F1: r.F1,
			},
			SpanExact:   toGoldenScore(r.SpanExact),
			SpanRelaxed: toGoldenScore(r.SpanRelaxed),
		})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })

	m := Micro(results)
	return Golden{
		Rules: rules,
		Micro: GoldenScore{
			TP: m.TP, FP: m.FP, FN: m.FN,
			Precision: m.Precision, Recall: m.Recall, F1: m.F1,
		},
		MicroSpanExact:   toGoldenScore(MicroSpanExact(results)),
		MicroSpanRelaxed: toGoldenScore(MicroSpanRelaxed(results)),
		MacroSpanExact:   toGoldenScore(MacroSpanExact(results)),
		MacroSpanRelaxed: toGoldenScore(MacroSpanRelaxed(results)),
		DatasetQuality: GoldenDatasetQuality{
			SpanlessPositiveCount: spanlessPositiveCount,
		},
	}
}

// BuildGoldenForCases は実測結果とケース集合から、精度と匿名データセット統計を
// 一度に組み立てる。生成物にはケース本文や PII を含めない。
func BuildGoldenForCases(results []Result, cases []Case) Golden {
	g := BuildGolden(results, SpanlessPositiveCount(cases))
	g.Dataset = ComputeDatasetStats(cases)
	return g
}

// SaveGolden は Golden を整形済み JSON として path へ書き出す。
func SaveGolden(path string, g Golden) error {
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

// LoadGolden は path から docs/accuracy.json 相当の JSON を読み込む。
func LoadGolden(path string) (Golden, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Golden{}, err
	}
	var g Golden
	if err := json.Unmarshal(b, &g); err != nil {
		return Golden{}, fmt.Errorf("%s の解析に失敗しました: %w", path, err)
	}
	return g, nil
}

// DiffGolden は実測（got）とコミット済みゴールデン（want）の精度指標を比較し、
// 不一致を表すメッセージの一覧を返す（一致すれば空）。DatasetQuality はここでは
// 比較しない（ラチェット方式のため専用の検証を TestDatasetQuality が行う）。
func DiffGolden(got, want Golden) []string {
	var diffs []string

	gotByID := make(map[string]GoldenRule, len(got.Rules))
	for _, r := range got.Rules {
		gotByID[r.RuleID] = r
	}
	wantByID := make(map[string]GoldenRule, len(want.Rules))
	for _, r := range want.Rules {
		wantByID[r.RuleID] = r
	}

	for id, w := range wantByID {
		g, ok := gotByID[id]
		if !ok {
			diffs = append(diffs, fmt.Sprintf(
				"%s: docs/accuracy.json に記載があるが実測結果に存在しない（ルールが削除された、または min_confidence=low で発火しなくなった可能性）",
				id))
			continue
		}
		if g != w {
			diffs = append(diffs, fmt.Sprintf(
				"%s: 実測 row=%+v span_exact=%+v span_relaxed=%+v, docs/accuracy.json は row=%+v span_exact=%+v span_relaxed=%+v"+
					"（`go test ./internal/eval -run 'TestGenerateDoc|TestReadmeBadges' -update` で再生成してコミットしてください）",
				id, g.Row, g.SpanExact, g.SpanRelaxed, w.Row, w.SpanExact, w.SpanRelaxed))
		}
	}
	for id := range gotByID {
		if _, ok := wantByID[id]; !ok {
			diffs = append(diffs, fmt.Sprintf(
				"%s: 実測結果にあるが docs/accuracy.json に存在しない（新しいルール。-update で追加してください）", id))
		}
	}

	diffs = append(diffs, diffScore("micro", got.Micro, want.Micro)...)
	diffs = append(diffs, diffScore("micro_span_exact", got.MicroSpanExact, want.MicroSpanExact)...)
	diffs = append(diffs, diffScore("micro_span_relaxed", got.MicroSpanRelaxed, want.MicroSpanRelaxed)...)
	diffs = append(diffs, diffScore("macro_span_exact", got.MacroSpanExact, want.MacroSpanExact)...)
	diffs = append(diffs, diffScore("macro_span_relaxed", got.MacroSpanRelaxed, want.MacroSpanRelaxed)...)
	if !equalDatasetStats(got.Dataset, want.Dataset) {
		diffs = append(diffs, fmt.Sprintf("dataset: 実測 %+v, docs/accuracy.json は %+v", got.Dataset, want.Dataset))
	}

	sort.Strings(diffs)
	return diffs
}

func diffScore(label string, got, want GoldenScore) []string {
	if got == want {
		return nil
	}
	return []string{fmt.Sprintf(
		"%s: 実測 %+v, docs/accuracy.json は %+v（-update で再生成してコミットしてください）",
		label, got, want)}
}

// RuleCaseCount はルール別の陽性ケース数（そのルールが Want または Spans に
// 現れるケースの数）。
type RuleCaseCount struct {
	RuleID string `json:"rule_id"`
	Cases  int    `json:"positive_cases"`
}

// DatasetStats は評価データセットの匿名統計。総ケース数・陽性/陰性内訳・
// ルール別件数・スパン付与状況を、PII やケース本文を含まない件数だけで表す。
type DatasetStats struct {
	TotalCases         int             `json:"total_cases"`
	PositiveCases      int             `json:"positive_cases"`
	NegativeCases      int             `json:"negative_cases"`
	SpanAnnotatedCases int             `json:"span_annotated_cases"`
	PerRule            []RuleCaseCount `json:"per_rule"`
}

func equalDatasetStats(a, b DatasetStats) bool {
	if a.TotalCases != b.TotalCases || a.PositiveCases != b.PositiveCases ||
		a.NegativeCases != b.NegativeCases || a.SpanAnnotatedCases != b.SpanAnnotatedCases ||
		len(a.PerRule) != len(b.PerRule) {
		return false
	}
	for i := range a.PerRule {
		if a.PerRule[i] != b.PerRule[i] {
			return false
		}
	}
	return true
}

// ComputeDatasetStats はケース集合から DatasetStats を計算する。
func ComputeDatasetStats(cases []Case) DatasetStats {
	stats := DatasetStats{TotalCases: len(cases)}
	perRule := map[string]int{}
	for _, c := range cases {
		positive := len(c.Want) > 0 || len(c.Spans) > 0
		if positive {
			stats.PositiveCases++
		} else {
			stats.NegativeCases++
		}
		if len(c.Spans) > 0 {
			stats.SpanAnnotatedCases++
		}
		ids := map[string]bool{}
		for _, id := range c.Want {
			ids[id] = true
		}
		for _, s := range c.Spans {
			ids[s.RuleID] = true
		}
		for id := range ids {
			perRule[id]++
		}
	}
	ruleIDs := make([]string, 0, len(perRule))
	for id := range perRule {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	for _, id := range ruleIDs {
		stats.PerRule = append(stats.PerRule, RuleCaseCount{RuleID: id, Cases: perRule[id]})
	}
	return stats
}

// SpanlessPositiveCount は、期待スパンが付いていない陽性 (ケース, ルール) の組の
// 総数を返す。データセット品質ガード（TestDatasetQuality）のラチェット監視に使う。
func SpanlessPositiveCount(cases []Case) int {
	spanless := 0
	for _, c := range cases {
		hasSpan := map[string]bool{}
		for _, s := range c.Spans {
			hasSpan[s.RuleID] = true
		}
		expected := map[string]bool{}
		for _, id := range c.Want {
			expected[id] = true
		}
		for _, s := range c.Spans {
			expected[s.RuleID] = true
		}
		for id := range expected {
			if !hasSpan[id] {
				spanless++
			}
		}
	}
	return spanless
}

// DatasetQualityProblems は未知ルール ID と完全一致重複を、PII やケース本文を
// エラーへ含めず検出する。外部 fixture 不要の単体テストからも利用できる。
func DatasetQualityProblems(cases []Case, knownRules map[string]bool) []string {
	var problems []string
	seenAt := map[string]int{}
	for i, c := range cases {
		for _, id := range c.Want {
			if !knownRules[id] {
				problems = append(problems, fmt.Sprintf("dataset[%d].want に未知のルール ID %q", i, id))
			}
		}
		for _, s := range c.Spans {
			if !knownRules[s.RuleID] {
				problems = append(problems, fmt.Sprintf("dataset[%d].spans に未知のルール ID %q", i, s.RuleID))
			}
		}
		b, err := json.Marshal(c)
		if err != nil {
			problems = append(problems, fmt.Sprintf("dataset[%d] をシリアライズできません", i))
			continue
		}
		key := string(b)
		if first, duplicate := seenAt[key]; duplicate {
			problems = append(problems, fmt.Sprintf("dataset[%d] は dataset[%d] と完全に重複", i, first))
			continue
		}
		seenAt[key] = i
	}
	return problems
}

// SpanlessPositiveIncreased はスパン未付与陽性のラチェットが後退したかを返す。
func SpanlessPositiveIncreased(cases []Case, maximum int) bool {
	return SpanlessPositiveCount(cases) > maximum
}
