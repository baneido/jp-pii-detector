package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

// GoldenAuxiliary はF1だけでは見えない誤検出数・陰性母数・信頼度不足。
type GoldenAuxiliary struct {
	Negatives      int `json:"negatives"`
	FindingFP      int `json:"finding_fp"`
	ConfidenceMiss int `json:"confidence_miss"`
}

// GoldenRule は 1 ルール分の行スコア、スパンスコア、補助指標。
type GoldenRule struct {
	RuleID          string          `json:"rule_id"`
	Row             GoldenScore     `json:"row"`
	SpanExact       GoldenScore     `json:"span_exact"`
	SpanContainment GoldenScore     `json:"span_containment"`
	SpanRelaxed     GoldenScore     `json:"span_relaxed"`
	Auxiliary       GoldenAuxiliary `json:"auxiliary"`
}

// GoldenProfile は検出設定を明示した1プロファイル分のゴールデン。
type GoldenProfile struct {
	ID                   string          `json:"id"`
	Description          string          `json:"description"`
	MinConfidence        string          `json:"min_confidence"`
	HighRecall           bool            `json:"high_recall"`
	Rules                []GoldenRule    `json:"rules"`
	Micro                GoldenScore     `json:"micro"`
	MicroSpanExact       GoldenScore     `json:"micro_span_exact"`
	MicroSpanContainment GoldenScore     `json:"micro_span_containment"`
	MicroSpanRelaxed     GoldenScore     `json:"micro_span_relaxed"`
	MacroSpanExact       GoldenScore     `json:"macro_span_exact"`
	MacroSpanContainment GoldenScore     `json:"macro_span_containment"`
	MacroSpanRelaxed     GoldenScore     `json:"macro_span_relaxed"`
	Auxiliary            GoldenAuxiliary `json:"auxiliary"`
}

// GoldenDatasetQuality はデータセット品質ガード用の集計値。件数のみを保持し、
// PII・ケース本文・ハッシュは含めない。
type GoldenDatasetQuality struct {
	// SpanlessPositiveCount は、期待スパンが付いていない陽性 (ケース, ルール) の
	// 組の総数。v2では常に0を要求する。
	SpanlessPositiveCount int `json:"spanless_positive_count"`
}

// Golden は docs/accuracy.json のスキーマ。README バッジ・docs/accuracy.md・
// TestAccuracy の回帰ガードの単一の情報源になる。件数と集計値のみを保持し、
// PII・ケース本文・ハッシュは含めない。
type Golden struct {
	DatasetID      string               `json:"dataset_id,omitempty"`
	Profiles       []GoldenProfile      `json:"profiles"`
	Dataset        DatasetStats         `json:"dataset"`
	DatasetQuality GoldenDatasetQuality `json:"dataset_quality"`
}

// BuildGoldenProfile は1プロファイルの実測値を永続化可能な形へ変換する。
func BuildGoldenProfile(spec ProfileSpec, results []Result) GoldenProfile {
	rules := make([]GoldenRule, 0, len(results))
	for _, r := range results {
		rules = append(rules, GoldenRule{
			RuleID: r.RuleID,
			Row: GoldenScore{
				TP: r.TP, FP: r.FP, FN: r.FN,
				Precision: r.Precision, Recall: r.Recall, F1: r.F1,
			},
			SpanExact:       toGoldenScore(r.SpanExact),
			SpanContainment: toGoldenScore(r.SpanContainment),
			SpanRelaxed:     toGoldenScore(r.SpanRelaxed),
			Auxiliary: GoldenAuxiliary{
				Negatives: r.Negatives, FindingFP: r.FindingFP, ConfidenceMiss: r.ConfidenceMiss,
			},
		})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })

	m := Micro(results)
	return GoldenProfile{
		ID:            spec.ID,
		Description:   spec.Description,
		MinConfidence: spec.Options.MinConfidence,
		HighRecall:    spec.Options.HighRecall,
		Rules:         rules,
		Micro: GoldenScore{
			TP: m.TP, FP: m.FP, FN: m.FN,
			Precision: m.Precision, Recall: m.Recall, F1: m.F1,
		},
		MicroSpanExact:       toGoldenScore(MicroSpanExact(results)),
		MicroSpanContainment: toGoldenScore(MicroSpanContainment(results)),
		MicroSpanRelaxed:     toGoldenScore(MicroSpanRelaxed(results)),
		MacroSpanExact:       toGoldenScore(MacroSpanExact(results)),
		MacroSpanContainment: toGoldenScore(MacroSpanContainment(results)),
		MacroSpanRelaxed:     toGoldenScore(MacroSpanRelaxed(results)),
		Auxiliary: GoldenAuxiliary{
			Negatives: m.Negatives, FindingFP: m.FindingFP, ConfidenceMiss: m.ConfidenceMiss,
		},
	}
}

// BuildGolden は3プロファイルと匿名データセット統計をまとめる。
func BuildGolden(evaluations []ProfileEvaluation, cases []Case, datasetID string) Golden {
	profiles := make([]GoldenProfile, 0, len(evaluations))
	for _, evaluation := range evaluations {
		profiles = append(profiles, BuildGoldenProfile(evaluation.Spec, evaluation.Stratified.Results))
	}
	return Golden{
		DatasetID: datasetID,
		Profiles:  profiles,
		Dataset:   ComputeDatasetStats(cases),
		DatasetQuality: GoldenDatasetQuality{
			SpanlessPositiveCount: SpanlessPositiveCount(cases),
		},
	}
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
// 比較せず、ゼロspan欠落などの絶対条件を専用の TestDatasetQuality が検証する。
func DiffGolden(got, want Golden) []string {
	var diffs []string
	if got.DatasetID != want.DatasetID {
		diffs = append(diffs, fmt.Sprintf("dataset_id: 実測 %q, docs/accuracy.json は %q", got.DatasetID, want.DatasetID))
	}
	gotProfiles := make(map[string]GoldenProfile, len(got.Profiles))
	for _, profile := range got.Profiles {
		gotProfiles[profile.ID] = profile
	}
	wantProfiles := make(map[string]GoldenProfile, len(want.Profiles))
	for _, profile := range want.Profiles {
		wantProfiles[profile.ID] = profile
	}
	for id, wantProfile := range wantProfiles {
		gotProfile, ok := gotProfiles[id]
		if !ok {
			diffs = append(diffs, fmt.Sprintf("profile %q: docs/accuracy.json にあるが実測に存在しない", id))
			continue
		}
		diffs = append(diffs, diffGoldenProfile(gotProfile, wantProfile)...)
	}
	for id := range gotProfiles {
		if _, ok := wantProfiles[id]; !ok {
			diffs = append(diffs, fmt.Sprintf("profile %q: 実測にあるが docs/accuracy.json に存在しない", id))
		}
	}
	if !equalDatasetStats(got.Dataset, want.Dataset) {
		diffs = append(diffs, fmt.Sprintf("dataset: 実測 %+v, docs/accuracy.json は %+v", got.Dataset, want.Dataset))
	}

	sort.Strings(diffs)
	return diffs
}

func diffGoldenProfile(got, want GoldenProfile) []string {
	prefix := "profile " + got.ID
	var diffs []string
	if got.Description != want.Description || got.MinConfidence != want.MinConfidence || got.HighRecall != want.HighRecall {
		diffs = append(diffs, fmt.Sprintf("%s settings: 実測 description=%q min=%q high_recall=%t, goldenは description=%q min=%q high_recall=%t",
			prefix, got.Description, got.MinConfidence, got.HighRecall,
			want.Description, want.MinConfidence, want.HighRecall))
	}
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
			diffs = append(diffs, fmt.Sprintf("%s rule %q: goldenにあるが実測に存在しない", prefix, id))
			continue
		}
		if g != w {
			diffs = append(diffs, fmt.Sprintf("%s rule %q: 実測 %+v, golden %+v（-updateで再生成してください）", prefix, id, g, w))
		}
	}
	for id := range gotByID {
		if _, ok := wantByID[id]; !ok {
			diffs = append(diffs, fmt.Sprintf("%s rule %q: 実測にあるがgoldenに存在しない", prefix, id))
		}
	}
	diffs = append(diffs, diffScore(prefix+" micro", got.Micro, want.Micro)...)
	diffs = append(diffs, diffScore(prefix+" micro_span_exact", got.MicroSpanExact, want.MicroSpanExact)...)
	diffs = append(diffs, diffScore(prefix+" micro_span_containment", got.MicroSpanContainment, want.MicroSpanContainment)...)
	diffs = append(diffs, diffScore(prefix+" micro_span_relaxed", got.MicroSpanRelaxed, want.MicroSpanRelaxed)...)
	diffs = append(diffs, diffScore(prefix+" macro_span_exact", got.MacroSpanExact, want.MacroSpanExact)...)
	diffs = append(diffs, diffScore(prefix+" macro_span_containment", got.MacroSpanContainment, want.MacroSpanContainment)...)
	diffs = append(diffs, diffScore(prefix+" macro_span_relaxed", got.MacroSpanRelaxed, want.MacroSpanRelaxed)...)
	if got.Auxiliary != want.Auxiliary {
		diffs = append(diffs, fmt.Sprintf("%s auxiliary: 実測 %+v, golden %+v", prefix, got.Auxiliary, want.Auxiliary))
	}
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

// DatasetDimensionCount は入力種別・ファイル形式・source class別の匿名件数。
type DatasetDimensionCount struct {
	Name  string `json:"name"`
	Cases int    `json:"cases"`
}

// DatasetStats は評価データセットの匿名統計。総ケース数・陽性/陰性内訳・
// ルール別件数・スパン付与状況を、PII やケース本文を含まない件数だけで表す。
type DatasetStats struct {
	TotalCases         int                     `json:"total_cases"`
	PositiveCases      int                     `json:"positive_cases"`
	NegativeCases      int                     `json:"negative_cases"`
	SpanAnnotatedCases int                     `json:"span_annotated_cases"`
	PerRule            []RuleCaseCount         `json:"per_rule"`
	PerKind            []DatasetDimensionCount `json:"per_kind"`
	PerFormat          []DatasetDimensionCount `json:"per_format"`
	PerSourceClass     []DatasetDimensionCount `json:"per_source_class"`
}

func equalDatasetStats(a, b DatasetStats) bool {
	if a.TotalCases != b.TotalCases || a.PositiveCases != b.PositiveCases ||
		a.NegativeCases != b.NegativeCases || a.SpanAnnotatedCases != b.SpanAnnotatedCases ||
		len(a.PerRule) != len(b.PerRule) ||
		!equalDimensionCounts(a.PerKind, b.PerKind) ||
		!equalDimensionCounts(a.PerFormat, b.PerFormat) ||
		!equalDimensionCounts(a.PerSourceClass, b.PerSourceClass) {
		return false
	}
	for i := range a.PerRule {
		if a.PerRule[i] != b.PerRule[i] {
			return false
		}
	}
	return true
}

func equalDimensionCounts(a, b []DatasetDimensionCount) bool {
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

// ComputeDatasetStats はケース集合から DatasetStats を計算する。
func ComputeDatasetStats(cases []Case) DatasetStats {
	stats := DatasetStats{TotalCases: len(cases)}
	perRule := map[string]int{}
	perKind := map[string]int{}
	perFormat := map[string]int{}
	perSourceClass := map[string]int{}
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
		perKind[caseKind(c)]++
		format := strings.TrimPrefix(strings.ToLower(filepath.Ext(c.File)), ".")
		if format == "" {
			format = "unspecified"
		}
		perFormat[format]++
		sourceClass := c.SourceClass
		if sourceClass == "" {
			sourceClass = "unspecified"
		}
		perSourceClass[sourceClass]++
	}
	ruleIDs := make([]string, 0, len(perRule))
	for id := range perRule {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	for _, id := range ruleIDs {
		stats.PerRule = append(stats.PerRule, RuleCaseCount{RuleID: id, Cases: perRule[id]})
	}
	stats.PerKind = dimensionCounts(perKind)
	stats.PerFormat = dimensionCounts(perFormat)
	stats.PerSourceClass = dimensionCounts(perSourceClass)
	return stats
}

func dimensionCounts(counts map[string]int) []DatasetDimensionCount {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]DatasetDimensionCount, 0, len(keys))
	for _, key := range keys {
		out = append(out, DatasetDimensionCount{Name: key, Cases: counts[key]})
	}
	return out
}

// SpanlessPositiveCount は、期待スパンが付いていない陽性 (ケース, ルール) の組の
// 総数を返す。v2では TestDatasetQuality が0を必須にする。
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
		// IDはケース内容の安定参照用であり、異なるIDを付けただけの重複を
		// 見逃さないよう内容比較から除く。
		content := c
		content.ID = ""
		b, err := json.Marshal(content)
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
