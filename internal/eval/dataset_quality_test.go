package eval

import (
	"testing"

	"github.com/baneido/jp-pii-detector/internal/piifixtures"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// TestDatasetQuality は評価データセット自体の品質を検証する。実測 F1 が
// docs/accuracy.json と一致するだけでは検出できない、データセット側の劣化
// （ルール ID の typo・完全一致の重複ケース・スパン付与の後退）を拾う。
// wantF1 map の撤去で失われた「未知のルール ID の検出」の代替も兼ねる。
func TestDatasetQuality(t *testing.T) {
	piifixtures.Require(t)
	cases, ok := piifixtures.Dataset()
	if !ok {
		t.Fatal("評価データセットを取得できません")
	}

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

	// (c) ルール別の陽性ケース数が少ない場合は警告に留める。既存データセットは
	// ほぼ全ルールで 10 件を下回るため、エラー昇格はデータセット拡充（P07/P27）後に行う。
	const minPositiveCases = 10
	stats := ComputeDatasetStats(cases)
	for _, rc := range stats.PerRule {
		if rc.Cases < minPositiveCases {
			t.Logf("警告: ルール %q の陽性ケース数が %d 件（目安 %d 件未満）", rc.RuleID, rc.Cases, minPositiveCases)
		}
	}

	// (d) スパン未付与の陽性 (ケース, ルール) 組の件数をラチェット監視する。
	// 増加のみエラーにする（減少は -update で docs/accuracy.json へ自動反映される）。
	golden, err := LoadGolden(accuracyJSONPath)
	if err != nil {
		t.Fatalf("docs/accuracy.json を読み込めません: %v（`go test ./internal/eval -run 'TestGenerateDoc|TestReadmeBadges' -update` で生成してください）", err)
	}
	if spanless := SpanlessPositiveCount(cases); SpanlessPositiveIncreased(cases, golden.DatasetQuality.SpanlessPositiveCount) {
		t.Errorf(
			"スパン未付与の陽性件数が増加しました: 実測 %d 件 > docs/accuracy.json の %d 件。"+
				"新しいケースに spans を付与するか、増加が既知・許容できるなら `go test ./internal/eval -run 'TestGenerateDoc|TestReadmeBadges' -update` で docs/accuracy.json を更新してください",
			spanless, golden.DatasetQuality.SpanlessPositiveCount)
	}
}
