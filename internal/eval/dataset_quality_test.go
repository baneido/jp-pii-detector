package eval

import (
	"testing"

	"github.com/baneido/jp-pii-detector/internal/nemotron"
	"github.com/baneido/jp-pii-detector/internal/privatecorpus"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// TestDatasetQuality は評価データセット自体の品質を検証する。実測 F1 が
// docs/accuracy.json と一致するだけでは検出できない、データセット側の劣化
// （ルール ID の typo・完全一致の重複ケース・スパン付与の後退・ラベル対応の欠落）を拾う。
//
// 評価コーパスは Nemotron-PII-Japan の抽出で、全ケースが陽性を含む複数行文書である。
// 陰性ケースや diff 形式、CSV/SQL/JSON の構造化ファイルはこのコーパスに無く、
// それらの回帰は公開合成コーパス（internal/publiceval）が担う。
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

	const minPositiveCases = 10
	perRule := map[string]int{}
	for _, rc := range ComputeDatasetStats(cases).PerRule {
		perRule[rc.RuleID] = rc.Cases
	}
	for _, id := range nemotron.CoveredRuleIDs() {
		if perRule[id] < minPositiveCases {
			t.Errorf("ルール %q の陽性ケース数が %d 件（最低 %d 件）", id, perRule[id], minPositiveCases)
		}
	}

	if spanless := SpanlessPositiveCount(cases); spanless != 0 {
		t.Errorf("全陽性にspansが必要です: 未付与の(case, rule)が%d件", spanless)
	}
	for i, c := range cases {
		if c.ID == "" || c.SourceClass == "" {
			t.Errorf("dataset[%d]のidまたはsource_classが空です", i)
		}
	}
}
