package fixturegen_test

import (
	"testing"

	"github.com/baneido/jp-pii-detector/internal/eval"
	"github.com/baneido/jp-pii-detector/internal/fixturegen"
)

// TestGeneratedCasesDetectAsExpected は fixturegen.Generate() が返す合成ケース
// （リテラル PII を含まず checksum/dict から計算合成した値）を、実際の検出
// パイプライン（internal/eval 経由で internal/detect を呼ぶ）に通し、各ルールが
// 期待どおり検出・棄却できることを検証する。JP_PII_FIXTURES（外部データセット）を
// 必要としない自己完結の回帰テストで、表記ゆれのマトリクスに対するルールの
// 頑健性を、外部フィクスチャなしでも継続的に確認できる（Issue #70 の核心）。
func TestGeneratedCasesDetectAsExpected(t *testing.T) {
	cases := fixturegen.Generate()
	if len(cases) == 0 {
		t.Fatal("fixturegen.Generate() returned no cases")
	}

	results, err := eval.EvaluateCases(cases)
	if err != nil {
		t.Fatalf("eval.EvaluateCases(fixturegen.Generate()) error: %v", err)
	}

	targetRules := []string{
		"jp-my-number", "credit-card", "jp-postal-code", "person-name",
		"jp-phone-number", "jp-birthdate", "jp-address", "jp-bank-account",
	}
	found := map[string]eval.Result{}
	for _, r := range results {
		found[r.RuleID] = r
	}
	for _, id := range targetRules {
		r, ok := found[id]
		if !ok {
			t.Errorf("rule %q has no results in the synthetic matrix", id)
			continue
		}
		if r.FN != 0 {
			t.Errorf("rule %q: FN = %d, want 0 (a notational variant went undetected: TP=%d FP=%d FN=%d)",
				id, r.FN, r.TP, r.FP, r.FN)
		}
		if r.FP != 0 {
			t.Errorf("rule %q: FP = %d, want 0 (an expected-negative variant was wrongly detected: TP=%d FP=%d FN=%d)",
				id, r.FP, r.TP, r.FP, r.FN)
		}
		if r.SpanExact.FN != 0 || r.SpanExact.FP != 0 {
			t.Errorf("rule %q: exact span mismatch: TP=%d FP=%d FN=%d",
				id, r.SpanExact.TP, r.SpanExact.FP, r.SpanExact.FN)
		}
		if r.ConfidenceMiss != 0 {
			t.Errorf("rule %q: confidence misses = %d, want 0", id, r.ConfidenceMiss)
		}
	}

	// 他ルールへの意図しない混入（例: 合成カード番号が jp-my-number も誤検出する等）
	// が無いことも確認する。対象外ルールの結果は本来 0 件のはずが、混入があれば
	// FP として出る。
	for id, r := range found {
		isTarget := false
		for _, t := range targetRules {
			if id == t {
				isTarget = true
			}
		}
		if !isTarget && (r.TP+r.FP) > 0 {
			t.Errorf("unexpected cross-rule detections for %q: TP=%d FP=%d (matrix should only touch %v)",
				id, r.TP, r.FP, targetRules)
		}
	}
}
