package rule

import (
	"slices"
	"testing"
)

// ClassifyNegativeKeyword は internal/detect の近接判定（hasUnitBefore /
// hasUnitAfter / 窓一致）を単一の情報源から駆動する分類器。語彙リスト
// （currencyPrefixWords 等、本パッケージの negative_context.go）とこの
// テストが対で管理されるべきで、語を足したのに分類が漏れる事故を防ぐ。
func TestClassifyNegativeKeyword(t *testing.T) {
	tests := []struct {
		kw   string
		want NegativeKeywordClass
	}{
		{"¥", NegativeKeywordCurrencyPrefix},
		{"￥", NegativeKeywordCurrencyPrefix},
		{"$", NegativeKeywordCurrencyPrefix},
		{"円", NegativeKeywordCurrencySuffix},
		{"千", NegativeKeywordCurrencySuffix},
		{"万", NegativeKeywordCurrencySuffix},
		{"億", NegativeKeywordCurrencySuffix},
		{"%", NegativeKeywordCurrencySuffix},
		{"％", NegativeKeywordCurrencySuffix},
		{"人", NegativeKeywordCounterSuffix},
		{"名", NegativeKeywordCounterSuffix},
		{"件", NegativeKeywordCounterSuffix},
		{"個", NegativeKeywordCounterSuffix},
		{"回", NegativeKeywordCounterSuffix},
		{"点", NegativeKeywordCounterSuffix},
		{"伝票番号", NegativeKeywordLabelPrefix},
		{"受付番号", NegativeKeywordLabelPrefix},
		{"予約番号", NegativeKeywordLabelPrefix},
		{"ビルド番号", NegativeKeywordLabelPrefix},
		{"シリアル番号", NegativeKeywordLabelPrefix},
		{"ジョブ", NegativeKeywordLabelPrefix},
		{"型番", NegativeKeywordLabelPrefix},
		{"品番", NegativeKeywordLabelPrefix},
		{"図面", NegativeKeywordLabelPrefix},
		{"追跡番号", NegativeKeywordLabelPrefix},
		{"トランザクション", NegativeKeywordLabelPrefix},
		{"sku", NegativeKeywordLabelPrefix},
		{"version", NegativeKeywordLabelPrefix},
		{"ver", NegativeKeywordLabelPrefix},
		// 汎用窓語（既存 4 ルール専用）。ラベル接頭クラスの語と紛らわしい
		// 「伝票」（≠伝票番号）が誤って LabelPrefix に分類されないことも確認する。
		{"注文", NegativeKeywordGeneric},
		{"伝票", NegativeKeywordGeneric},
		{"管理番号", NegativeKeywordGeneric},
		{"通し番号", NegativeKeywordGeneric},
		{"連番", NegativeKeywordGeneric},
		{"未知の語", NegativeKeywordGeneric},
	}
	for _, tt := range tests {
		t.Run(tt.kw, func(t *testing.T) {
			if got := ClassifyNegativeKeyword(tt.kw); got != tt.want {
				t.Errorf("ClassifyNegativeKeyword(%q) = %v, want %v", tt.kw, got, tt.want)
			}
		})
	}
}

// digitRuleNegativeContext（jp-drivers-license 等）と
// digitRuleUnitAdjacentNegativeContext（jp-my-number 等）で、汎用窓語の
// 混入がないこと・採番ラベル接頭語と通貨接頭語が両方の語彙に含まれることを
// 確認する（P05 の変更対象: 汎用窓語は my-number 等の語彙に適用しない。採番
// ラベル接頭語は値への直接隣接でしか効かない隣接判定限定クラスのため、
// 汎用窓語と異なり両方の語彙に加えても誤爆リスクが小さい）。
func TestDigitRuleNegativeContextVocabSeparation(t *testing.T) {
	for _, w := range genericNegativeWords {
		if !slices.Contains(digitRuleNegativeContext, w) {
			t.Errorf("digitRuleNegativeContext は汎用語 %q を含むべき", w)
		}
		if slices.Contains(digitRuleUnitAdjacentNegativeContext, w) {
			t.Errorf("digitRuleUnitAdjacentNegativeContext は汎用語 %q を含むべきではない", w)
		}
	}
	for _, w := range numberingLabelPrefixes {
		if !slices.Contains(digitRuleUnitAdjacentNegativeContext, w) {
			t.Errorf("digitRuleUnitAdjacentNegativeContext は採番ラベル %q を含むべき", w)
		}
		if !slices.Contains(digitRuleNegativeContext, w) {
			t.Errorf("digitRuleNegativeContext は採番ラベル %q を含むべき", w)
		}
	}
	for _, w := range currencyPrefixWords {
		if !slices.Contains(digitRuleNegativeContext, w) || !slices.Contains(digitRuleUnitAdjacentNegativeContext, w) {
			t.Errorf("通貨接頭語 %q は両方の語彙に含まれるべき", w)
		}
	}
}
