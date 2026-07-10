package rule

import "slices"

// NegativeKeywordClass は NegativeContext の語 1 つが、値に対してどの近接判定
// で扱われるかを表す。internal/detect の近接判定ロジック（hasUnitBefore /
// hasUnitAfter / 窓一致）はこの分類だけを見て動作を決めるため、語彙とこの
// 分類は必ずこのファイル内で対にして管理する（語を足しても分類を更新し
// 忘れて黙って Generic 扱いになる、という事故を防ぐ単一の情報源）。
type NegativeKeywordClass int

const (
	// NegativeKeywordGeneric は前後 ±window ルーン以内に存在すれば抑制する
	// 汎用語（伝票・管理番号 等）。位置関係を問わない分、値と無関係な
	// 離れた語にも反応しうるため、肯定文脈が弱いルールには適用しない。
	NegativeKeywordGeneric NegativeKeywordClass = iota
	// NegativeKeywordCurrencyPrefix は値の直前に隣接する通貨記号
	// （¥100 / ￥100 / $100 の ¥ ￥ $）。
	NegativeKeywordCurrencyPrefix
	// NegativeKeywordCurrencySuffix は値の直後に隣接する通貨単位
	// （100円 / 100万 / 100% 等）。
	NegativeKeywordCurrencySuffix
	// NegativeKeywordCounterSuffix は値の直後に隣接する数量カウンタ
	// （100件 / 100人 等）。直後が漢字複合語の場合（件名・名義 等）は
	// カウンタとみなさない境界判定つき（hasUnitAfter の requireBoundary）。
	NegativeKeywordCounterSuffix
	// NegativeKeywordLabelPrefix は値の直前に隣接する採番ラベル
	// （伝票番号 100000000013 の「伝票番号」等）。汎用語と異なり、値に
	// 直接隣接する場合のみ抑制する（離れた位置の「伝票」等では抑制しない）。
	NegativeKeywordLabelPrefix
)

// currencyPrefixWords / currencySuffixWords / counterSuffixWords /
// numberingLabelPrefixes / genericNegativeWords は語彙そのもの。
// digitRuleNegativeContext（既存 4 ルール用）と
// digitRuleUnitAdjacentNegativeContext（my-number 等 5 ルール用）は
// これらを組み合わせて構成する。
var (
	// currencyPrefixWords は値の直前に付く通貨記号。
	currencyPrefixWords = []string{"¥", "￥", "$"}
	// currencySuffixWords は値の直後に付く通貨単位・比率単位。
	currencySuffixWords = []string{"円", "千", "万", "億", "%", "％"}
	// counterSuffixWords は値の直後に付く数量カウンタ。
	counterSuffixWords = []string{"人", "名", "件", "個", "回", "点"}
	// numberingLabelPrefixes は値の直前に付く採番ラベル。hasUnitBefore と
	// 同型の「数字直前隣接」判定でのみ効き、窓全体の汎用一致にはしない
	// （「マイナンバー: …を伝票に転記」のように離れているだけでは抑制しない）。
	numberingLabelPrefixes = []string{
		"伝票番号", "受付番号", "予約番号", "ビルド番号", "シリアル番号",
		"ジョブ", "型番", "品番", "図面", "追跡番号",
	}
	// genericNegativeWords は前後 ±window ルーン以内であれば位置を問わず
	// 抑制する汎用語。既存 4 ルール（jp-drivers-license 等）専用。
	//
	// 注: "no." や "#" は採番ラベルだが、肯定文脈（口座・免許 等）が既に必須の
	// ため FP 抑制効果は薄く、"license no." のような正規ラベルを誤って棄却する
	// 副作用が大きいため除外している。
	genericNegativeWords = []string{"注文", "伝票", "管理番号", "通し番号", "連番"}
)

// digitRuleNegativeContext は jp-drivers-license / jp-pension-number /
// jp-bank-account / jp-health-insurance 向けの語彙（通貨・カウンタクラス +
// 汎用窓語）。これらのルールは肯定文脈（RequireContext）が既に必須のため、
// 汎用窓語による誤抑制のリスクが小さい。
var digitRuleNegativeContext = concatNegativeWords(
	currencyPrefixWords, currencySuffixWords, counterSuffixWords, genericNegativeWords,
)

// digitRuleUnitAdjacentNegativeContext は jp-my-number / credit-card /
// jp-postal-code / jp-passport / jp-residence-card 向けの語彙（通貨・カウンタ・
// 採番ラベル接頭クラスのみ。汎用窓語は含まない）。
//
// これらのルールは my-number / credit-card のように肯定文脈が必須でない
// （近傍に語が無くても検出する）ものを含むため、汎用窓語（注文・伝票・
// 管理番号 等）まで適用すると「カード番号 … で注文」「マイナンバー … を
// 伝票に転記」のような正当な検出まで抑制してしまう（実測 FN）。値に直接
// 隣接する単位・ラベルのみで判定することで、この FN を避けつつ
// 「売上は 4242... 円」「伝票番号 100000000013」のような FP を防ぐ。
var digitRuleUnitAdjacentNegativeContext = concatNegativeWords(
	currencyPrefixWords, currencySuffixWords, counterSuffixWords, numberingLabelPrefixes,
)

func concatNegativeWords(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// ClassifyNegativeKeyword は NegativeContext の語 kw が上記のどの近接判定
// クラスに属するかを返す。internal/detect はこの分類だけを見て
// hasUnitBefore / hasUnitAfter / 窓一致のいずれを使うか決める。
func ClassifyNegativeKeyword(kw string) NegativeKeywordClass {
	switch {
	case slices.Contains(currencyPrefixWords, kw):
		return NegativeKeywordCurrencyPrefix
	case slices.Contains(currencySuffixWords, kw):
		return NegativeKeywordCurrencySuffix
	case slices.Contains(counterSuffixWords, kw):
		return NegativeKeywordCounterSuffix
	case slices.Contains(numberingLabelPrefixes, kw):
		return NegativeKeywordLabelPrefix
	default:
		return NegativeKeywordGeneric
	}
}
