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
// digitRuleNegativeContext（jp-drivers-license 等）と
// digitRuleUnitAdjacentNegativeContext（my-number 等）は
// これらを組み合わせて構成する。numberingLabelPrefixes は値への直接隣接
// （internal/detect/negative_context.go の hasLabelBefore）でしか効かない
// 隣接判定限定クラスのため、離れた位置の語では誤爆しない。汎用窓語
// （genericNegativeWords）と異なり、既に RequireContext 前提の
// digitRuleNegativeContext 側に混ぜても副作用が小さいため、両方の語彙に含める。
var (
	// currencyPrefixWords は値の直前に付く通貨記号。
	currencyPrefixWords = []string{"¥", "￥", "$"}
	// currencySuffixWords は値の直後に付く通貨単位・比率単位。
	currencySuffixWords = []string{"円", "千", "万", "億", "%", "％"}
	// counterSuffixWords は値の直後に付く数量カウンタ。
	counterSuffixWords = []string{"人", "名", "件", "個", "回", "点"}
	// numberingLabelPrefixes は値の直前に付く採番ラベル。hasLabelBefore
	// （internal/detect/negative_context.go）の「数字直前隣接」判定でのみ効き、
	// 窓全体の汎用一致にはしない（「マイナンバー: …を伝票に転記」のように
	// 離れているだけでは抑制しない）。hasLabelBefore は空白・タブに加えて、
	// 助詞（は/が/の/を/も）とコロン・イコールを最大 2 個までグルーとして
	// 読み飛ばすため、「ジョブID: …」のような ASCII 語混じりのラベルや
	// 「受付番号は…」のような助詞続きのラベルにも隣接判定が届く。
	// sku/version/ver は ASCII 大小文字を区別せず比較する（"SKU:" も一致）。
	numberingLabelPrefixes = []string{
		"伝票番号", "受付番号", "予約番号", "ビルド番号", "シリアル番号",
		"ジョブ", "型番", "品番", "図面", "追跡番号", "トランザクション",
		"sku", "version", "ver",
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
// jp-bank-account / jp-health-insurance 等向けの語彙（通貨・カウンタ・汎用窓語 +
// 採番ラベル接頭クラス）。これらのルールは肯定文脈（RequireContext）が既に
// 必須のため、汎用窓語による誤抑制のリスクが小さい。numberingLabelPrefixes は
// 値への直接隣接でしか効かない隣接判定限定クラスのため、汎用窓語と違って
// 離れた位置の語では誤爆せず、追加しても同じ理由で安全側に倒れる。
var digitRuleNegativeContext = concatNegativeWords(
	currencyPrefixWords, currencySuffixWords, counterSuffixWords, genericNegativeWords, numberingLabelPrefixes,
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
