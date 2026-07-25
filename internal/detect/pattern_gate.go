package detect

import (
	"regexp/syntax"
)

// patternGate は 1 パターンの正規表現がマッチするために最低限必要な行の特徴量。
// 正規表現の構文木から「どのマッチ文字列にも必ず含まれる」量の下限を静的に
// 導出したもので、行側の実測値（classifyLine が 1 パスで数える数字の総数・
// 最長連続桁数・CJK 文字の有無）が下限に届かない行では、そのパターンの
// 正規表現評価をまるごとスキップできる（scanLineNoIgnoreWithContext 参照）。
//
// 導出は常に保守側（過小評価）に倒す: 解析できない構文・判断に迷う構文は
// すべて「保証なし（0 / false）」へフォールバックするため、ゲートで
// スキップされるのは「正規表現を実行しても絶対にマッチしない」行だけであり、
// 検出結果は一切変わらない。効果は数字を含む行のホットパス（数字系ルール
// 約 60 パターンの正規表現走査）で大きい: 大半のコード行は数字の総数・
// 連続桁数が電話番号・マイナンバー等の要求（7〜14 桁）に届かないため、
// 正規表現に到達する前に棄却できる。
type patternGate struct {
	// minDigits はマッチ文字列に必ず含まれる ASCII 数字の総数の下限。
	minDigits int
	// minDigitRun はマッチ文字列に必ず含まれる連続 ASCII 数字列の長さの下限。
	minDigitRun int
	// needsCJK はどのマッチ文字列にも CJK 文字（U+3000 以上。classifyLine の
	// hasCJK と同じ閾値）が必ず 1 つ以上含まれることを表す。
	needsCJK bool
}

// skips は行の特徴量がゲートの下限に届かず、このパターンの正規表現評価を
// まるごと省略してよいかを返す。判定を 1 箇所に集約し、走査側
// （scanLineNoIgnoreWithContext）と健全性テストが同じ式を見るようにする。
func (g patternGate) skips(f lineFeatures) bool {
	return g.minDigits > f.digits || g.minDigitRun > f.maxDigitRun || (g.needsCJK && !f.hasCJK)
}

// digitInfo は構文木ノードごとの保証量（そのノードにマッチしうる全文字列に
// わたる最小値）。
type digitInfo struct {
	// digits はマッチに必ず含まれる ASCII 数字の総数の下限。
	digits int
	// run はマッチに必ず含まれる連続数字列長の下限。
	run int
	// cjk はマッチに必ず含まれる CJK 文字（U+3000 以上）数の下限。
	cjk int
	// allDigits は「このノードのあらゆるマッチが ASCII 数字のみから成る
	// （空文字列を含む）」ことを表す。連接時に隣接ノードと連続桁として
	// 結合できるかの判定に使う。
	allDigits bool
}

// gateForPattern は正規表現のソース文字列から patternGate を導出する。
// 解析に失敗した場合はゼロ値（ゲートなし＝常に評価）を返す。
func gateForPattern(src string) patternGate {
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return patternGate{}
	}
	info := analyzeDigits(re)
	return patternGate{
		minDigits:   info.digits,
		minDigitRun: info.run,
		needsCJK:    info.cjk > 0,
	}
}

// epsilonInfo は空文字列にマッチする（かつ文字を消費しない）ノードの保証量。
// allDigits を true にしておくことで、`\d{3}\b\d{4}` のような数字列の途中に
// 置かれた幅ゼロの表明が連続桁の結合を妨げないようにする。
func epsilonInfo() digitInfo { return digitInfo{allDigits: true} }

// analyzeDigits は構文木を再帰的に解析し、各ノードの保証量を返す。
// 未知の構文は digitInfo{}（保証なし）へフォールバックする（保守側）。
func analyzeDigits(re *syntax.Regexp) digitInfo {
	switch re.Op {
	case syntax.OpEmptyMatch,
		syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return epsilonInfo()
	case syntax.OpLiteral:
		return literalInfo(re.Rune)
	case syntax.OpCharClass:
		return charClassInfo(re.Rune)
	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return analyzeDigits(re.Sub[0])
		}
		return digitInfo{}
	case syntax.OpStar, syntax.OpQuest:
		// 0 回の繰り返しがありうるため保証はゼロ。allDigits だけは保存する
		// （数字ノードの任意回繰り返しは何回でも数字のみ）。
		sub := analyzeDigits(re.Sub[0])
		return digitInfo{allDigits: sub.allDigits}
	case syntax.OpPlus:
		// 最低 1 回は出現する。
		sub := analyzeDigits(re.Sub[0])
		return digitInfo{digits: sub.digits, run: sub.run, cjk: sub.cjk, allDigits: sub.allDigits}
	case syntax.OpRepeat:
		sub := analyzeDigits(re.Sub[0])
		if re.Min <= 0 {
			return digitInfo{allDigits: sub.allDigits}
		}
		info := digitInfo{
			digits:    re.Min * sub.digits,
			run:       sub.run,
			cjk:       re.Min * sub.cjk,
			allDigits: sub.allDigits,
		}
		if sub.allDigits {
			// 数字のみのノードの連続繰り返しは、繰り返し間に他の文字が
			// 入らないため連続桁として結合する（例: (?:\d){12} → run 12）。
			info.run = re.Min * sub.digits
		}
		return info
	case syntax.OpConcat:
		return concatInfo(re.Sub)
	case syntax.OpAlternate:
		return alternateInfo(re.Sub)
	}
	// OpAnyChar / OpAnyCharNotNL / OpNoMatch / 未知の Op: 保証なし。
	return digitInfo{}
}

func isASCIIDigit(r rune) bool { return r >= '0' && r <= '9' }

// literalInfo はリテラル文字列の保証量（マッチは常にこの文字列そのもの）。
func literalInfo(runes []rune) digitInfo {
	info := digitInfo{allDigits: true}
	run := 0
	for _, r := range runes {
		switch {
		case isASCIIDigit(r):
			info.digits++
			run++
			if run > info.run {
				info.run = run
			}
		default:
			run = 0
			info.allDigits = false
			if r >= cjkRuneMin {
				info.cjk++
			}
		}
	}
	return info
}

// charClassInfo は文字クラスの保証量。クラス内の全文字が数字なら 1 桁の数字を、
// 全文字が CJK なら CJK 1 文字を保証する。混在クラスは保証なし。
// re.Rune は [lo1, hi1, lo2, hi2, ...] の範囲ペア列。
func charClassInfo(ranges []rune) digitInfo {
	if len(ranges) == 0 {
		return digitInfo{}
	}
	allDigit, allCJK := true, true
	for i := 0; i+1 < len(ranges); i += 2 {
		lo, hi := ranges[i], ranges[i+1]
		if lo < '0' || hi > '9' {
			allDigit = false
		}
		if lo < cjkRuneMin {
			allCJK = false
		}
	}
	switch {
	case allDigit:
		return digitInfo{digits: 1, run: 1, allDigits: true}
	case allCJK:
		return digitInfo{cjk: 1}
	}
	return digitInfo{}
}

// concatInfo は連接の保証量。総数は各ノードの和、連続桁は「数字のみノードの
// 連なり」を結合しつつ最大を取る（数字のみでないノードの内部 run も候補に含める。
// ノード境界をまたぐ部分的な結合（前ノードの末尾数字＋次ノードの先頭数字）は
// 追跡せず 0 とみなす＝保守側）。
func concatInfo(subs []*syntax.Regexp) digitInfo {
	info := digitInfo{allDigits: true}
	joined := 0 // 直前から連続している「数字のみノード」の桁数合計
	for _, sub := range subs {
		si := analyzeDigits(sub)
		info.digits += si.digits
		info.cjk += si.cjk
		if si.allDigits {
			joined += si.digits
			if joined > info.run {
				info.run = joined
			}
		} else {
			joined = 0
			info.allDigits = false
		}
		if si.run > info.run {
			info.run = si.run
		}
	}
	return info
}

// alternateInfo は選択の保証量（どの分岐でも成り立つ量＝各分岐の最小値）。
func alternateInfo(subs []*syntax.Regexp) digitInfo {
	if len(subs) == 0 {
		return digitInfo{}
	}
	info := analyzeDigits(subs[0])
	for _, sub := range subs[1:] {
		si := analyzeDigits(sub)
		info.digits = min(info.digits, si.digits)
		info.run = min(info.run, si.run)
		info.cjk = min(info.cjk, si.cjk)
		info.allDigits = info.allDigits && si.allDigits
	}
	return info
}
