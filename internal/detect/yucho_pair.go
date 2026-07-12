package detect

import (
	"strings"

	"github.com/baneido/jp-pii-detector/internal/normalize"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// scanCrossLineYuchoPairs はフォームでゆうちょ銀行の記号・番号がそれぞれ独立した
// ラベル付きフィールドとして別行に分かれるケース（例:
//
//	記号: 14040
//	番号: 12345671
//
// ）を検出する。internal/rule/builtin.go の jp-yucho-account は同一行の
// ハイフン相関形式・同一行のラベル形式（具体例は同ファイルの
// jp-yucho-account 節のコメント参照。dogfooding での自己検出を避けるため
// ここでは繰り返さない）には対応済みだが、記号・番号が別行に分かれる形式は
// 未対応だった。姓名別行ペア（internal/detect/structured_pair.go の
// scanCrossLineSurnameGivenPairs）と同じ方式で実装する。
//
// scanCrossLineSurnameGivenPairs との違い: あちらは高再現率モード限定
// （単独行の弱いラベル検出が Medium 止まりで、ペアであるという構造的証拠を
// 使えていないケースを補う）だが、こちらは記号・番号ラベルの組という強い構造的
// 手がかりに加え、ValidCrossLineYuchoPair（validYuchoAccount と同一基準の
// 形状検証）まで通した Base High・Validated=true の検出のため、高再現率モードに
// 依存せず既定で有効にする（ScanContent から d.crossLineName の nil ガードの外で
// 呼ぶ）。Base が常に High（Confidence の最大値）のため、
// scanCrossLineSurnameGivenPairs 等にある `rule.Medium < d.minConf` 相当の
// 早期 return（minConf 未満なら走査自体を省略する最適化）はここでは行わない
// （常に false になり意味を持たないため）。
//
// 記号ラベル行 i と、その論理隣接（nextNonBlankIndex、maxAdjacentLineGap。間は
// 空白のみの行を最大 2 行まで挟んでもよい）の番号ラベル行 j を探索する。
// 順序制約: 記号→番号の順のみを対象とする（i を記号ラベル行、その直後の
// 非空白行 j を番号ラベル行としてしか調べないため、逆順のペアは自然に検出
// 対象から外れる。日本語フォームで番号が記号より先に来る表記は、姓名ペアの
// 名→姓の逆順と同様に稀という前提）。
//
// 検証（rule.ValidCrossLineYuchoPair）通過時は、記号の値・番号の値それぞれに
// jp-yucho-account の finding を 1 件ずつ出す（値のマスクが両方の値に効くように
// するため。scanCrossLineSurnameGivenPairs と同じ流儀）。RuleID・Description は
// d.rules から jp-yucho-account の定義を引いて使い、builtin.go の文字列を
// 複製しない（yuchoAccountRule）。ユーザー設定で jp-yucho-account 自体が
// 無効化されている場合はこの別行ペア走査も何も検出しない（単一行形式が無効な
// のに別行形式だけ検出され続けるのは一貫性を欠くため）。
//
// ignore マーカー・allowlist の扱いは scanCrossLineSurnameGivenPairs と同じ規則に
// 従う。CrossLineYuchoSymbolRe / CrossLineYuchoNumberRe は行全体を `^...$` で
// アンカーするため、行末に何か（ignore マーカーを含む）が付くとその行自体が
// 正規表現にマッチしなくなり、抑制は自然に値が乗る行基準になる（明示的な
// ignoredLine 判定は不要）。allowlist は記号・番号それぞれの値に対し独立に判定し、
// 一方だけが該当する場合はその値の finding だけを落とす（もう一方は検証済みの
// 正当な検出のため出す）。
//
// diff 走査は scanCrossLineYuchoPairsDiff（本ファイル下部、issue #134）が、この
// 関数を hunk のテキスト列に対してそのまま実行した上で、検出値が追加行に乗る
// finding だけを残す形（最小案）で対応する。詳細・設計判断は
// scanCrossLineYuchoPairsDiff のコメントを参照。
func (d *Detector) scanCrossLineYuchoPairs(file string, lines []string) []Finding {
	yuchoRule, ok := yuchoAccountRule(d.rules)
	if !ok {
		return nil
	}
	var out []Finding
	for i := range lines {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		j := nextNonBlankIndex(lines, i, maxAdjacentLineGap)
		if j < 0 {
			continue
		}
		symbolLine, numberLine := lines[i], lines[j]
		normSymbol := normalize.Line(symbolLine)
		normNumber := normalize.Line(numberLine)
		symM := rule.CrossLineYuchoSymbolRe.FindStringSubmatchIndex(normSymbol)
		if symM == nil || symM[2] < 0 {
			continue
		}
		numM := rule.CrossLineYuchoNumberRe.FindStringSubmatchIndex(normNumber)
		if numM == nil || numM[2] < 0 {
			continue
		}
		symbol := normSymbol[symM[2]:symM[3]]
		number := normNumber[numM[2]:numM[3]]
		if !rule.ValidCrossLineYuchoPair(symbol, number) {
			continue
		}
		if !d.allowlisted(symbol) {
			out = append(out, crossLineYuchoFinding(yuchoRule, file, i+1, symbolLine, normSymbol, symM))
		}
		if !d.allowlisted(number) {
			out = append(out, crossLineYuchoFinding(yuchoRule, file, j+1, numberLine, normNumber, numM))
		}
	}
	return out
}

// yuchoAccountRule は rules（呼び出し元では d.rules）から "jp-yucho-account"
// （internal/rule/builtin.go）の定義を線形探索して返す。RuleID・Description の
// 唯一の出所を builtin.go 側に保ち、文字列の複製を避けるための小さなヘルパー
// （d.ruleHasNegativeContext と同じ、ルール数は小さいため走査コストは無視できる）。
func yuchoAccountRule(rules []rule.Rule) (rule.Rule, bool) {
	for _, r := range rules {
		if r.ID == "jp-yucho-account" {
			return r, true
		}
	}
	return rule.Rule{}, false
}

// crossLineYuchoFinding は scanCrossLineYuchoPairs 内の 1 値分の Finding を
// 組み立てる（記号側・番号側で共通の構築ロジックを切り出したもの。
// structured_pair.go の crossLineSurnameGivenFinding と同じ構造）。m は
// rule.CrossLineYuchoSymbolRe / rule.CrossLineYuchoNumberRe の
// FindStringSubmatchIndex の結果（グループ 1 = 値、m[2]:m[3] がそのバイト
// オフセット）。正規化は 1:1（ルーン数保存）のため、norm 上のルーン位置は
// 元行と一致する（scanCrossLineNames と同じ前提）。
func crossLineYuchoFinding(r rule.Rule, file string, lineNo int, origLine, normLine string, m []int) Finding {
	rs := len([]rune(normLine[:m[2]]))
	re := rs + len([]rune(normLine[m[2]:m[3]]))
	origRunes := []rune(origLine)
	finding := Finding{
		RuleID:      r.ID,
		Description: r.Description,
		File:        file,
		Line:        lineNo,
		Column:      rs + 1,
		Match:       string(origRunes[rs:re]),
		Confidence:  rule.High,
		Reason: DetectReason{
			BaseConfidence:  rule.High.String(),
			FinalConfidence: rule.High.String(),
			Validated:       true,
		},
		start:         rs,
		end:           re,
		scoreEvidence: confidenceScoreEvidence{structuredPair: true},
	}
	finalizeFindingScore(&finding)
	return finding
}

// scanCrossLineYuchoPairsDiff は scanCrossLineYuchoPairs の diff 版（最小案、
// issue #134）。hunk のテキスト列全体（文脈行＋追加行）に対して
// scanCrossLineYuchoPairs をそのまま実行し（ラベル探索・検証ロジックは一切
// 変更しない）、結果から検出値が追加行（added[i]==true）に乗る finding だけを
// 残す。他の diff 走査経路（scanAdjacentLinesDiff 等）と同じ「文脈行上で
// 完結する検出は新規追加ではないため報告しない」原則に従う。
//
// 設計判断（最小案）:
//
//   - 記号・番号ラベルの一方が文脈行（未変更）、もう一方が追加行という
//     ケース（例: 既存の「記号: …」行の直後に新規の「番号: …」行を追加）でも、
//     scanCrossLineYuchoPairs 自体はペアとして検証（ValidCrossLineYuchoPair）まで
//     通す。ここでのフィルタにより追加行側の値だけが finding として残る
//     （文脈行側の既存の記号値は「新規追加」ではないため報告しない）。
//
//   - ignore マーカーの扱いは scanCrossLineYuchoPairs の実装をそのまま使う
//     （変更しない）。CrossLineYuchoSymbolRe/CrossLineYuchoNumberRe が行全体を
//     `^...$` でアンカーするため、記号行・番号行のどちらにマーカー等の
//     余分な文字列が付いてもその行の正規表現マッチ自体が失敗し、ペア全体が
//     不成立になる（scanAdjacentLinesDiff のように scanLineNoIgnore 経由で
//     値の行だけを厳密に見る分離走査ではなく、姓名ペア structured_pair.go と
//     同じ「ラベル行全体を正規表現でアンカーする」専用スキャナのため）。
//     これは「値が乗る行のマーカーだけが抑制する」という diff 経路の他ルールより
//     粗い（文脈行に残った古いマーカーが結果的にペア全体の検出を止めうる）が、
//     既存のフル走査実装を変更せずそのまま再利用する最小案として許容する。
//
//   - 記号行・番号行の両方が文脈行（どちらも未変更）のペアは、検証まで通っても
//     双方とも報告しない（「文脈行に乗る値は報告しない」という diff 走査全体の
//     原則どおり）。
func (d *Detector) scanCrossLineYuchoPairsDiff(file string, texts []string, added []bool) []Finding {
	var out []Finding
	for _, f := range d.scanCrossLineYuchoPairs(file, texts) {
		idx := f.Line - 1
		if idx < 0 || idx >= len(added) || !added[idx] {
			continue
		}
		out = append(out, f)
	}
	return out
}
