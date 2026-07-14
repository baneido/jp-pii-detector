package detect

import (
	"strings"

	"github.com/baneido/jp-pii-detector/internal/normalize"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// scanCrossLineSurnameGivenPairs はフォームで姓と名が別行の弱いラベル付き
// フィールドに分かれるケース（姓ラベル行の次に名ラベル行が続く形）を検出する
// （高再現率モード限定）。単独行では弱いラベル（姓/名字/苗字/last_name、
// 名/first_name。internal/rule/builtin.go の person-name ルール参照）+ 1 行値と
// して評価され、辞書一致しても Medium 止まりで、ペアであるという構造的証拠を
// 使えていない。姓行と名行が論理隣接するときにペアとして相関検証（姓+名の
// 組み合わせが辞書上も筋が通っているか）できれば、より強い根拠になる。
//
// scanCrossLineNames（強いラベル専用、ラベル行に値を伴わず次行が値）とは別の
// 走査系統で、こちらは姓行・名行それぞれが単独で「ラベル+値」を満たす点が
// 異なる（rule.CrossLineSurnameLabelRe / rule.CrossLineGivenLabelRe は行全体を
// アンカーする正規表現で、値をグループ 1 として同一行から取り出す）。
//
// 姓ラベル行 i と、その論理隣接（nextNonBlankIndex、maxAdjacentLineGap。間は
// 空白のみの行を最大 2 行まで挟んでもよい）の名ラベル行 j を探索する。
// 順序制約: 姓→名の順のみを対象とする。名→姓の順は日本語フォームで稀なため
// 対象外とする（i を姓ラベル行、その直後の非空白行 j を名ラベル行として
// しか調べないため、逆順のペアは自然に検出対象から外れる）。
//
// 検証（rule.ValidCrossLineSurnameGivenPair）通過時は、姓の値・名の値それぞれに
// person-name-structured の finding を 1 件ずつ出す（値のマスクが両方の値に
// 効くようにするため。scanCrossLineNames が単一の値行に対して 1 件出すのと
// 同じ流儀）。
//
// ignore マーカー・allowlist の扱いは scanCrossLineNames と同じ規則に従う。
// CrossLineSurnameLabelRe / CrossLineGivenLabelRe は行全体を `^...$` でアンカー
// するため、行末に何か（ignore マーカーを含む）が付くとその行自体が正規表現に
// マッチしなくなり、抑制は自然に値が乗る行基準になる（明示的な ignoredLine
// 判定は不要。scanCrossLineNames のコメントを参照）。allowlist は姓・名それぞれの
// 値に対し独立に判定し、一方だけが該当する場合はその値の finding だけを落とす
// （もう一方は辞書照合済みの正当な検出のため出す）。
//
// 同一スパンで単独行の弱いラベル検出（person-name、Medium）と重なった場合は、
// このパスの finding も同じく Medium のため、呼び出し元 ScanContent の
// resolveOverlapsPerLine が Confidence・内部 score・スパン長のタイブレーク
// （最終的に RuleID の辞書順）で決着する。person-name-structured という強い相関の根拠があっても、
// 単独行検出が既に Medium で拾える値では person-name 側が残ることがあるが、
// 値そのものは変わらず Medium で報告されるため実害はない
// （detect_test.go 相当の固定テストは structured_pair_test.go 側に置く）。
func (d *Detector) scanCrossLineSurnameGivenPairs(file string, lines []string) []Finding {
	if rule.Medium < d.scanMinConf {
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
		seiLine, meiLine := lines[i], lines[j]
		normSei := normalize.Line(seiLine)
		normMei := normalize.Line(meiLine)
		seiM := rule.CrossLineSurnameLabelRe.FindStringSubmatchIndex(normSei)
		if seiM == nil || seiM[2] < 0 {
			continue
		}
		meiM := rule.CrossLineGivenLabelRe.FindStringSubmatchIndex(normMei)
		if meiM == nil || meiM[2] < 0 {
			continue
		}
		sei := normSei[seiM[2]:seiM[3]]
		mei := normMei[meiM[2]:meiM[3]]
		if !rule.ValidCrossLineSurnameGivenPair(sei, mei) {
			continue
		}
		if !d.allowlisted(sei) {
			out = append(out, d.crossLineSurnameGivenFinding(file, i+1, seiLine, normSei, seiM))
		}
		if !d.allowlisted(mei) {
			out = append(out, d.crossLineSurnameGivenFinding(file, j+1, meiLine, normMei, meiM))
		}
	}
	return out
}

// crossLineSurnameGivenFinding は scanCrossLineSurnameGivenPairs 内の 1 値分の
// Finding を組み立てる（姓側・名側で共通の構築ロジックを切り出したもの）。m は
// rule.CrossLineSurnameLabelRe / rule.CrossLineGivenLabelRe の
// FindStringSubmatchIndex の結果（グループ 1 =値、m[2]:m[3] がそのバイト
// オフセット）。正規化は 1:1（ルーン数保存）のため、norm 上のルーン位置は
// 元行と一致する（scanCrossLineNames と同じ前提）。
func (d *Detector) crossLineSurnameGivenFinding(file string, lineNo int, origLine, normLine string, m []int) Finding {
	rs := len([]rune(normLine[:m[2]]))
	re := rs + len([]rune(normLine[m[2]:m[3]]))
	origRunes := []rune(origLine)
	finding := Finding{
		RuleID:      d.crossLineName.ID,
		Description: d.crossLineName.Description,
		File:        file,
		Line:        lineNo,
		Column:      rs + 1,
		Match:       string(origRunes[rs:re]),
		Confidence:  rule.Medium,
		Reason: DetectReason{
			BaseConfidence:  rule.Medium.String(),
			FinalConfidence: rule.Medium.String(),
			Validated:       true,
		},
		start:         rs,
		end:           re,
		scoreEvidence: confidenceScoreEvidence{structuredPair: true},
	}
	finalizeFindingScore(&finding)
	return finding
}
