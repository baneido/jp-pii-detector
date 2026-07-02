package rule

import (
	"regexp"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// 構造化・複数行の氏名検出（高再現率）で使う公開ヘルパ。
// フォームや設定ファイルでは「ラベル行」と「値行」が別の行に分かれることがある
// （例: `氏名:` の次の行に `山田太郎`）。同一行前提の person-name パターンでは
// 取りこぼすため、detect.ScanContent が隣接行に対してこれらを使う。
//
// ラベル語彙（personNameLabelJP / personNameLabelASCIIStrong）と値の文字クラス
// （personNameValue）は同一行ルールと共有し、定義の二重化を避ける。
var (
	// CrossLineNameLabelRe は氏名系の強いラベルと区切りだけで、値を伴わない行に
	// マッチする（値が次行にあるフォーム形式）。弱いラベル（姓・名 等の単一
	// フィールド）は姓名ペアの結合が別途必要なため、ここでは強いラベルに限定する。
	// 行頭の引用符（"氏名":）と区切り後の開き引用符・括弧（氏名: "／氏名：「）も許す。
	CrossLineNameLabelRe = regexp.MustCompile(
		`^\s*["']?(?:` + personNameLabelJP + `|` + personNameLabelASCIIStrong + `)["']?` +
			`\s*[:=]\s*["'「『（(]?\s*$`,
	)
	// CrossLineNameValueRe は氏名の値だけからなる行にマッチし、値をグループ 1 で
	// 返す。前後のインデント・引用符・括弧を許容する。`名:` のようなラベル行
	// （コロンを含む）はマッチしないため、ラベル行と値行を取り違えない。
	CrossLineNameValueRe = regexp.MustCompile(
		`^\s*["'「『（(]?(` + personNameValue + `)["'」』）)]?\s*$`,
	)
	// CSVNameHeaderRe は CSV/TSV のヘッダの 1 フィールド本文が、氏名系の強い
	// ラベルそのものと完全一致するかを判定する（列全体をアンカーし、
	// 部分一致は誤検出が増えるため許可しない）。CrossLineNameLabelRe と違い
	// 区切り記号（:/=）は伴わない（ヘッダセルはラベル語そのものなため）。
	// personNameLabelJP は「氏名カナ」等カナ接尾辞も許容するが、埋め込み
	// 姓名辞書は漢字ベースのため、フリガナ列は ValidCrossLineName が値を
	// 通さず自然に対象外になる（意図した挙動）。
	CSVNameHeaderRe = regexp.MustCompile(
		`^(?:` + personNameLabelJP + `|` + personNameLabelASCIIStrong + `)$`,
	)
	// CSVNameValueRe は CSV/TSV データ行の 1 フィールド本文全体が氏名の値と
	// して妥当な形かを判定する（前後の空白のみ許容）。値をグループ 1 で返す。
	CSVNameValueRe = regexp.MustCompile(
		`^\s*(` + personNameValue + `)\s*$`,
	)
)

// ValidCrossLineName は次行の値 v が氏名として妥当かを返す。クロスライン検出は
// 「ラベルの次行はほぼ確実に値」という同一行ほど強くない前提に立つため、同一行の
// 強いラベル（辞書照合なし）より厳しく、コンパクト姓名辞書での照合を必須にする
// （プレースホルダ・組織名も棄却）。辞書未収録の氏名は取りこぼす（高再現率モード
// 限定の適合率↔再現率トレードオフ）。
func ValidCrossLineName(v string) bool {
	v = strings.TrimSpace(v)
	return notPlaceholderName(v) && notOrgName(v) && dict.IsPersonName(v)
}
