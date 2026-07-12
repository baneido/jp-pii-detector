package rule

import (
	"regexp"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/checksum"
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
	// personNameLabelJP は「氏名カナ」等カナ接尾辞も許容する。#58 で姓名辞書に
	// カタカナ読みが追加されたため、フリガナ列（カタカナのフルネーム）も
	// ValidCrossLineName を通過して検出されるようになった。
	CSVNameHeaderRe = regexp.MustCompile(
		`^(?:` + personNameLabelJP + `|` + personNameLabelASCIIStrong + `)$`,
	)
	// CSVNameValueRe は CSV/TSV データ行の 1 フィールド本文全体が氏名の値と
	// して妥当な形かを判定する（前後の空白のみ許容）。値をグループ 1 で返す。
	CSVNameValueRe = regexp.MustCompile(
		`^\s*(` + personNameValue + `)\s*$`,
	)
	// CrossLineSurnameLabelRe / CrossLineGivenLabelRe は、姓・名の弱いラベル
	// （姓/名字/苗字/last_name、名/first_name。internal/rule/builtin.go の
	// person-name ルールの弱いラベルパターンと同じ語彙）と値が同一行に収まる形に
	// マッチし、値をグループ 1 で返す。姓と名がそれぞれ別行の弱いラベル付き
	// フィールドとして分かれるフォーム（姓行の次に名行が続く形）で、姓行・名行を
	// それぞれ単独に識別するために使う。値そのものは各行内に収まっているが、
	// 姓+名のペアとしての相関検証は detect.scanCrossLineSurnameGivenPairs が行う
	// （このファイルは正規表現・検証器の定義に留め、走査は internal/detect 側の
	// 既存方針を踏襲する）。値の文字クラスは personNameValueShort を共用し、
	// 定義の二重化を避ける。行全体を `^...$` でアンカーするため、行末に何か
	// （ignore マーカーを含む）が付くとその行自体がマッチしなくなり、抑制は
	// 自然に値が乗る行基準になる（CrossLineNameLabelRe / CrossLineNameValueRe と
	// 同じ設計。呼び出し側で明示的な ignore 判定は不要）。
	CrossLineSurnameLabelRe = regexp.MustCompile(
		`^\s*["']?(?:姓|名字|苗字|last_?name)["']?\s*[:=]\s*["'「]?(` + personNameValueShort + `)["'」]?\s*$`,
	)
	// CrossLineGivenLabelRe は CrossLineSurnameLabelRe の名側版（名・first_name）。
	// 設計・用途は同じ。
	CrossLineGivenLabelRe = regexp.MustCompile(
		`^\s*["']?(?:名|first_?name)["']?\s*[:=]\s*["'「]?(` + personNameValueShort + `)["'」]?\s*$`,
	)
	// CrossLineYuchoSymbolRe / CrossLineYuchoNumberRe は、ゆうちょ銀行の記号・番号が
	// フォームでそれぞれ独立したラベル付きフィールドとして別行に分かれる表記
	// （例:「記号:」の次行に「番号:」、値はそれぞれ独立した行に載る）に対応する。
	// internal/rule/builtin.go の jp-yucho-account は同一行のハイフン相関形式・
	// 同一行のラベル形式（具体例は同ファイルの jp-yucho-account 節のコメント参照。
	// dogfooding での自己検出を避けるためここでは繰り返さない）には対応済みだが、
	// 記号・番号が別行に分かれる形式は未対応だった。CrossLineSurnameLabelRe /
	// CrossLineGivenLabelRe（姓名別行ペア）と同じ方式で、値が同一行に収まる
	// 「ラベル+値」を行全体アンカーで判定し、記号行・番号行それぞれを単独に識別
	// できるようにする。ペアとしての相関検証（形状チェック）は
	// ValidCrossLineYuchoPair が行う（このファイルは正規表現・検証器の定義に
	// 留め、走査は internal/detect/yucho_pair.go の scanCrossLineYuchoPairs が行う）。
	// 前置語「ゆうちょ」は任意（"ゆうちょ 記号: …" のような表記も許す）。
	// 行全体を `^...$` でアンカーするため、行末に何か（ignore マーカーを含む）が
	// 付くとその行自体がマッチしなくなり、抑制は自然に値が乗る行基準になる
	// （CrossLineSurnameLabelRe と同じ設計。呼び出し側で明示的な ignore 判定は
	// 不要）。
	CrossLineYuchoSymbolRe = regexp.MustCompile(
		`^\s*(?:ゆうちょ)?\s*記号\s*[:=]?\s*(1\d{4})\s*$`,
	)
	// CrossLineYuchoNumberRe は CrossLineYuchoSymbolRe の番号側版。値（7〜8 桁、
	// 末尾は必ず "1"）をグループ 1 で返す。桁数・末尾の制約は
	// jp-yucho-account の同一行パターンおよび validYuchoAccount と同じ。
	CrossLineYuchoNumberRe = regexp.MustCompile(
		`^\s*(?:ゆうちょ)?\s*番号\s*[:=]?\s*(\d{6,7}1)\s*$`,
	)
)

// ValidCrossLineName は次行の値 v が氏名として妥当かを返す。クロスライン検出は
// 「ラベルの次行はほぼ確実に値」という同一行ほど強くない前提に立つため、同一行の
// 強いラベル（辞書照合なし）より厳しく、姓+名の分割（FullNameSplit）かつ名成分
// 2 文字以上を必須にする（プレースホルダ・組織名も棄却）。単独の姓・名一致
// （渋谷・大和・本田のような地名・企業名と同形の姓を含む）は許可しない。
// 辞書未収録の氏名は取りこぼす（高再現率モード限定の適合率↔再現率トレードオフ）。
func ValidCrossLineName(v string) bool {
	v = strings.TrimSpace(v)
	return notPlaceholderName(v) && notOrgName(v) && validStrictFullNameExtended(v)
}

// ValidCrossLineSurnameGivenPair は、姓ラベル行から取り出した値 sei と名ラベル行
// から取り出した値 mei が、姓+名のペアとして妥当かを返す。クロスラインは同一行
// より前提が弱いため、ValidCrossLineName と同じ思想で辞書一致を必須にする
// （dict.IsSurname(sei) && dict.IsGivenName(mei)）。姓ラベル・名ラベルという
// 構造的な手がかりが既にあるため、姓+名一括の分割検証（dict.SplitFullName）は
// 使わず、姓辞書・名辞書とそれぞれ直接照合する。プレースホルダ（未定 等、
// notPlaceholderName）は両方の値に適用して棄却する。
func ValidCrossLineSurnameGivenPair(sei, mei string) bool {
	sei = dict.ComposeKana(strings.TrimSpace(sei))
	mei = dict.ComposeKana(strings.TrimSpace(mei))
	if !notPlaceholderName(sei) || !notPlaceholderName(mei) {
		return false
	}
	return dict.IsSurname(sei) && dict.IsGivenNameExtended(mei)
}

// ValidCrossLineYuchoPair は、記号ラベル行から取り出した値 symbol と番号ラベル行
// から取り出した値 number が、ゆうちょ銀行の記号番号ペアとして妥当かを返す。
// 判定基準は builtin.go の validYuchoAccount（同一行ハイフン相関形式）と同一
// （記号は 5 桁で先頭が必ず "1"、番号は 7〜8 桁で末尾が必ず "1"、全桁同一の
// ダミー値は棄却）。CrossLineYuchoSymbolRe / CrossLineYuchoNumberRe が桁数・
// 先頭/末尾を既に正規表現側で保証しているため実質的には AllSame の棄却が主だが、
// validYuchoAccount と同じ形状チェックも defense-in-depth として残す（将来
// どちらかの正規表現だけが変更されても判定基準がずれないように）。
func ValidCrossLineYuchoPair(symbol, number string) bool {
	symbol = strings.TrimSpace(symbol)
	number = strings.TrimSpace(number)
	if len(symbol) != 5 || symbol[0] != '1' ||
		(len(number) != 7 && len(number) != 8) || number[len(number)-1] != '1' {
		return false
	}
	return !checksum.AllSame(symbol) && !checksum.AllSame(number)
}
