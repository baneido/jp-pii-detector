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
	// CrossLineNameHeaderRe は、区切り記号（:/=）を伴わない氏名系の強いラベル
	// だけからなる行にマッチする。CSV のヘッダセル（CSVNameHeaderRe）が区切りを
	// 持たないのと同じ構造で、プレーンテキストの名簿では
	//
	//	氏名
	//	山田太郎
	//	佐藤花子
	//
	// のようにコロン無しの見出し行が使われる。CrossLineNameLabelRe が区切りを
	// 必須にしているため、この形はラベル行として認識されず名簿全体を取りこぼして
	// いた。
	//
	// 区切りが無いぶん「ラベル行である」という手がかりは弱い（本文中に
	// 「氏名」とだけ書かれた行もありうる）。そのため detect.scanCrossLineNames は
	// この行を採用しても、続く行が姓名辞書を通らなければ何も報告しない
	// （検出の可否は最終的に値側の ValidCrossLineName が決める）。
	// Markdown の見出し（`## 氏名`）や表のセル（`| 氏名 |`）は行頭の記号・
	// パイプがあるためこの行全体アンカーに一致しない。
	CrossLineNameHeaderRe = regexp.MustCompile(
		`^\s*["']?(?:` + personNameLabelJP + `|` + personNameLabelASCIIStrong + `)["']?\s*$`,
	)
	// CrossLineNameSectionRe は、帳票の「人物ごとの欄」を始める見出し行
	// （`患者情報` `【申込者情報】` `お届け先情報` `■本人情報` `委任者の確認情報:`）
	// だけからなる行にマッチする。業務帳票ではこの見出しの直後の行に氏名だけを
	// 置き、`氏名:` のラベルを付けないことが多い（Nemotron-PII-Japan の 1 万件抽出で、
	// 既定設定が取りこぼした姓の約 6 割がこの形だった）。
	//
	// 見出しは「〜者／〜人／〜主／〜員（の確認／基本）情報」と、人物を表す
	// 固定語（患者・本人・お届け先・お客様・会員・基本）に限る。`商品情報`
	// `配送情報` のような人物でない欄も漢字だけなら形は同じだが、値側の
	// ValidCrossLineName（姓名辞書照合）を通らない行は報告しないため、見出しの
	// 判定は粗くてよい。値の判定は CrossLineNameHeaderRe と同じ経路を通る。
	CrossLineNameSectionRe = regexp.MustCompile(
		`^\s*[【\[［■□◆◇●○]?\s*(?:[` + kanji + `]{0,8}?(?:者|人|主|員)|患者|本人|お届け先|届け先|お客様|会員|基本)` +
			`の?(?:確認|基本)?情報\s*[】\]］]?\s*(?:[:：]|は(?:以下|次)の(?:通り|とおり)です。?)?\s*$`,
	)
	// PersonIDFieldRe は人物の識別子の項目行（`患者ID: …` `従業員ID: …` `ユーザー名: …`）。
	// 帳票ではこの行の直後に氏名だけの行が続くことがあるため、見出し行と同じく扱う。
	// StrongLabelSpacedValueLineRe は「<氏名系の強いラベル>: <姓> <名>」だけの行にマッチし、値を
	// グループ 1 で返す。次の行が人物の項目行のとき、辞書に無い氏名を形で採るために使う。
	StrongLabelSpacedValueLineRe = regexp.MustCompile(
		`^\s*(?:` + personNameLabelJP + `)\s*[:=]\s*([` + kanji + `]{1,4} [` + kanji + hiragana + katakana + `]{1,4})\s*$`,
	)
	// FieldLineRe は「<ラベル>: <値>」の項目行（ラベルは漢字・かな 2〜12 文字）。
	FieldLineRe     = regexp.MustCompile(`^\s*[` + kanji + hiragana + katakana + `A-Za-z・()（）]{2,12}\s*[:：]\s*\S`)
	PersonIDFieldRe = regexp.MustCompile(
		`^\s*(?:患者|顧客|従業員|会員|利用者|受講者|購入者)?(?:ID|ユーザー名)\s*[:：]\s*\S`,
	)
	// PersonAttrFieldRe は人物の属性の項目行（`生年月日: …` `性別: …` `個人番号: …` `金融機関名: …` 等）。氏名だけの行の
	// 直後にこの行が続く形（`<姓> <名>` の次行に `生年月日:`）を、氏名の手がかりにする。
	PersonAttrFieldRe = regexp.MustCompile(
		`^\s*[` + kanji + hiragana + katakana + `]{0,8}?(?:生年月日|性別|血液型|年齢|(?:患者|顧客|従業員|会員)ID|ユーザー名|メールアドレス|(?:携帯)?電話番号|連絡先|個人番号|マイナンバー|金融機関名|住所)\s*[:：]`,
	)
	// StandaloneNameSentenceRe は「<姓> <名>。」だけの行（審査報告書の署名行など）にマッチし、
	// 値をグループ 1 で返す。
	StandaloneNameSentenceRe = regexp.MustCompile(
		`^\s*([` + kanji + `]{1,4} [` + kanji + hiragana + katakana + `]{1,4})。\s*$`,
	)
	// CrossLineNameRoleHeadingRe は「給付対象者」「作成者」のように「情報」を伴わない
	// 「〜者」「〜人」だけの見出し行（3〜7 文字）にマッチし、語をグループ 1 で返す。
	// 「直人」「正人」のような人名とも同形になるため、呼び出し側は語が姓名辞書に
	// 一致しないこと（IsRoleHeadingWord）も確かめる。
	CrossLineNameRoleHeadingRe = regexp.MustCompile(
		`^\s*[【\[［■□◆◇●○]?\s*([` + kanji + `]{2,6}(?:者|人))\s*[】\]］]?\s*[:：]?\s*$`,
	)
	// CrossLineNamePartyHeadingRe は契約書の当事者欄の見出し「甲」「乙（受託者）」だけの行に
	// マッチする（次の行以降に住所・氏名が並ぶ）。
	CrossLineNamePartyHeadingRe = regexp.MustCompile(
		`^\s*(?:甲|乙|丙|丁)\s*(?:[(（][` + kanji + `]{2,6}[)）])?\s*[:：]?\s*$`,
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
	// ASCII ラベルは person-name の同ラベルと同じく `(?i:...)` で大文字表記
	// （LAST_NAME: 等）も拾う（normalize は ASCII の大小文字を変換しないため）。
	CrossLineSurnameLabelRe = regexp.MustCompile(
		`^\s*["']?(?:姓|名字|苗字|(?i:last_?name))["']?\s*[:=]\s*["'「]?(` + personNameValueShort + `)["'」]?\s*$`,
	)
	// CrossLineGivenLabelRe は CrossLineSurnameLabelRe の名側版（名・first_name）。
	// 設計・用途は同じ。
	CrossLineGivenLabelRe = regexp.MustCompile(
		`^\s*["']?(?:名|(?i:first_?name))["']?\s*[:=]\s*["'「]?(` + personNameValueShort + `)["'」]?\s*$`,
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
	// 前置語「ゆうちょ」「通帳」「貯金」は任意（"ゆうちょ 記号: …"・
	// "通帳記号: …"・"貯金記号: …" のような表記も許す）。JSON/YAML の
	// フィールド行（`"記号": "…",` のようにラベル・値が引用符で囲まれ、行末に
	// 区切りカンマが付く形）にも対応するため、ラベル・値を囲む引用符・鉤括弧と
	// 行末のカンマ・読点 1 つまでを任意で許容する。
	// 行全体を `^...$` でアンカーするため、それ以外の何か（単位や ignore
	// マーカーを含む）が行末に付くとその行自体がマッチしなくなり、抑制は自然に
	// 値が乗る行基準になる（CrossLineSurnameLabelRe と同じ設計。呼び出し側で
	// 明示的な ignore 判定は不要）。
	CrossLineYuchoSymbolRe = regexp.MustCompile(
		`^\s*["']?(?:ゆうちょ|通帳|貯金)?\s*記号["']?\s*[:=]?\s*["'「]?(1\d{3}0)["'」]?\s*[,、]?\s*$`,
	)
	// CrossLineYuchoNumberRe は CrossLineYuchoSymbolRe の番号側版。値（7〜8 桁、
	// 末尾は必ず "1"）をグループ 1 で返す。桁数・末尾の制約は
	// jp-yucho-account の同一行パターンおよび validYuchoAccount と同じ。
	CrossLineYuchoNumberRe = regexp.MustCompile(
		`^\s*["']?(?:ゆうちょ|通帳|貯金)?\s*番号["']?\s*[:=]?\s*["'「]?(\d{6,7}1)["'」]?\s*[,、]?\s*$`,
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

// SurnameFieldLineRe / GivenFieldLineRe は「<前置き>姓: <値>」「<前置き>名: <値>」だけの行
// （「申立人姓: …」の次行に「申立人名: …」）にマッチし、前置きをグループ 1、値をグループ 2 で返す。
var (
	SurnameFieldLineRe = regexp.MustCompile(`^\s*([` + kanji + hiragana + katakana + `]{0,8}?)[ ]?姓\s*[:：]\s*([` + kanji + `]{1,4})\s*$`)
	GivenFieldLineRe   = regexp.MustCompile(`^\s*([` + kanji + hiragana + katakana + `]{0,8}?)[ ]?名\s*[:：]\s*([` + kanji + hiragana + katakana + `]{1,4})\s*$`)
	// SurnameGivenSameLineRe は同じ行の「姓: <値>、名: <値>」にマッチする。
	SurnameGivenSameLineRe = regexp.MustCompile(`(?:^|[^` + kanji + `])姓\s*[:：]\s*([` + kanji + `]{1,4})[、,]\s*名\s*[:：]\s*([` + kanji + hiragana + katakana + `]{1,4})(?:[、,。\s]|$)`)
)

// ValidSurnameGivenFieldPair は、姓の欄と名の欄の組から取り出した値 sei・mei を氏名として
// 採ってよいかを返す。欄の組が手がかりになるため、姓か名の片側が辞書にあればよい（「姓: 会議」
// 「名: 資料」のような様式の語の組は両側とも辞書に無いので落ちる）。
func ValidSurnameGivenFieldPair(sei, mei string) bool {
	if !notOrgName(sei) || !notPlaceholderName(sei) || !notPlaceholderName(mei) || spacedGivenStopwords[mei] || spacedGivenStopwords[sei] {
		return false
	}
	return dict.IsSurname(sei) || dict.IsGivenName(mei)
}

// ValidSectionNameShape は、見出し行の直後にあり、さらに次の行が人物の項目行
// （PersonAttrFieldRe / PersonIDFieldRe）という 2 つの手がかりがそろった値に限って使う、
// 姓名辞書を使わない形の判定。空白で 2 語に分かれ、先頭語が漢字 1〜3 文字、2 語目が漢字・かな
// 1〜3 文字で、職名・一般語・組織名・都道府県名でないこと。姓も名も辞書にない氏名
// （Nemotron-PII-Japan の 1 万件抽出で、見逃した姓の多く）を拾うため。
func ValidSectionNameShape(v string) bool {
	v = strings.TrimSpace(v)
	f := strings.Fields(v)
	if len(f) != 2 || !notOrgName(v) || !notPlaceholderName(v) || spacedGivenStopwords[f[1]] || prefectureWordRe.MatchString(f[0]) {
		return false
	}
	return spacedNameSurnameRe.MatchString(f[0]) && spacedNameGivenRe.MatchString(f[1])
}

// IsRoleHeadingWord は CrossLineNameRoleHeadingRe の語が見出しとして使えるか（姓名辞書に
// 一致しない立場の語か）を返す。「登美人」のような人名の行を見出しとみなさないため。
func IsRoleHeadingWord(w string) bool {
	return dict.MatchPersonName(w) == dict.NoMatch
}

// ValidSectionName は、帳票の見出し行やコロンなしの氏名ラベル行の次の行（既定で有効な
// detect.scanSectionHeadingNames）の値を氏名として採用してよいかを返す。
// ValidCrossLineName に加えて、空白で 2 語に分かれ先頭語が辞書の姓で 2 語目が 1〜3 文字の
// 名らしい語（validSpacedSurnameGiven）の値も受ける。名の辞書は収録外の名が多く
// （Nemotron-PII-Japan の 1 万件抽出で正解の名の約 2 割）、見出しの直後に「姓 名」と
// 空白区切りで置かれた行は、姓の辞書照合だけで氏名とみなせるため。
func ValidSectionName(v string) bool {
	v = strings.TrimSpace(v)
	// 字間を空けた見出し語（主 催・概 要）と文の断片（整 備する）は氏名ではない。
	if f := strings.Fields(v); len(f) == 2 && isLetterSpacedWord(f[0], f[1]) {
		return false
	}
	return ValidCrossLineName(v) || validSpacedNameOneSideDict(v) || ValidUncommonSpacedName(v)
}

// ValidUncommonSpacedName は、姓名辞書に無い「<姓> <名>」を、形（ValidSectionNameShape）に加えて
// 2 語のどちらも一般語（dict.IsCommonWord）でないことを条件に受ける。辞書にない姓（一ノ関・八ツ木）は
// 一般語でもないのに対し、帳票の欄に書かれる非人名の値（別紙 参照・同上 同上・本人 確認）は一般語の
// 組になるため。
func ValidUncommonSpacedName(v string) bool {
	if !ValidSectionNameShape(v) {
		return false
	}
	f := strings.Fields(strings.TrimSpace(v))
	if hasOrgUnitSuffix(f[0]) || hasOrgUnitSuffix(f[1]) {
		return false
	}
	return !dict.IsCommonWord(f[0]) && !dict.IsCommonWord(f[1])
}

// ValidRosterName は、ラベルも敬称も無い羅列（名簿ファイル判定、
// detect.scanNameRosterFile）で 1 行の値 v を氏名として採用してよいかを返す。
//
// ValidCrossLineName より 1 段厳しく、org 版の高再現率カタカナ名を含まない
// 姓名辞書（validStrictFullName）だけで判定する。クロスラインには「直前の行に
// 氏名ラベルがある」という構造的な手がかりがあるのに対し、名簿判定には行単位の
// 手がかりが一切無く、ファイル全体の統計だけが根拠になるため。
func ValidRosterName(v string) bool {
	v = strings.TrimSpace(v)
	return notPlaceholderName(v) && notOrgName(v) && validStrictFullName(v)
}

// ValidCrossLineSurnameGivenPair は、姓ラベル行から取り出した値 sei と名ラベル行
// から取り出した値 mei が、姓+名のペアとして妥当かを返す。クロスラインは同一行
// より前提が弱いため、ValidCrossLineName と同じ思想で辞書一致を必須にする
// （dict.IsSurname(sei) && dict.IsGivenNameExtended(mei)。名側は ValidCrossLineName が
// validStrictFullNameExtended を使うのと揃え、高再現率用カタカナ名まで許す）。姓ラベル・名ラベルという
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
// （記号は 5 桁で先頭 "1"・末尾 "0"、番号は 7〜8 桁で末尾 "1"、全桁同一の
// ダミー値は棄却し、記号 4 桁目を checksum.YuchoAccount で検証）。正規表現が
// 桁数・先頭/末尾を保証していても、validYuchoAccount と同じ形状チェックを
// defense-in-depth として残す（将来どちらかだけが変更されても基準がずれない）。
func ValidCrossLineYuchoPair(symbol, number string) bool {
	symbol = strings.TrimSpace(symbol)
	number = strings.TrimSpace(number)
	if len(symbol) != 5 || symbol[0] != '1' || symbol[4] != '0' ||
		(len(number) != 7 && len(number) != 8) || number[len(number)-1] != '1' {
		return false
	}
	return !checksum.AllSame(symbol) && !checksum.AllSame(number) && checksum.YuchoAccount(symbol, number)
}
