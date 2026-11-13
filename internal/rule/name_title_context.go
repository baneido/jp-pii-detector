package rule

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// 2026-11-12 の公開文書の走査（2,489 件）で、大学・官公庁・企業の広報の本文に出る氏名を
// 既定モードのルールが取りこぼしていた形（person-name-role-label）。いずれも「人を指す語」
// （職名・敬称・就任）が氏名に直結する構造を要求し、値は姓名辞書の完全分割（姓+名）か、
// 空白区切りの「<辞書の姓> <名>」で検証する。姓だけ・一般語・組織名は通らない。

// personTitleWords は氏名の後に置かれる職名（長いものを先に並べる）。
const affiliationTitleTail = `[ ]+(?:[^ /／()（）]{1,24}[ ]?)?(?:` + personTitleWords + `)[ ]*(?:$|[/／)）、]|ら[のがはとを])`

const personTitleWords = `特任准教授|特任教授|特任講師|特任助教|名誉教授|客員教授|准教授|教授|助教|講師|主任研究員|研究員|` +
	`大学院生|大臣政務官|政務官|副大臣|大臣|長官|副知事|知事|副市長|市長|副学長|学長|副総長|総長|` +
	`理事長|副会長|会長|副社長|社長|頭取|研究科長|医学部長|看護部長|学部長|病院長|院長`

var (
	// personNameDotAffiliationTitleRe は「<姓><名>・<学部>教授が受賞」のように、氏名と
	// 所属 + 職名を中黒でつないだ表記を拾う（大学のニュースで実測）。
	personNameDotAffiliationTitleRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|の)([` + kanji + `]{3,6})・[` + kanji + katakana + `ー]{1,20}?` +
			`(?:` + personTitleWords + `)(?:[ 、。・がはのをにともへ」）)]|$)`,
	)
	// personNameAffiliationTitleRe は「<姓> <名> <所属> <職名>」「（<学部>・<姓><名> 特任助教）」
	// 「<姓><名> <所属> 准教授 / <姓><名> <所属> 大学院生」のように、氏名の後に空白を挟んで
	// 所属と職名が続き、行末・括弧閉じ・スラッシュで終わる表記を拾う（研究成果の発表者欄・
	// 政務官の一覧で実測）。値の直前は行頭・括弧・中黒・スラッシュ・空白に限る。
	// 空白区切りの値と空白のない値は別の正規表現にする（1 つにまとめると「<姓><名> <所属>」を
	// 空白区切りの値として先に取り、検証で落ちて後ろの形を試さないため）。
	personNameAffiliationTitleRe = regexp.MustCompile(
		`(?:^|[（(・／/｜|]|[ ])([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + `]{1,4})` + affiliationTitleTail,
	)
	personNameAffiliationTitleUnspacedRe = regexp.MustCompile(
		`(?:^|[（(・／/｜|]|[ ])([` + kanji + `]{3,6})` + affiliationTitleTail,
	)
	// personNameParenOfficeLineRe は「<姓> <名>（<担当>大臣）」「<姓> <名>（<大学>教授）」だけの行
	// （閣僚・役員の一覧で実測）。括弧内は職名で終わることを要求する。
	personNameParenOfficeLineRe = regexp.MustCompile(
		`^[ ]*([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + `]{1,4}|[` + kanji + `]{3,6})[ ]*[（(][^（()）]{0,16}` +
			`(?:` + personTitleWords + `|議員)[）)][ ]*$`,
	)
	// personNameAppointedRe は社史・人事の「<姓><名>が代表取締役社長に就任」。
	personNameAppointedRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|[のとは])([` + kanji + `]{3,6})が` +
			`(?:代表取締役|取締役)?(?:社長|会長|副社長|理事長|学長|総長|頭取|委員長|監督|知事|市長)に(?:就任|選任|再任)`,
	)
	// personNameStrictHonorificRe は本文の「<姓><名>さんが受賞」「<姓><名>氏をお招きし」。敬称の
	// 「さん」「氏」は一般語の中にも現れる（高知さんさん・実在氏名・〜氏遺跡）ため、既定モードでは
	// 値を 3〜6 字の漢字に限り、姓名辞書の完全分割を必須にし（姓だけは通らない）、敬称の直後を
	// 区切り・助詞・行末に限る。敬称全般を緩く拾う形は従来どおり高再現率（person-name-high-recall）。
	personNameStrictHonorificRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|[のでとはがにらをもへ]|である)([` + kanji + `]{3,6}?)(?:さん|氏)` +
			// 行末の「<姓><名>氏」は高再現率の敬称ルールの範囲として残す（既定モードは後ろに文が続く形だけ）。
			// 2026-11-13 に「<姓><名>さんなど」「<姓><名>さん表敬訪問」「～<姓><名>さん～」の見逃しを実測し、
			// 後ろに「など」「ら」「表敬」「～」を加えた。
			`(?:[ 、。・，,！!）)（(」がはのをにともへや～〜~]|など|ら[がはのとを、]|表敬)`,
	)
	// personNameRomajiParenTitleCaseRe は「<姓> <名>（Taro Yamada）」のように、ローマ字の
	// 姓名が先頭だけ大文字の 2 語の表記（大学の教員紹介で実測）。施設の英語名（東京駅
	// （Tokyo Station））と区別するため、ローマ字 2 語が姓名のローマ字辞書に一致することを
	// ValidateLine（rejectRomajiParenNonName）で確かめる。
	personNameRomajiParenTitleCaseRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `])` +
			`([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + `]{1,4}|[` + kanji + `]{2,6})[ ]*[(（][ ]*[A-Z][a-z]{1,15}[ ]+[A-Z][a-z]{1,15}[ ]*[)）]`,
	)
	romajiParenPairRe = regexp.MustCompile(`^[ ]*[(（][ ]*([A-Z][a-z]{1,15})[ ]+([A-Z][a-z]{1,15})[ ]*[)）]`)
)

// strictHonorificRoleTails は「<語>さん」で値の末尾に来る職業・役割の字（八百屋さん・
// 運転手さん・事務員さん）。名の末字としてはほとんど使われない。
var strictHonorificRoleTails = []string{"者", "員", "手", "屋", "師", "士", "部", "課", "係", "室", "先", "店", "家"}

// rejectStrictHonorificFragment は personNameStrictHonorificRe の値の追加検証。値全体が姓 1 つ
// （分割が偶然通っただけ）、職業・役割の字で終わる語、「さん」の後にさらに「さん」が続く
// 「さんさん」（燦々）、「氏名」「氏族」の「氏」を棄却する。
func rejectStrictHonorificFragment(line string, start, end int) bool {
	v := line[start:end]
	if dict.IsSurname(v) || !notOrgName(v) {
		return false
	}
	for _, s := range strictHonorificRoleTails {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	after := line[end:]
	if strings.HasPrefix(after, "さんさん") {
		return false
	}
	// 「故・<姓><名>氏」「故 <姓><名>さん」は亡くなった人（個人情報保護法の個人情報は生存する個人）。
	before := strings.TrimRight(line[:start], " ・")
	if strings.HasSuffix(before, "故") {
		return false
	}
	return rejectPostTitleFragment(line, start, end)
}

// rejectRomajiParenNonName は personNameRomajiParenTitleCaseRe の括弧内のローマ字 2 語が
// 姓名のローマ字辞書（語順不問）に一致するかを確かめ、漢字側が組織名なら棄却する。
func rejectRomajiParenNonName(line string, start, end int) bool {
	if !notOrgName(line[start:end]) {
		return false
	}
	m := romajiParenPairRe.FindStringSubmatch(line[end:])
	if m == nil {
		return false
	}
	return validRomajiFullName(m[1] + " " + m[2])
}

// endsWithTitleWord は値が職名で終わるか（「<姓>大臣・<姓>大臣」の「<姓>大臣」を姓+名と
// 分割してしまう形。2026-11-12 に大臣会見の案内で実測した偽陽性）を返す。
func endsWithTitleWord(v string) bool {
	for _, t := range strings.Split(personTitleWords, "|") {
		if strings.HasSuffix(v, t) {
			return true
		}
	}
	return false
}

// rejectDotAffiliationFragment は personNameDotAffiliationTitleRe の値の追加検証。
func rejectDotAffiliationFragment(line string, start, end int) bool {
	return !endsWithTitleWord(line[start:end]) && rejectPostTitleFragment(line, start, end)
}

// validTitleContextName は職名の文脈で拾った値を検証する。空白を含む値は「<辞書の姓> <名>」、
// 含まない値は姓名辞書の完全分割を要求する。
func validTitleContextName(v string) bool {
	v = strings.TrimSpace(v)
	if !notOrgName(v) || !notPlaceholderName(v) || endsWithTitleWord(v) {
		return false
	}
	if strings.Contains(v, " ") {
		return validSpacedSurnameGiven(v)
	}
	return utf8.RuneCountInString(v) >= 3 && validPersonNameFullSplit(v)
}

// orgUnitSuffixes は部局・係の名前の末字。辞書に無い空白区切りの 2 語（ValidUncommonSpacedName）で
// どちらかの語がこの字で終われば、「市長室 広報課」「水道局 総務課」のような部署名とみなす
// （2026-11-12 に市のソーシャルメディア一覧で実測した偽陽性）。
var orgUnitSuffixes = []string{"課", "局", "係", "室", "署", "班", "省", "庁", "館"}

func hasOrgUnitSuffix(w string) bool {
	for _, s := range orgUnitSuffixes {
		if strings.HasSuffix(w, s) {
			return true
		}
	}
	return false
}

// rejectSansanHonorific は「高知さんさんテレビ」のように、敬称の「さん」の直後にさらに「さん」が
// 続く「さんさん」（燦々）を敬称とみなさない（2026-11-12 に実測した高再現率モードの偽陽性）。
func rejectSansanHonorific(line string, start, end int) bool {
	return !strings.HasPrefix(line[end:], "さんさん")
}
