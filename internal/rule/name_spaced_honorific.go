package rule

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// 2026-11-14 の公開文書の走査（7,083 件）で、既定モードのルールが取りこぼしていた氏名の形
// （person-name-role-label）。いちばん多かったのは、姓と名の間に空白を入れた氏名に敬称が続く
// 「<姓> <名>さん」「<姓> <名> 君」「<姓> <名> 先生」で、これまでは「様」「氏」が空白 1 個で
// 直結し、後ろが助詞・行末の形しか拾っていなかった。値はいずれも「<辞書の姓> <名>」を要求し、
// 名が一般語（管理・企画・日本）や職名のものは通さない（validSpacedHonorificName）。

var (
	// personNameSpacedHonorificAnyRe は「<姓> <名>さん（2年生）」「<姓>　<名>　君」「<姓> <名> さん<出身校>」
	// 「作者：<姓>　<名>　様　(<市>)」「主任技術者  <姓>  <名> 氏」。姓と名の間は空白 1〜3 個、
	// 名と敬称の間は空白 0〜2 個。値の直前は漢字・カタカナ以外に限る（長い語の途中から切らない）。
	personNameSpacedHonorificAnyRe = regexp.MustCompile(
		`(?:^|[^` + kanji + katakana + `])([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + hiragana + `]{1,4})[ ]{0,2}(?:さん|君|先生|選手|様|氏)`,
	)
	// personNameSpacedTitleLineRe は名簿の行頭の「<姓>　<名>委員　　<所属>」「<姓> <名>議員 質問資料」。
	personNameSpacedTitleLineRe = regexp.MustCompile(
		`^[ ]*([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + `]{1,4})[ ]?(?:副委員長|委員長|委員|議員|副会長|会長|理事|監事|顧問)(?:[ ]+|$)`,
	)
	// personNameKessanGluedRe は決算短信の表紙を PDF から抜いたときに欄がつながった
	// 「（氏名）<姓>　<名>問合せ先責任者（役職名）…（氏名）<姓>　<名>TEL」。
	personNameKessanGluedRe = regexp.MustCompile(
		`[(（]氏名[)）][ ]*([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + `]{1,4}?)(?:問合せ先|TEL|ＴＥＬ|[(（]役職名|配当支払|定時株主)`,
	)
	// personNameRosterOrgTitleRe は会議の構成員名簿の「<姓>  <名>      <所属><職名>」だけの行
	// （氏名の後に 2 個以上の空白、行末が職名）。
	personNameRosterOrgTitleRe = regexp.MustCompile(
		`^[ ]*([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + `]{1,4})[ ]{2,}[^ 。][^。]{1,40}?` +
			`(?:次長|局長|室長|審議官|統括官|参事官|長官|理事長|副会長|会長|理事|准教授|教授|所長|部長|課長|代理|代行|相談役|社長|委員長|館長|校長|院長|市長|町長|村長|知事)[ ]*$`,
	)
	// personNameSpacedParenOrgRe は発表者・受賞者の一覧の「<姓> <名>（<大学>）」「<姓> <名>(<大学><学部>)」
	// 「<姓> <名>（<中学校>3年生）」。括弧内に所属（大学・学校・会社・研究所など）を要求する。
	personNameSpacedParenOrgRe = regexp.MustCompile(
		`(?:^|[^` + kanji + katakana + `])([` + kanji + `]{1,4}[ ]{1,2}[` + kanji + `]{1,4})[ ]?[（(][^（()）]{0,24}` +
			`(?:大学|高等学校|高校|中学校|小学校|高専|株式会社|研究所|研究科|学部|病院|協会|法人)[^（()）]{0,16}[）)]`,
	)
	// personNameDietMemberRe は会議録・お知らせの「…における<姓><名>衆議院議員の、」「<姓><名>参議院議員が」。
	// 職名が議員に限られるので、直前がひらがな（「における」）でも拾う。値は姓名辞書の完全分割。
	personNameDietMemberRe = regexp.MustCompile(
		`(?:^|[^` + kanji + katakana + `])([` + kanji + `]{3,6}?)(?:衆議院議員|参議院議員)`,
	)
	// personNameColonCreditRe は「撮影：<姓><名>」「（著者：<姓><名>）」「総合司会：<姓> <名>（<学会>会長）」
	// 「モデレーター：<姓> <名>　<所属>」のように、役割のラベルとコロンに続く氏名。
	personNameColonCreditRe = regexp.MustCompile(
		`(?:作者|著者|撮影|総合司会|司会|モデレーター|文責|演者|発表者|受賞者|報告者|執筆者)[ ]?[：:／/][ ]*` +
			`([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + `]{1,4}|[` + kanji + `]{3,6})(?:[ （()）、,／/・。]|$)`,
	)
)

// validSpacedHonorificName は敬称・職名・所属の手がかりに続く空白区切りの「<姓> <名>」を検証する。
// 姓は姓の辞書に一致すること、名は 1〜4 字で職名・欄名でないことを要求する。名が漢字だけなら
// 名の辞書に一致するか一般語でないこと、ひらがなを含むなら名の辞書に一致することを要求する
// （「事務室 管理」「取締役 監査等」「東 日本」を通さない）。1 字の姓（東・森・林）は地名・方角と
// 同形なので、名が辞書にあるときだけ通す。
func validSpacedHonorificName(v string) bool {
	v = strings.TrimSpace(v)
	f := strings.Fields(v)
	if len(f) != 2 || !notOrgName(v) || !notPlaceholderName(v) {
		return false
	}
	sur, given := f[0], f[1]
	n := utf8.RuneCountInString(given)
	if n < 1 || n > 4 || spacedGivenStopwords[given] || endsWithTitleWord(given) || isLetterSpacedWord(sur, given) {
		return false
	}
	if !dict.IsSurname(sur) || prefectureWordRe.MatchString(sur) {
		return false
	}
	// 名が職名・部署の語尾（管理課・委員会）や敬称の字（「<名>氏（<所属>）」の「氏」）で終わる形は、
	// 名の後ろの語まで値に取り込んでいる。
	for _, s := range []string{"長", "員", "事", "部", "課", "係", "室", "会", "所", "局", "科", "氏", "様", "殿", "君"} {
		if n >= 2 && strings.HasSuffix(given, s) {
			return false
		}
	}
	inDict := dict.IsGivenNameExtended(given)
	if utf8.RuneCountInString(sur) == 1 {
		return inDict
	}
	hasKana := false
	for _, r := range given {
		if r >= 0x3041 && r <= 0x309E {
			hasKana = true
		}
	}
	if hasKana {
		return inDict
	}
	return inDict || !dict.IsCommonWord(given)
}

// validColonCreditName は役割のラベルとコロンに続く値を検証する（姓名辞書の完全分割か
// 「<辞書の姓> <名>」。職名で終わる「<姓>社長」や組織名は通さない）。
func validColonCreditName(v string) bool {
	v = strings.TrimSpace(v)
	if !notOrgName(v) || !notPlaceholderName(v) || endsWithTitleWord(v) {
		return false
	}
	if strings.Contains(v, " ") {
		return validSpacedHonorificName(v)
	}
	return validPersonNameFullSplit(v) && !dict.IsCommonWord(v)
}

// spacedHonorificWordTails は、敬称の字の直後に続くと敬称ではなく別の語になる字
// （氏名・氏族、様式・様々、君主、選手権・選手団、さんさん）。
var spacedHonorificWordTails = map[string]string{
	"さん": "さぽ",
	"氏":  "名族子神",
	"様":  "式々子相態",
	"選手": "権団会村名宣",
}

// rejectSpacedHonorificTail は personNameSpacedHonorificAnyRe の値の後ろを確かめる。敬称の後に
// 別の語を作る字が続く形と、「君」の後に漢字・ひらがな（助詞以外）が続く形を棄却する。
func rejectSpacedHonorificTail(line string, start, end int) bool {
	rest := strings.TrimLeft(line[end:], " ")
	for h, tails := range spacedHonorificWordTails {
		if strings.HasPrefix(rest, h) {
			next, _ := utf8.DecodeRuneInString(rest[len(h):])
			return next == utf8.RuneError || !strings.ContainsRune(tails, next)
		}
	}
	if strings.HasPrefix(rest, "君") {
		next, size := utf8.DecodeRuneInString(rest[len("君"):])
		if size == 0 {
			return true
		}
		if strings.ContainsRune("がはのをにともへや", next) {
			return true
		}
		isKanji := (next >= 0x4E00 && next <= 0x9FFF) || next == 0x3005
		isHira := next >= 0x3041 && next <= 0x3096
		return !isKanji && !isHira
	}
	return rejectHonorificWordTail(line, start, end)
}

// rejectPagerDigits は「1234567...22」のように、数字の並びの直後に省略記号が続くページ送りの
// 番号を口座番号とみなさない（2026-11-14 に大学のニュース一覧で実測した偽陽性。前の行の
// 「<銀行名>」が文脈語になっていた）。
func rejectPagerDigits(line string, start, end int) bool {
	rest := line[end:]
	return !strings.HasPrefix(rest, "...") && !strings.HasPrefix(rest, "…")
}
