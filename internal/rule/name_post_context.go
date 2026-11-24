package rule

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// 2026-11-17 の公開文書の走査（8,699 件）で、既定モードのルールが取りこぼしていた氏名の形
// （person-name-role-label）。人を指す語のある無作為 600 行に人手で付けた正解（姓+名 62 人）のうち、
// 設計用の 35 人で既定モードが拾えたのは 21 人だった。ここではそのうち次の形を拾う。値はいずれも
// 姓名辞書の完全分割（姓+名）を基本にし、会議録の定型に限って「辞書の姓 + ひらがなの名」と
// 「名の辞書に一致する 1 字の名」を採る。

// postTitleFormerWords は「<氏名>前首相」「<氏名>元知事」の職名（前・元・現を必須にする。
// 接頭辞のない「<氏名>知事」は既存のパターンの範囲）。
const postTitleFormerWords = `首相|総理大臣|総理|大統領|知事|市長|町長|村長|区長|議長|会長|社長|学長|総長|議員|大臣|長官|監督|代表|理事長|委員長|校長`

// dotPartyTitleWords は「<氏名>・党代表」「<氏名>・幹事長」のように中黒で氏名につなぐ政党・団体の職名。
const dotPartyTitleWords = `党代表|代表代行|副代表|代表|党首|幹事長|書記局長|政調会長|国対委員長|総務会長|委員長|衆院議員|参院議員|衆議院議員|参議院議員|県議|市議|議員`

var (
	// personNameTitleKunCallRe は会議録の指名「これを許します。内閣総理大臣<氏名>君。」のように、
	// 職名に直結した氏名 + 「君。」。既存の personNameChairKunRe は「委員長<氏名>君。」だけだった。
	personNameTitleKunCallRe = regexp.MustCompile(
		`(?:大臣|長官|副長官|政務官|総裁|議長|参考人|公述人|理事長|知事|市長|町長|村長|局長|部長|課長)` +
			`([` + kanji + `]{2,4}[` + kanji + hiragana + `]{1,4}?)君。`,
	)
	// personNameTitleNoDesuRe は挨拶文の名乗り「<市>長の<氏名>です。」（既存の personNameSelfIntroRe は
	// 「でございます」「と申します」だけ）。「です」は一般の文にも続くため、直前を職名の末字 + 「の」に限る。
	personNameTitleNoDesuRe = regexp.MustCompile(
		`(?:長|役|理事|委員|議員|教授|講師|医師|代表|担当|職員|主事|主査|主任)の([` + kanji + `]{3,6})です(?:[。 ！!]|$)`,
	)
	// personNameDotPartyTitleRe は「<選挙区>から出馬した<氏名>・党代表は、」のように、氏名と政党・団体の
	// 職名を中黒でつないだ表記（既存の personNameDotAffiliationTitleRe は大学・省庁の職名で終わる形だけ）。
	personNameDotPartyTitleRe = regexp.MustCompile(
		`(?:^|[^` + kanji + katakana + `])([` + kanji + `]{3,6}?)・(?:` + dotPartyTitleWords + `)` + looseTitleFollow,
	)
	// personNameFormerTitleRe は「<選手>や<氏名>前首相の出身地」のように、氏名 + 前・元・現 + 職名。
	personNameFormerTitleRe = regexp.MustCompile(
		`(?:^|[^` + kanji + katakana + `])([` + kanji + `]{3,6}?)(?:前|元|現)(?:` + postTitleFormerWords + `)` + looseTitleFollow,
	)
	// personNameMidParenAffiliationRe は「訳・解説 <氏名>（<学部><学科>准教授）」のように、行の途中の
	// 氏名の直後に所属 + 職名の括弧書きが続く形（既存の personNameAffiliationParenLineRe は行頭だけ）。
	personNameMidParenAffiliationRe = regexp.MustCompile(
		`[ 、・／/：:]([` + kanji + `]{3,6})[（(][^（()）]{2,30}?(?:名誉教授|准教授|教授|講師|助教|主任研究員|研究員|学芸員)[）)]`,
	)
	// personNameTitleHonorificRe は「<大学><学部>教授<氏名>さん実施報告」のように、職名に直結した氏名 + 敬称。
	personNameTitleHonorificRe = regexp.MustCompile(
		`(?:` + personTitleWords + `)([` + kanji + `]{3,6}?)(?:さん|氏|先生)`,
	)
)

// validKunOrKanaGivenName は会議録の発言者ラベル「○<姓><ひらがなの名>君」と指名「<姓><ひらがなの名>君。」の
// 値を検証する。validKunName に加えて「辞書の姓 + ひらがな 2〜5 字」を採る（名をひらがなで届け出ている
// 議員。2026-11-17 に国会の会議録で実測した見逃し）。
func validKunOrKanaGivenName(v string) bool {
	return validKunName(v) || (!strings.Contains(strings.TrimSpace(v), " ") && validSpeakerParenName(v))
}

// looseKunSingleGiven は発言者ラベルの括弧内「○国務大臣（<姓><1 字の名>君）」で、姓が辞書にない氏名を
// 「名が名の辞書に一致する 1 字、姓が 2〜3 字の漢字で職名の末字で終わらない」ときに採る
// （2026-11-17 に国会の会議録で実測した見逃し）。値全体が一般語・辞書の姓のときは呼び出し側で棄却済み。
func looseKunSingleGiven(sur, given string) bool {
	ns := utf8.RuneCountInString(sur)
	if ns < 2 || ns > 3 || utf8.RuneCountInString(given) != 1 || !allKanji(sur) {
		return false
	}
	if !dict.IsGivenName(given) || dict.IsCommonWord(given) || dict.IsCommonWord(sur) || endsWithTitleWord(sur) {
		return false
	}
	for _, s := range kunSurnameStopTails {
		if strings.HasSuffix(sur, s) || given == s {
			return false
		}
	}
	return true
}

// rejectFormerTitleFragment は personNameFormerTitleRe・personNameDotPartyTitleRe の値の追加検証。
// 値の直前が漢字で終わる語の途中でないことは正規表現で保証しているので、ここでは職名の一部を
// 取り込んだ形（rejectPostTitleFragment）だけを見る。
func rejectFormerTitleFragment(line string, start, end int) bool {
	return rejectPostTitleFragment(line, start, end)
}

// sampleGivenNames は様式の記入例で使われる定番の名。
var sampleGivenNames = map[string]bool{"太郎": true, "花子": true, "次郎": true, "一郎": true, "春子": true}

// isMunicipalitySampleName は「<自治体名> 花子」「<自治体名>太郎」のように、自治体の名前を姓にした
// 記入例の氏名かどうかを返す（2026-11-17 に市の様式の記入例で実測した偽陽性。実在の個人ではない）。
// 姓の辞書にある語（自治体名と同形の姓）は対象にしない。
func isMunicipalitySampleName(v string) bool {
	t := strings.Join(strings.Fields(v), "")
	r := []rune(t)
	if len(r) < 3 {
		return false
	}
	sur, given := string(r[:len(r)-2]), string(r[len(r)-2:])
	if !sampleGivenNames[given] || dict.IsSurname(sur) {
		return false
	}
	for _, suf := range []string{"", "市", "町", "村", "区"} {
		if dict.IsMunicipalityOrPrefecture(sur + suf) {
			return true
		}
	}
	return false
}

// tollNumberPrefixRe はナビダイヤル・フリーダイヤルの番号帯。
var tollNumberPrefixRe = regexp.MustCompile(`^(?:0570|0120|0800)[- ]?\d{6}$`)
var phoneLabelNearRe = regexp.MustCompile(`(?i)ナビダイヤル|フリーダイヤル|フリーコール|tel|電話|お問合せ|お問い合わせ|問合せ`)

// rejectTollNumber は jp-pension-number の 4-6 桁の値が、電話の文脈にあるナビダイヤル・フリーダイヤルの
// 番号（0570-031227 の形）である場合に棄却する（2026-11-17 に独立行政法人の「恩給・共済年金を担保とする
// 融資」の問合せ先で実測した偽陽性。「年金」が同じ行にあるため文脈ありと判定されていた）。
func rejectTollNumber(line string, start, end int) bool {
	if !tollNumberPrefixRe.MatchString(line[start:end]) {
		return true
	}
	return !phoneLabelNearRe.MatchString(line)
}

var digits12TokenRe = regexp.MustCompile(`\d{12}`)
var csvPrevCodeRe = regexp.MustCompile(`(\d{5,6})[ ]?,[ "]*$`)

// rejectSerialIDList は jp-my-number の 12 桁の値が個人番号ではない連番・整理番号である場合に棄却する
// （2026-11-17 に実測した偽陽性。検査用数字が偶然一致していた）。
//   - CSV の「<団体コード>,<団体コード + 連番>」: 直前の欄の 5〜6 桁のコードで始まる ID
//   - 抽選の当選番号などの一覧: 同じ行に 12 桁の数字が 4 個以上並び、個人番号の語がない
func rejectSerialIDList(line string, start, end int) bool {
	v := line[start:end]
	if m := csvPrevCodeRe.FindStringSubmatch(line[:start]); m != nil && strings.HasPrefix(v, m[1]) {
		return false
	}
	if strings.Contains(line, "個人番号") || strings.Contains(line, "マイナンバー") {
		return true
	}
	return len(digits12TokenRe.FindAllString(line, 5)) < 4
}

// notPlaceholderOrSampleName は notPlaceholderName に加えて、自治体名を姓にした記入例の氏名を棄却する。
// 「氏名:」欄・見出しの次の行など、様式の記入例が現れる経路（person-name、構造化された氏名）だけで使う。
// 役職ラベルの後（代表取締役社長：<姓> <名>）は実在の役員の欄なので対象にしない。
func notPlaceholderOrSampleName(v string) bool {
	return notPlaceholderName(v) && !isMunicipalitySampleName(v) && !isMunicipalityFullName(v)
}
