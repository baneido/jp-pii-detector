package rule

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// 2026-11-13 の公開文書の走査（2,179 件）で、既定モードのルールが取りこぼしていた氏名の形
// （person-name-role-label）。会議録・大学や企業のお知らせの本文で、指名・当選・職名・敬称・
// 名乗りが氏名に直結する構造を要求し、値は姓名辞書の完全分割（姓+名）か、空白区切りの
// 「<辞書の姓> <名>」、発言者ラベルに限り「<辞書の姓> + ひらがなの名」で検証する。
// 姓だけ・一般語・組織名は通らない。

var (
	// personNameKunNominateRe は会議録の「委員長に<氏名>君を指名いたします」「<氏名>君が委員長に
	// 当選した」「補欠として<氏名>君が選任された」。値の直前は漢字以外に限る（職名に地続きの
	// 「委員長<氏名>君」は範囲を決められないので拾わない）。
	personNameKunNominateRe = regexp.MustCompile(
		`(?:^|[^` + kanji + `])([` + kanji + `]{1,4}[ ]{1,2}[` + kanji + `]{1,4}|[` + kanji + `]{3,6}|[` + kanji + `]{1,4}[` + hiragana + `]{2,5})君` +
			`(?:を[^。、]{0,12}?指名|が[^。、]{0,14}?(?:に当選|に選任|を辞任|に就任))`,
	)
	// personNameSenseiParticleRe は本文の「<姓><名>先生に聞く」「<姓><名>先生が講演」。「先生」は
	// 一般語にも付く（担任の先生・保健室の先生）ため、値を 3〜6 字の漢字に限り、姓名辞書の
	// 完全分割を必須にし、「先生」の直後を区切り・助詞・行末に限る。
	personNameSenseiParticleRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|[のでとはがにらをもへ])([` + kanji + `]{3,6}?)先生` +
			`(?:[ 、。・，,！!）)（(」がはのをにともへや]|$)`,
	)
	// personNameSpeakerParenRe は地方議会の会議録の発言者ラベル「○副議長（<姓><名>）」
	// 「○教育長（<姓><名>）」。国会の会議録と違い「君」を付けない。PDF の 2 段組みでは行の途中に
	// 現れるため行頭に限らない。名がひらがなの議員（<姓> + ひらがな）も、○ + 職名 + 括弧という
	// 定型があるので姓の辞書だけで採る（validSpeakerParenName）。
	personNameSpeakerParenRe = regexp.MustCompile(
		`[○〇◯][ ]?(?:[0-9]{1,3}番|[` + kanji + `]{0,12}?(?:議長|委員長|市長|町長|村長|区長|知事|教育長|部長|課長|局長|室長|所長|次長|管理者|監査委員|委員|議員|理事|参事|主幹))` +
			`[ ]?[（(]([` + kanji + `]{1,4}[ ]{0,2}[` + kanji + hiragana + `]{1,5})[）)]`,
	)
	// personNameTitleNoNameRe は「取締役 専務執行役員 CFOの<姓><名>が、」「代表の<姓><名>は、」のように、
	// 職名 + 「の」 + 氏名 + 助詞 + 読点で人物を紹介する表記。後ろを「が、」「は、」などに限るのは、
	// 「社長の経営方針が示された」のような「職名 + の + 一般語」を避けるため。
	personNameTitleNoNameRe = regexp.MustCompile(
		`(?:CEO|CFO|COO|CTO|CIO|社長|会長|頭取|理事長|取締役|執行役員|役員|本部長|部長|所長|室長|局長|センター長|教授|監督|代表|委員長|弁護士|医師|アナウンサー|研究員|キャスター)の` +
			`([` + kanji + `]{3,6}?)(?:が、|は、|より、|から、|による)`,
	)
	// personNameGiinLineRe は議員紹介・一般質問の一覧の「<姓> <名> 議員」だけの行。
	personNameGiinLineRe = regexp.MustCompile(
		`^[ ]*([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + hiragana + `]{1,4})[ ]+議員[ ]*$`,
	)
	// personNameSelfIntroRe は会議録の名乗り「…こととなりました<姓><名>でございます」
	// 「<課>長の<姓><名>でございます」。姓だけの名乗り（<姓>でございます）は完全分割を通らない。
	personNameSelfIntroRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|ました|おります|[のはが])([` + kanji + `]{3,6})(?:でございます|と申します)`,
	)
)

// validSpeakerParenName は発言者ラベルの括弧内の値を検証する。姓名辞書の完全分割（空白は除く）、
// 「<辞書の姓> <名>」、または「<辞書の姓> + ひらがな 2〜5 字」を許可する。
func validSpeakerParenName(v string) bool {
	t := strings.TrimSpace(v)
	if t == "" || !notPlaceholderName(t) || !notOrgName(t) {
		return false
	}
	joined := strings.Join(strings.Fields(t), "")
	if validPersonNameFullSplit(joined) || validSpacedSurnameGiven(t) {
		return true
	}
	// 漢字の姓 + ひらがなの名。
	i := 0
	for i < len(joined) {
		r, n := utf8.DecodeRuneInString(joined[i:])
		if r >= 0x3041 && r <= 0x3096 {
			break
		}
		i += n
	}
	sur, given := joined[:i], joined[i:]
	if sur == "" || utf8.RuneCountInString(given) < 2 || !dict.IsSurname(sur) {
		return false
	}
	for _, r := range given {
		if r < 0x3041 || r > 0x3096 {
			return false
		}
	}
	return true
}

// validSelfIntroName は名乗りの値を検証する。姓名辞書の完全分割に加え、値そのものが一般語
// （通常国会でございます・大変恐縮でございます）や組織名でないことを要求する。
func validSelfIntroName(v string) bool {
	return validPersonNameFullSplit(v) && !dict.IsCommonWord(v) && !dict.IsSurname(v) && notOrgName(v) && !endsWithTitleWord(v)
}

// rejectSenseiFragment は personNameSenseiParticleRe の値の追加検証（職業・役割の字で終わる語、
// 値全体が姓 1 つ、組織名、肩書きの一部を取り込んだ形を棄却する）。
func rejectSenseiFragment(line string, start, end int) bool {
	v := line[start:end]
	if dict.IsSurname(v) || !notOrgName(v) || dict.IsCommonWord(v) {
		return false
	}
	for _, s := range strictHonorificRoleTails {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	return rejectPostTitleFragment(line, start, end)
}

// letterSpacedWordGivenTails は「整 備する」「援 を行う」のように、行の折り返しや字間を空けた
// 組版で 1 字目だけが離れた文の断片の 2 語目に現れる形。
var letterSpacedVerbTailRe = regexp.MustCompile(`^(?:を.*|.*(?:する|した|して|される|行う|図る|なる))$`)

// isLetterSpacedWord は、空白で 2 語に分かれた値 f0・f1 が氏名ではなく、字間を空けた見出し語
// （「主 催」「概 要」）や文の断片（「整 備する」「援 を行う」）かを返す。2026-11-13 に商工会議所・
// 県の催し案内と大学の計画書（PDF）で、項目行の次の行の person-name の偽陽性として実測した。
// つなげた語が一般語（主催・概要）になる 1 字 + 1 字の組と、2 語目が助詞「を」で始まるか
// 動詞の活用で終わる組を、姓名辞書に片側が一致していても氏名とみなさない。
func isLetterSpacedWord(f0, f1 string) bool {
	if letterSpacedVerbTailRe.MatchString(f1) {
		return true
	}
	return utf8.RuneCountInString(f0) == 1 && utf8.RuneCountInString(f1) == 1 && dict.IsCommonWord(f0+f1)
}

// rejectHandleDigits は「@<数字>」のように @ に直結する数字列（SNS・技術記事サイトの
// ユーザー名）を個人番号とみなさない。12 桁の数字だけのユーザー名は 1/11 の確率で検査用数字が
// 一致する（2026-11-13 に技術記事サイトのフォロー一覧で実測した偽陽性）。
func rejectHandleDigits(line string, start, end int) bool {
	return !strings.HasSuffix(line[:start], "@")
}

// rejectUjiReadingName は「<姓>氏<1 字>（…うじ…）」のように、読みに「うじ」を含む括弧が続く
// 「氏」を敬称とみなさない（名が「氏〜」の歴史上の人物。2026-11-13 に人名の曖昧さ回避の一覧で
// 実測した高再現率モードの偽陽性）。
var ujiReadingRe = regexp.MustCompile(`^氏[` + kanji + `][ ]?[（(][` + hiragana + ` ]*うじ`)

func rejectUjiReadingName(line string, start, end int) bool {
	return !ujiReadingRe.MatchString(line[end:])
}
