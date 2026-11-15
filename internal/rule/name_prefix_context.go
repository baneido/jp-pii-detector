package rule

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// 2026-11-15 の公開文書の走査（2,659 件）で、既定モードのルールが取りこぼしていた氏名の形
// （person-name-role-label）。これまでのパターンは値の直前を行頭・記号・一部の助詞に限っていたため、
// 活用語尾（「出席する<氏名>会長」「手掛けた<氏名>氏」）、接続の語（「<氏名>講師および<氏名>講師」
// 「同<氏名>准教授」）、カタカナ語（「<チーム名><氏名>監督」「<職業名><氏名>さん」）に直結する
// 氏名と、氏名と職名の間に空白が入る形（「<氏名> 教授が」「<姓> <名> 助教（」）を落としていた。
// 値はいずれも姓名辞書の完全分割（姓+名）か、空白区切りの「<辞書の姓> <名>」で検証し、
// 一般語・組織名・職名で終わる語は通さない。

// looseTitleFollow は職名・敬称の直後に来る区切り・助詞・接続の語。
const looseTitleFollow = `(?:[ 、。・，,！!）)（(」「がはのをにともへやらか]|および|及び|並びに|$)`

// spaceTitleTail は「<氏名> <職名>」の職名と、その後ろに続く本文の先頭。
const spaceTitleTail = `(?:先生|` + personTitleWords + `)(?:[（(がはのをにともへ、。]|ら[のがはとを]|[A-Za-z]|$)`

var (
	// personNameLoosePrefixTitleRe は「表彰式に出席する<氏名>会長」「<学部>の<氏名>講師および<氏名>講師が」
	// 「<大学>の<氏名>教授、同<氏名>准教授、」「<職業名のカタカナ><氏名>さんによる」。値の直前は
	// ひらがな・「同」・カタカナ 2 字以上のいずれか（行頭・記号・助詞の直後は既存のパターンが拾う）。
	// 行末の「<氏名>氏」「<氏名>さん」は、既存の personNameStrictHonorificRe と同じく高再現率の
	// 敬称ルールの範囲として残す（既定モードは後ろに文が続く形だけ）。
	personNameLoosePrefixTitleRe = regexp.MustCompile(
		`(?:[` + hiragana + `]|同|[` + katakana + `]{2})([` + kanji + `]{3,6}?)` +
			`(?:(?:` + personTitleWords + `|弁護士)` + looseTitleFollow +
			`|(?:さん|氏)(?:[ 、。・，,！!）)（(」「がはのをにともへやらか]|および|及び|並びに))`,
	)
	// personNameTitleConjRe は「<学部>の<氏名>講師および<氏名>講師が」の 1 人目のように、職名の直後に
	// 接続の語（および・及び・並びに）やかぎ括弧が続く形。値の直前は既存のパターンと同じ。
	personNameTitleConjRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|[のにでとはがをもへや])([` + kanji + `]{3,6}?)` +
			`(?:` + personTitleWords + `|弁護士)(?:および|及び|並びに|「)`,
	)
	// personNameAthleteRe は「<競技名のカタカナ><氏名>選手を」「<チーム名><氏名>監督らが」
	// 「<事業名> <氏名>選手<催しの名前>」「<チーム名><姓> <名>選手「」。値の直前は漢字以外。
	// 「選手権」「選手団」「監督官」のように別の語になる続きは rejectAthleteTail で棄却する。
	// 空白区切りの値と空白のない値は別の正規表現にする（1 つにまとめると「<事業名> <氏名>選手」を
	// 空白区切りの値として先に取り、検証で落ちて後ろの形を試さないため）。
	personNameAthleteRe = regexp.MustCompile(
		`(?:^|[^` + kanji + `])([` + kanji + `]{3,6}?)(?:選手|監督)`,
	)
	personNameAthleteSpacedRe = regexp.MustCompile(
		`(?:^|[^` + kanji + `])([` + kanji + `]{1,4}[ ]{1,2}[` + kanji + `]{1,4})(?:選手|監督)`,
	)
	// personNameSpaceTitleRe は「<氏名> 先生Webページ」「<姓> <名> 助教（<所属>）とその研究チーム」
	// 「<学科>の<氏名> 教授が」のように、氏名と職名の間に空白が 1 個入り、職名の後に本文が続く形
	// （行末・括弧閉じで終わる形は既存の personNameAffiliationTitleRe が拾う）。
	personNameSpaceTitleRe = regexp.MustCompile(
		`(?:^|[^` + kanji + katakana + `])([` + kanji + `]{3,6})[ ]` + spaceTitleTail,
	)
	personNameSpaceTitleSpacedRe = regexp.MustCompile(
		`(?:^|[^` + kanji + katakana + `])([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + `]{1,4})[ ]` + spaceTitleTail,
	)
	// personNameTitleSpaceParticleRe は「学長 <氏名>からのメッセージ」「代表取締役社長・CEO <姓> <名>が「…」を受章」
	// のように、職名・空白・氏名の後に助詞が続く形（行末で終わる形は personNameTitleNameLineEndRe が拾う）。
	personNameTitleSpaceParticleRe = regexp.MustCompile(
		`(?:会長|理事長|代表理事|所長|館長|学長|総長|院長|園長|校長|社長|頭取|委員長|センター長|CEO|COO|CFO|CTO)[ ]+` +
			`([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + `]{1,4}|[` + kanji + `]{3,6}?)(?:から|より|が|は|による|の[^` + kanji + `])`,
	)
	// personNameKanaGivenSanRe は「<姓><ひらがなの名>さんと<市長>の対談」のように、名がひらがなの氏名に
	// 「さん」が続く形。姓は姓の辞書、名は名の辞書に一致することを要求する（validKanaGivenName）。
	personNameKanaGivenSanRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|[のでとはがにをもへ])([` + kanji + `]{1,3}[` + hiragana + `]{2,4}?)さん` +
			`(?:[ 、。・，,！!）)（(」がはのをにともへや]|$)`,
	)
	// personNameChairKunRe は会議録の「<委員会名>委員長<氏名>君。」（委員長報告の指名）。
	personNameChairKunRe = regexp.MustCompile(
		`委員長([` + kanji + `]{2,4}[` + kanji + hiragana + `]{1,4}?)君。`,
	)
	// personNameColonOrgTitleRe は「<日付>：<姓> <名> <大学><職名> <本文>」のように、コロンの後に
	// 空白区切りの氏名・所属 + 職名が続き、その後ろに空白を挟んで本文が続く形（大学の受賞の一覧）。
	personNameColonOrgTitleRe = regexp.MustCompile(
		`[：:][ ]*([` + kanji + `]{1,4}[ ]{1,2}[` + kanji + `]{1,4})[ ]+[^ ]{2,20}?(?:` + personTitleWords + `)[ ]`,
	)
)

// validLooseTitleName は活用語尾・接続の語・カタカナ語に直結する値を検証する。姓名辞書の完全分割に
// 加えて、値全体が一般語・姓 1 つ・組織名・職名で終わる語でないことを要求する。
func validLooseTitleName(v string) bool {
	v = strings.TrimSpace(v)
	if !notOrgName(v) || !notPlaceholderName(v) || endsWithTitleWord(v) {
		return false
	}
	// 「<姓>栄誉教授」「<姓>厚生大臣」のように、職名の前に付く語（栄誉・特別・主任、省庁の名前）まで
	// 名として取り込んだ形は通さない（2026-11-15 に大学のニュースと国会の会議録で実測）。
	for _, s := range titleModifierTails {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	if strings.Contains(v, " ") {
		return validSpacedHonorificName(v)
	}
	return utf8.RuneCountInString(v) >= 3 && validPersonNameFullSplit(v) && !dict.IsCommonWord(v) && !dict.IsSurname(v)
}

// titleModifierTails は職名の前に付く語。値がこれで終わるときは「<姓> + 職名の一部」とみなす。
var titleModifierTails = []string{
	"栄誉", "特別", "主任", "客員", "上席", "招聘", "特命", "特任", "名誉", "担当", "国務", "総理", "官房",
	"厚生", "厚労", "総務", "外務", "財務", "法務", "防衛", "環境", "文部", "文科", "農水", "農林", "国交", "経産",
	"大蔵", "通産", "運輸", "建設", "郵政", "自治", "労働", "復興", "内閣",
}

// looseNameStopHeads は活用語尾の直後に来る、氏名ではない語の先頭（「出席した各委員会長」
// 「参加した全国会長」など、連体修飾の語が姓の辞書と同形になる形）。
var looseNameStopHeads = []string{"各", "全", "当", "本", "同", "両", "元", "前", "現", "新", "副", "次期", "歴代", "初代"}

// rejectLoosePrefixFragment は personNameLoosePrefixTitleRe の値の追加検証。
func rejectLoosePrefixFragment(line string, start, end int) bool {
	v := line[start:end]
	for _, h := range looseNameStopHeads {
		if strings.HasPrefix(v, h) {
			return false
		}
	}
	return rejectStrictHonorificFragment(line, start, end) && rejectShiInsideGivenName(line, start, end)
}

// athleteWordTails は「選手」の直後に続くと別の語になる字（選手権・選手団・選手会・選手村・
// 選手名・選手宣誓・選手生命・選手層・選手寿命・選手間）。
const athleteWordTails = "権団会村名宣生層寿間"

// rejectAthleteTail は personNameAthleteRe の値の後ろを確かめる。「選手権」のように別の語になる形と、
// 「監督」の後に漢字が続く形（監督官・監督署・監督下）を棄却する。
func rejectAthleteTail(line string, start, end int) bool {
	rest := line[end:]
	switch {
	case strings.HasPrefix(rest, "選手"):
		next, _ := utf8.DecodeRuneInString(rest[len("選手"):])
		if strings.ContainsRune(athleteWordTails, next) {
			return false
		}
	case strings.HasPrefix(rest, "監督"):
		next, _ := utf8.DecodeRuneInString(rest[len("監督"):])
		if (next >= 0x4E00 && next <= 0x9FFF) || next == 0x3005 {
			return false
		}
	}
	before := strings.TrimRight(line[:start], " ・")
	if strings.HasSuffix(before, "故") {
		return false
	}
	return rejectPostTitleFragment(line, start, end)
}

// validKanaGivenName は「<姓><ひらがなの名>」を検証する。漢字の部分が姓の辞書に、ひらがなの部分が
// 名の辞書に一致することを要求する（「皆さま」「森のくま」は通らない）。
func validKanaGivenName(v string) bool {
	v = strings.TrimSpace(v)
	i := 0
	for i < len(v) {
		r, size := utf8.DecodeRuneInString(v[i:])
		if r >= 0x3041 && r <= 0x309E {
			break
		}
		i += size
	}
	sur, given := v[:i], v[i:]
	if sur == "" || given == "" || !notOrgName(v) || !notPlaceholderName(v) {
		return false
	}
	return dict.IsSurname(sur) && dict.IsGivenName(given) && !dict.IsCommonWord(given) && !dict.IsCommonWord(v)
}
