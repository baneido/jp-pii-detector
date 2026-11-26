package rule

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// 2026-11-16 の公開文書の走査（6,842 件）で、既定モードのルールが取りこぼしていた氏名の形
// （person-name-role-label）。会議録の指名「次に、<氏名>君。」、括弧の中の「（<姓> <名>社長）」
// 「（<氏名>名誉会員）」、活用語尾に続く「式辞を述べる<氏名>町長」。値はいずれも姓名辞書の
// 完全分割（姓+名）か、空白区切りの「<辞書の姓> <名>」で検証する。会議録の定型（発言者ラベル・
// 出席者の名簿）に限り、姓が辞書にない氏名を「名が辞書に一致」で採る（validKunStructuredName）。

// localTitleWords は personTitleWords に入っていない職名（自治体・学校・施設・議会・企業の役職）。
const localTitleWords = `副町長|町長|副村長|村長|副区長|区長|教育長|校長|館長|園長|所長|副議長|議長|議員|` +
	`支店長|工場長|署長|団長|部長|課長|室長|局長|名誉会員`

var (
	// personNameKunCallPunctRe は会議録の指名「○<委員長>　次に、<氏名>君。」「順次これを許します。<氏名>君。」。
	// 既存の personNameKunCallRe は直前が「君）」の形（○議長（<氏名>君）　<氏名>君。）だけを拾っていた。
	// 「君。」で文が終わる呼びかけに限り、値は validKunName（姓だけの「<姓>君。」は通らない）。
	personNameKunCallPunctRe = regexp.MustCompile(
		`[、。][ ]?([` + kanji + `]{3,6}|[` + kanji + `]{1,4}[` + hiragana + `]{2,5})君。`,
	)
	// personNameParenTitleRe は「<社名>（<姓> <名>社長）は、」「第 99 代会長（<氏名>名誉会員）を」のように、
	// 括弧の中が氏名 + 職名だけの形。空白区切りの値と空白のない値は別の正規表現にする。
	personNameParenTitleRe = regexp.MustCompile(
		`[（(]([` + kanji + `]{3,6}?)(?:代表取締役)?(?:` + personTitleWords + `|` + localTitleWords + `)[）)]`,
	)
	personNameParenTitleSpacedRe = regexp.MustCompile(
		`[（(]([` + kanji + `]{1,4}[ ]{1,2}[` + kanji + `]{1,4})(?:代表取締役)?(?:` + personTitleWords + `|` + localTitleWords + `)[）)]`,
	)
	// personNameLoosePrefixLocalTitleRe は「式辞を述べる<氏名>町長」「あいさつする<氏名>校長」のように、
	// 活用語尾に続く氏名 + 自治体・学校・施設の職名（personNameLoosePrefixTitleRe の職名の追加）。
	personNameLoosePrefixLocalTitleRe = regexp.MustCompile(
		`(?:[` + hiragana + `]|同)([` + kanji + `]{3,6}?)(?:` + localTitleWords + `)` + looseTitleFollow,
	)
)

// kunSurnameStopTails は会議録の名簿で、氏名の前に置かれる職名の末字（「理事 <姓>君」「委員長 <姓>君」の
// 職名を姓と読まないため）。
var kunSurnameStopTails = []string{"長", "員", "事", "官", "臣", "人", "部", "課", "係", "室", "会", "所", "局", "科", "者"}

// validKunStructuredName は会議録の発言者ラベル「○議長（<氏名>君）」と出席者の名簿「<姓>　<名>君」の値を
// 検証する。validKunName（姓名辞書の完全分割か「<辞書の姓> <名>」）に加えて、姓が辞書にない氏名を
// 「名が名の辞書に一致し、姓が 1〜3 字の漢字で職名の末字で終わらない」ときに採る。空白のない値は
// allowUnspaced（発言者ラベルの括弧内）のときだけ、後ろ 2〜3 字が名の辞書に一致する分割を試す。
// 2026-11-16 に国会の会議録で、姓が辞書にない議員（一般語と同形の姓を含む）の見逃しを実測した。
func validKunStructuredName(allowUnspaced bool) func(string) bool {
	return func(v string) bool {
		if validKunName(v) {
			return true
		}
		t := strings.TrimSpace(v)
		if t == "" || !notPlaceholderName(t) || !notOrgName(t) {
			return false
		}
		f := strings.Fields(t)
		switch {
		case len(f) == 2:
			return looseKunPair(f[0], f[1])
		case len(f) == 1 && allowUnspaced:
			r := []rune(t)
			if dict.IsCommonWord(t) || dict.IsSurname(t) {
				return false
			}
			for g := 2; g <= 3; g++ {
				if len(r)-g >= 2 && looseKunPair(string(r[:len(r)-g]), string(r[len(r)-g:])) {
					return true
				}
			}
			// 1 字の名（2026-11-17 に実測した見逃し。looseKunSingleGiven）。
			if len(r) >= 3 && looseKunSingleGiven(string(r[:len(r)-1]), string(r[len(r)-1:])) {
				return true
			}
			// 名が辞書にない氏名（2026-11-26 に実測した見逃し。looseKunSurnameFirst）。
			for s := 2; s <= 3; s++ {
				if len(r)-s == 2 && looseKunSurnameFirst(string(r[:s]), string(r[s:])) {
					return true
				}
			}
		}
		return false
	}
}

// looseKunSurnameFirst は発言者ラベルの括弧内・登壇の注記「〔<氏名>君登壇〕」で、名が辞書にない氏名を
// 「姓が姓の辞書に一致する 2〜3 字、名が 2 字の漢字で一般語・姓・職名の末字でない」ときに採る
// （2026-11-26 に 1950 年代の国会の会議録で実測した見逃し「〔<姓><辞書にない名>君登壇〕」）。
func looseKunSurnameFirst(sur, given string) bool {
	if utf8.RuneCountInString(given) != 2 || !allKanji(sur) || !allKanji(given) {
		return false
	}
	if !dict.IsSurname(sur) || dict.IsCommonWord(given) || dict.IsSurname(given) || spacedGivenStopwords[given] || endsWithTitleWord(given) {
		return false
	}
	for _, t := range kunSurnameStopTails {
		if strings.HasSuffix(given, t) {
			return false
		}
	}
	return true
}

func looseKunPair(sur, given string) bool {
	ns, ng := utf8.RuneCountInString(sur), utf8.RuneCountInString(given)
	if ns < 1 || ns > 3 || ng < 2 || ng > 4 || !allKanji(sur) {
		return false
	}
	if !dict.IsGivenName(given) || dict.IsCommonWord(given) || spacedGivenStopwords[given] || endsWithTitleWord(sur) {
		return false
	}
	for _, s := range kunSurnameStopTails {
		if strings.HasSuffix(sur, s) {
			return false
		}
	}
	return true
}

// rejectLocalTitleFragment は localTitleWords の職名に続く値の追加検証。「<姓>本部長」（本部の長）と
// 「<姓>第一部長」（第一部の長）は、姓の後ろの「本」「第一」まで名として取り込んだ形なので棄却する
// （2026-11-16 に国会の会議録と市のお知らせで、修正の途中に実測した範囲のずれ）。
func rejectLocalTitleFragment(line string, start, end int) bool {
	v := line[start:end]
	if strings.Contains(v, "第") || (strings.HasSuffix(v, "本") && strings.HasPrefix(line[end:], "部長")) {
		return false
	}
	return rejectPostTitleFragment(line, start, end)
}

// rejectParenTitleFragment は personNameParenTitleRe の値の追加検証。
func rejectParenTitleFragment(line string, start, end int) bool {
	return rejectLocalTitleFragment(line, start, end)
}

// rejectHonorificOrgOrPlace は高再現率の敬称パターンで、省庁の略称・一般の役割語・店や機関の
// 名前に付く「さん」「様」と、ひらがなの地名「さんりく」（三陸）を敬称とみなさない
// （2026-11-16 に国会の会議録・家電量販店のお知らせ・市の予防接種の案内・同郷会の名前で実測した
// 高再現率モードの偽陽性。「文科省さん」「荷主さん」「地域家電店様」「医療機関様」
// 「首都圏さんりく<地名>人会」。いずれも特定の個人を指さない）。
func rejectHonorificOrgOrPlace(line string, start, end int) bool {
	rest := line[end:]
	if strings.HasPrefix(rest, "さんりく") {
		return false
	}
	if !strings.HasPrefix(rest, "さん") && !strings.HasPrefix(rest, "様") {
		return true
	}
	v := line[start:end]
	if v == "荷主" || v == "事業所" {
		return false
	}
	for _, s := range []string{"省", "機関", "家電店", "量販店", "代理店", "加盟店",
		// 「<地名>保育園様」「<姓>農園さん」は施設・事業者の名前（2026-11-17 に企業の導入事例と市の給食だよりで実測）。
		"保育園", "幼稚園", "こども園", "保育所", "農園", "牧場", "事業所", "工房", "酒造", "薬局"} {
		if strings.HasSuffix(v, s) && utf8.RuneCountInString(v) > utf8.RuneCountInString(s) && !dict.IsPersonName(v) {
			return false
		}
	}
	return true
}

// birthdateOldestYear は jp-birthdate が報告する最も古い生年。これより前に生まれた人は存命では
// ないので（個人情報保護法の個人情報は生存する個人の情報）、歴史上の人物の「生年月日 明治元年…」を
// 報告しない（2026-11-16 に省庁の歴代大臣の紹介ページで実測した偽陽性）。
const birthdateOldestYear = 1908

// rejectTimestampFileName は jp-my-number の 4-4-4 のハイフン区切りが、URL・ファイル名の中の
// 「<西暦年>-<月日>-<時分>」（CMS が付ける 2015-0612-1014.pdf のような名前）である場合に棄却する
// （2026-11-16 に市の PDF の URL で実測した偽陽性。検査用数字が偶然一致していた）。
// 直前が「/」か、直後が拡張子（.pdf など）のときだけを対象にする。
var timestampFileNameRe = regexp.MustCompile(`^(?:19|20)\d{2}-(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-(?:[01]\d|2[0-3])[0-5]\d$`)
var fileExtTailRe = regexp.MustCompile(`^\.[A-Za-z]{2,5}(?:[^A-Za-z]|$)`)

func rejectTimestampFileName(line string, start, end int) bool {
	if !timestampFileNameRe.MatchString(line[start:end]) {
		return true
	}
	if strings.HasSuffix(line[:start], "/") || strings.HasSuffix(line[:start], "_") || fileExtTailRe.MatchString(line[end:]) {
		return false
	}
	return true
}
