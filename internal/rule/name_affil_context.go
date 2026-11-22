package rule

import (
	"regexp"
	"strings"
)

// 2026-11-22 の公開文書の走査（7,736 件）で、既定モードのルールが取りこぼしていた氏名の形
// （person-name-role-label）と、同じ確認で見つけた誤検出の棄却。人を指す語のある無作為 461 行に
// 人手で付けた正解（姓+名 61 人）のうち、既定モードが拾えたのは 42 人だった。偶数番の行の見逃しだけを
// 設計に使い、奇数番の行は検証用に残した。

// affilUnitWords は「（<氏名><学科名>教授）」の所属の末尾の語。
const affilUnitWords = `学科|学部|研究科|専攻|学群|学類|学系|学府|研究院|研究所|センター|講座|分野`

// directorTitleWords は法人の役員の職名（役員の名簿・異動のお知らせ）。
const directorTitleWords = `代表理事|専務理事|常務理事|常任理事|副理事長|理事長|理事|監事|評議員|幹事|顧問|参与|副会長|会長`

// selfOrgWords は「当社 <姓> <名>が登壇」のように、自分の組織を指す語。
const selfOrgWords = `当社|弊社|当行|当会|当法人|当院|当協会|当財団|当組合|当事務所|本学|本校`

var (
	// personNameParenAffilTitleNRe は「<研究室>（<氏名><学科名>教授）に所属した」のように、括弧の中で
	// 氏名に所属 + 教員の職名が直結する形を、氏名の字数（3〜5 字）ごとに分けたもの（大学のニュースで実測）。
	// 所属の名前は正規表現で区切れないので、氏名の字数を固定して姓名辞書の完全分割で確かめる。
	personNameParenAffilTitle3Re = parenAffilTitleRe(3)
	personNameParenAffilTitle4Re = parenAffilTitleRe(4)
	personNameParenAffilTitle5Re = parenAffilTitleRe(5)
	// personNameKunSubstituteRe は会議録の委員の異動「委員<氏名>君辞任につき、その補欠として<氏名>君が」
	// 「補欠として<氏名>君及び<氏名>君が議長の指名で」の氏名（1960〜70 年代の国会の会議録で実測。
	// 既存の「<氏名>君」のパターンは発言者の印・名簿の空白・登壇の注記が必要だった）。値は「君」を含めない。
	personNameKunSubstituteRe = regexp.MustCompile(
		`(?:委員|理事|として|及び|並びに)[ ]?([` + kanji + `][` + kanji + hiragana + `]{1,6}?)君` +
			`(?:辞任|及び|並びに|が議長|が委員|が理事|が選任|が補欠|を委員|を理事|の補欠)`,
	)
	// personNameKunAndRe は上の形の 2 人目「<氏名>君及び<氏名>君が」。1 人目のパターンが「及び」まで
	// 読むので、2 人目は別のパターンで拾う。
	personNameKunAndRe = regexp.MustCompile(
		`君(?:及び|並びに)([` + kanji + `][` + kanji + hiragana + `]{1,6}?)君(?:が|を|の|、|。|[ ]|$)`,
	)
	// personNameSpacedParenAffilTitleRe は「[就任]<姓> <名>( <大学> <学部> <講座> 教授 )」のように、
	// 空白区切りの氏名の後の括弧が所属で始まり教員の職名で終わる形（学会の人事のお知らせで実測。
	// 既存のパターンは括弧の中が 20 字までだった）。
	personNameSpacedParenAffilTitleRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `])([` + kanji + `]{1,4}[ ]{1,2}[` + kanji + `]{1,4})[ ]?[（(][ ]?[^（）()]{2,60}?` +
			`(?:` + personTitleWords + `)[ ]?[）)]`,
	)
	// personNameTitleSpaceNameCloseRe は「<病院名>（<所在地> 理事長・院長 <氏名>）と覚書を」のように、
	// 職名・空白・氏名で括弧が閉じる形（企業のお知らせで実測）。
	personNameTitleSpaceNameCloseRe = regexp.MustCompile(
		`(?:` + honorificSpaceTitleWords + `|` + localTitleWords + `|` + personTitleWords + `)[ ]+` +
			`([` + kanji + `]{1,4}[ ][` + kanji + `]{1,4}|[` + kanji + `]{3,6})[）)]`,
	)
	// personNameSelfOrgSpacedRe は「当社 <姓> <名>が登壇することを」のように、自分の組織を指す語・空白・
	// 空白区切りの氏名に助詞が続く形（企業の登壇のお知らせで実測）。
	personNameSelfOrgSpacedRe = regexp.MustCompile(
		`(?:` + selfOrgWords + `)[ ]+([` + kanji + `]{1,4}[ ][` + kanji + `]{1,4})(?:が|は|の|より|による)`,
	)
	// personNameTitleNoNameParticleRe は「当社社長の<氏名>のインタビュー記事が」のように、職名 + の + 氏名に
	// 助詞が続く形（企業のメディア掲載のお知らせで実測）。敬称が続く形は既存のパターンが拾う。
	personNameTitleNoNameParticleRe = regexp.MustCompile(
		`(?:` + honorificSpaceTitleWords + `|` + directorTitleWords + `)の([` + kanji + `]{3,6}?)(?:の|が|は|を|に|と|も|より)`,
	)
	// personNameDirectorAttachedRe は「<団体>の<氏名>常務理事にも」のように、氏名に法人の役員の職名が
	// 直結する形（団体の活動報告で実測。理事長・会長は既存のパターンが拾う）。
	personNameDirectorAttachedRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|[のにでとはがをもへや])([` + kanji + `]{3,6}?)(?:代表理事|専務理事|常務理事|常任理事|副理事長|副会長)` +
			`(?:[ 、。・，,！!）)（(」がはのをにともへやらか]|$)`,
	)
	// personNameDirectorStatusRe は「理事（理事長） <姓> <名>（重任）」のように、役員の職名・空白・氏名の後に
	// 就任の区分の括弧が続く形（公益法人の役員変更の公告で実測）。
	personNameDirectorStatusRe = regexp.MustCompile(
		`(?:` + directorTitleWords + `)(?:[（(][^（）()]{1,8}[）)])?[ ]+([` + kanji + `]{1,4}[ ][` + kanji + `]{1,4}|[` + kanji + `]{3,6})[ ]?` +
			`[（(](?:重任|新任|再任|就任|退任|辞任|留任|常勤|非常勤)[）)]`,
	)
	// personNameMarkedAffilLineRe は「◎<姓> <名> （元 <機関名>所長）」「<部門名> <姓> <名> （<団体名>専務理事）」の
	// ように、行頭の印・部門名の後に空白区切りの氏名があり、括弧の所属が職名で終わって行が終わる形
	// （団体の委員の名簿で実測。27 人の名簿で既定モードが拾えたのは 15 人だった）。行全体がこの形で
	// あることと、姓か名のどちらかが辞書にあることを要求する。
	personNameMarkedAffilLineRe = regexp.MustCompile(
		`^[ ]*(?:[◎○●◯〇・＊*※][ ]?)?(?:[` + kanji + `・]{2,10}(?:部門|部会|分野|委員会)[ ]+)?` +
			`([` + kanji + `]{1,4}[ ]{1,4}[` + kanji + `]{1,4})[ ]+[（(](?:元|前|現)?[ ]?[^ ]{2,40}?(?:` + affilLineTitleWords + `)[）)][ ]*$`,
	)
)

// affilLineTitleWords は名簿の行「<姓> <名> （<所属><職名>）」の括弧の末尾の職名。
const affilLineTitleWords = `名誉教授|准教授|教授|講師|助教|理事長|専務理事|常務理事|代表理事|理事|監事|副会長|会長|社長|所長|校長|学長|院長|館長|` +
	`顧問|参事|参与|部長|課長|室長|局長|主管|主幹|研究員|学環長|研究科長|学部長|センター長|コンサルタント|リサーチャー`

func parenAffilTitleRe(n int) *regexp.Regexp {
	return regexp.MustCompile(
		`[（(]([` + kanji + `]{` + string(rune('0'+n)) + `})[` + kanji + katakana + `]{2,12}?(?:` + affilUnitWords + `)` +
			`(?:特任|客員|名誉|特命)?(?:准教授|教授|講師|助教)[）)、]`,
	)
}

// rejectParenAffilFragment は personNameParenAffilTitleNRe の値の追加検証。次の形を棄却する。
//   - 値の直後が「学」「大学」で始まる（「（<県名>大学<学部>教授）」の「<県名>大」が姓 + 1 字の名に見える形）
//   - 値が「元」「前」「現」「故」で始まる（「（元<県名>大学<学部>教授）」の「元<県名>」が姓 + 名に見える形）
//   - 前後に逝去・享年などの語がある（亡くなった人）
func rejectParenAffilFragment(line string, start, end int) bool {
	rest := line[end:]
	if strings.HasPrefix(rest, "学") || strings.HasPrefix(rest, "大学") {
		return false
	}
	for _, h := range []string{"元", "前", "現", "故"} {
		if strings.HasPrefix(line[start:end], h) {
			return false
		}
	}
	return !deceasedNear(line, start, end)
}

// rejectFounderTitleName は personNameTitleNoNameParticleRe の値の追加検証。rejectTitleSpaceNameFragment に
// 加えて、職名の前に「初代」「先代」「創業者」がある形を棄却する（「初代社長の<氏名>が掲げた創業の精神」は
// 会社の沿革で、多くは存命でない創業者を指す。存命かどうかを文から判断できないので報告しない）。
func rejectFounderTitleName(line string, start, end int) bool {
	before := lastRunes(line[:start], 12)
	for _, w := range []string{"初代", "先代", "創業者", "創立者", "創設者"} {
		if strings.Contains(before, w) {
			return false
		}
	}
	return rejectTitleSpaceNameFragment(line, start, end)
}

// honorificRoleNounsWide は敬称の前に来る、取引上の立場・施設・職種を指す一般語（2026-11-22 に不動産会社の
// 案内「貸主様・借主様」、システム会社の案内「施設様のニーズ」、国会の会議録「看護婦さんたち」で実測した
// 高再現率モードの偽陽性。いずれも特定の個人を指さない）。
var honorificRoleNounsWide = map[string]bool{
	"貸主": true, "借主": true, "施設": true, "看護婦": true, "看護師": true, "保健婦": true, "保母": true,
}

// historicalClanTails は「<氏族名>氏」の後に続くと、その「氏」が武家・豪族の一族を指すことを示す語
// （2026-11-22 に自治体の文化財の案内「<氏族名>氏の支配下にあった」「<氏族名>氏・<氏族名>氏の系譜」
// 「<氏族名>氏の居城」で実測した高再現率モードの偽陽性。歴史上の一族で、生存する個人ではない）。
var historicalClanTails = []string{
	"の支配", "の系譜", "の居城", "の家臣", "の一族", "の滅亡", "の時代", "の領地", "の所領", "の城", "の庇護", "の勢力", "の拠点", "の菩提寺", "の家紋", "の家督",
	"が築城", "が築いた", "が支配", "が治め", "が滅", "に仕え", "に滅ぼされ", "に属し", "一族", "の功績が認められ",
}

// rejectHonorificRoleOrClan は高再現率の敬称パターンで、立場・施設・職種を指す一般語に付く敬称と、
// 歴史上の一族を指す「<氏族名>氏」を、敬称付きの氏名とみなさない。
func rejectHonorificRoleOrClan(line string, start, end int) bool {
	v := line[start:end]
	if honorificRoleNounsWide[v] {
		return false
	}
	rest, ok := strings.CutPrefix(strings.TrimLeft(line[end:], " "), "氏")
	if !ok {
		return true
	}
	// 「<氏族名>氏・<氏族名>氏の系譜」のように中黒で並ぶ形は、最後の氏族名の後の語で判定する。
	for {
		i := strings.Index(rest, "氏")
		if !strings.HasPrefix(rest, "・") || i < 0 || i > 16 {
			break
		}
		rest = rest[i+len("氏"):]
	}
	for _, t := range historicalClanTails {
		if strings.HasPrefix(rest, t) {
			return false
		}
	}
	return true
}

// deceasedNoticeWords は訃報・逝去のお知らせで氏名の近くに来る語（deceasedContextWords のうち、
// 遺族年金の届出のように存命の人の氏名の近くにも来る「遺族」「故人」「追悼」を除いたもの）。
var deceasedNoticeWords = []string{"享年", "逝去", "死去", "訃報", "永眠"}

// DeceasedNoticeNear は氏名のラベルに続く値（person-name）の前後 16 字に、亡くなったことを示す語が
// あるかを返す（2026-11-22 に自治体の訃報「氏名：<姓> <名>（享年<年齢>歳）」「【訃報】<職名> <姓> <名>の
// 逝去について」で実測した偽陽性。個人情報保護法の個人情報は生存する個人に関する情報）。
// line は値のある 1 行、start/end はバイトオフセット。
func DeceasedNoticeNear(line string, start, end int) bool {
	if start < 0 || end > len(line) || start > end {
		return false
	}
	before := lastRunes(line[:start], 16)
	after := firstRunes(line[end:], 16)
	for _, w := range deceasedNoticeWords {
		if strings.Contains(before, w) || strings.Contains(after, w) {
			return true
		}
	}
	return false
}
