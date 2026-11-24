package rule

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// 2026-11-24 の公開文書の走査（7,564 件）で、既定モードのルールが取りこぼしていた氏名の形
// （person-name-role-label）と、同じ確認で見つけた誤検出の棄却。人を指す語のある無作為 730 行に
// 人手で付けた正解（姓+名 106 人）のうち、既定モードが拾えたのは 73 人だった。偶数番の行の見逃しだけを
// 設計に使い、奇数番の行は検証用に残した。

var (
	// personNameSenseiEventRe は「<氏名>先生サイン会のお知らせ」「<氏名>先生卒寿を祝う会」のように、
	// 「先生」の直後に催しの名前が続く形（書店のお知らせ・団体の催し案内で実測。既存の
	// personNameSenseiParticleRe は「先生」の直後を区切り・助詞・行末に限っていた）。値は姓 + 名の
	// 完全分割を要求する。
	personNameSenseiEventRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|[のでとはがにらをもへ])([` + kanji + `]{3,6}?)先生` +
			`(?:サイン会|トークショー|トークイベント|講演会|特別講演|記念講演|特別講義|最終講義|公開講座|還暦|古希|古稀|喜寿|傘寿|米寿|卒寿|白寿|退職記念|退官記念|受賞記念)`,
	)
	// personNameSpacedThenStaffLineEndRe は「<資格名>（<診療科>）　<姓> <名> 医師」のように、空白区切りの
	// 氏名・空白・医療職の名前で行が終わる形（病院の医師紹介で実測）。
	personNameSpacedThenStaffLineEndRe = regexp.MustCompile(
		`(?:^|[^` + kanji + `])(` + spacedKanjiName + `)[ ]{1,2}(?:医師|歯科医師|医長|薬剤師|看護師)[ ]*$`,
	)
	// personNameSenseiListRe は「・<氏名> 先生　・<氏名> 先生」のように、氏名・空白・「先生」の組が
	// 中黒や読点で並ぶ形の、行末以外の人（学会の講師一覧で実測。行末の 1 人だけ拾えていた）。
	personNameSenseiListRe = regexp.MustCompile(
		`(?:^|[^` + kanji + katakana + `])([` + kanji + `]{3,6})[ ]先生[ ]{1,3}[・、,，／/●○◎]`,
	)
	// personNameThenCommitteeParenRe は「<氏名>　委員（<大学名>教授）」のように、行頭の氏名・空白・
	// 会議体の役の名前に、所属と職名の括弧が続く形（団体の委員名簿で実測。既存のパターンは「委員」を
	// 名として取って検証で落としていた）。括弧の中が長く行をまたぐ名簿もあるので、括弧が閉じることは要求しない。
	personNameThenCommitteeParenRe = regexp.MustCompile(
		`^[ ]*([` + kanji + `]{3,6}|` + spacedKanjiName + `)[ ]{1,2}(?:副委員長|委員長|委員|副会長|会長|座長|理事|監事|幹事|顧問)[ ]?` +
			`[（(][^（）()]{2,}`,
	)
	// personNameOrgAttachedTitleRe は「<研究所名><氏名>社長（当時）の会見」のように、組織の名前に氏名と
	// 役員の職名が空白なしで続く形（団体の沿革で実測。既存のパターンは氏名の直前に区切りか助詞を
	// 要求していた）。組織の語尾を手がかりにし、値は姓 + 名の完全分割を要求する。
	personNameOrgAttachedTitleRe = regexp.MustCompile(
		`(?:研究所|株式会社|協会|機構|財団|連合会|新聞社|銀行|公社|公団|事業団|商工会議所|ホールディングス|グループ)` +
			`([` + kanji + `]{3,6}?)(?:副社長|社長|副会長|会長|理事長|所長|頭取)(?:[（(、。がはのをにともへ]|$)`,
	)
)

// 以下は、同じ確認で検出の付いていない「氏名らしい行」（検出器と関係ない正規表現で抜き出した 170 行）を
// 読んで見つけた見逃しの形。
var (
	// personNameHeadColonLineEndRe は「院長：<姓> <名>」「副院長：<姓> <名>」のように、施設の長の職名・
	// コロン・氏名で行が終わる形（病院の概要で実測。「副会長：」「看護部長：」は拾えていた）。
	personNameHeadColonLineEndRe = regexp.MustCompile(
		`(?:^|[ ・、])(?:名誉|副|前|元)?(?:病院長|院長|センター長|施設長|事務長|事務局長|所長|館長|園長|校長|学長|理事長|技師長|師長|総監督|監督)` +
			`[ ]?[:：][ ]?(` + spacedKanjiName + `|[` + kanji + `]{3,6})[ ]*$`,
	)
	// personNameTitleDesuRe は「<学科名>の<氏名>講師です。」のように、氏名に直結した職名の後が「です」で
	// 終わる文（大学の記事で実測。既存のパターンは職名の後を区切り・助詞・行末に限っていた）。
	personNameTitleDesuRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|[のにでとはがをもへや])([` + kanji + `]{3,6}?)(?:` + personTitleWords + `)(?:です|でした|である)`,
	)
	// personNameParenOrgRe は「委員 <氏名>（<大学名>），<氏名>（<大学名>）」のように、空白のない氏名の直後の
	// 括弧が大学・研究所・病院の名前で終わる形（学会の委員一覧・発表者一覧で実測。空白区切りの氏名は
	// 拾えていた）。氏名と括弧の間の敬称（「<氏名>氏（<研究所名>）」）は値に含めない。
	personNameParenOrgRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `])([` + kanji + `]{3,6}?)(?:氏|さん|先生|様)?[（(][^（）()]{0,16}?(?:大学|大学院|高専|高等専門学校|研究所|研究センター|病院)[）)]`,
	)
	// personNameSpacedAttachedDoctorRe は「<センター名> <姓> <名>医師の記事が掲載されました」のように、
	// 空白区切りの氏名に「医師」が直結する形（病院のお知らせで実測。空白のない氏名は拾えていた）。
	personNameSpacedAttachedDoctorRe = regexp.MustCompile(
		`(?:^|[^` + kanji + `])(` + spacedKanjiName + `)医師(?:[ 、。・，,！!）)（(」がはのをにともへやらか]|$)`,
	)
	// personNameTitleNameThenParenRe は「理事長　<氏名>　（<流派名>家元）」のように、職名・空白・空白のない
	// 氏名の後に、空白を挟んで括弧の補足が続く形（団体の役員紹介で実測。行末で終わる形は拾えていた）。
	personNameTitleNameThenParenRe = regexp.MustCompile(
		`(?:会長|副会長|理事長|代表理事|専務理事|常務理事|理事|監事|施設長|所長|館長|学長|院長|園長|校長|社長|代表|委員長|センター長)[ ]+` +
			`([` + kanji + `]{3,6})[ ]+[（(]`,
	)
	// personNameSpacedThenCoachLineRe は「<姓> <名> 総監督」のように、行全体が空白区切りの氏名・空白・
	// 競技の指導者の役の名前である形（大学の運動部の紹介で実測）。
	personNameSpacedThenCoachLineRe = regexp.MustCompile(
		`^[ ]*(` + spacedKanjiName + `)[ ]{1,2}(?:総監督|監督|ヘッドコーチ|コーチ|主将)[ ]*$`,
	)
)

// pseudonymMarkRe は氏名の直後（敬称を挟んでもよい）の「（仮名）」「＝仮名」。
var pseudonymMarkRe = regexp.MustCompile(`^[ ]?(?:さん|氏|様|君|くん|ちゃん|先生)?[ ]?(?:[（(][ ]?仮名[ ]?[）)、・]|[=＝・][ ]?仮名)`)

// PseudonymMarked は line[start:end] の氏名の直後に「（仮名）」の印があるかを返す。2026-11-24 に大学の
// 連載記事「<部署名>、<氏名>さん（仮名）」で person-name-role-label の偽陽性として実測した。仮名は本人を
// 特定させないために付けた名前で、特定の個人を識別する情報ではない。
func PseudonymMarked(line string, start, end int) bool {
	if start < 0 || end > len(line) || start > end {
		return false
	}
	_, lineEnd := physicalLineBounds(line, start, end)
	return pseudonymMarkRe.MatchString(line[end:lineEnd])
}

// mournedAfterRe は氏名の直後（敬称を挟んでもよい）の「を偲んで」「を悼む」「追悼」。
var mournedAfterRe = regexp.MustCompile(`^[ ]?(?:さん|氏|様|君|先生)?[ ]?(?:を偲|をしのぶ|をしのん|を悼|追悼)`)

// MournedAfter は line[start:end] の氏名の直後に「を偲んで」「追悼」が続くかを返す。2026-11-24 に美術館の
// 連載の題名「<氏名>さんを偲んで」で実測した。亡くなった人の氏名は、個人情報保護法の個人情報
// （生存する個人に関する情報）ではない。
func MournedAfter(line string, start, end int) bool {
	if start < 0 || end > len(line) || start > end {
		return false
	}
	_, lineEnd := physicalLineBounds(line, start, end)
	return mournedAfterRe.MatchString(line[end:lineEnd])
}

// isMunicipalityFullName は v が「<名前>町」「<名前>市」のように、自治体の種類の字で終わる実在の
// 市区町村・都道府県の名前かを返す。2026-11-24 に自治体の SNS アカウントの一覧「名前：<町名>」で
// person-name の偽陽性として実測した（姓の辞書に同形の語があり、氏名のラベルの値として通っていた）。
func isMunicipalityFullName(v string) bool {
	v = strings.TrimSpace(v)
	if strings.ContainsAny(v, " \t") {
		return false
	}
	r, _ := utf8.DecodeLastRuneInString(v)
	if !strings.ContainsRune("都道府県市区町村", r) {
		return false
	}
	return dict.IsMunicipalityOrPrefecture(v)
}

// honorificShopNouns は敬称の前に来る、取引先の種類を表す一般語（2026-11-24 に企業の導入事例
// 「代理店様が同システムから」と自治体の案内「新婚さんはおトクな」で実測した高再現率モードの偽陽性）。
var honorificShopNouns = map[string]bool{
	"代理店": true, "販売店": true, "取扱店": true, "加盟店": true, "協力店": true, "小売店": true, "量販店": true, "専門店": true,
	"新婚": true, "新婚夫婦": true,
}

// companyMarkBeforeRe は値の直前が法人の種類の印（㈱・（株）・(有)）である形。
var companyMarkBeforeRe = regexp.MustCompile(`(?:㈱|㈲|[（(](?:株|有|同|社|財|医)[）)])[ ]?$`)

// ujiResidenceTails は「<氏族名>氏屋敷」のように、氏の後に続くと屋敷・居館の名前になる語。
var ujiResidenceTails = []string{"屋敷", "邸", "旧宅", "居館", "館", "城"}

// honorificDeceasedTails は「<氏名>さんを偲んで」のように、敬称の後に続くと亡くなった人を示す語。
var honorificDeceasedTails = []string{"を偲", "をしのぶ", "をしのん", "を悼", "追悼", "逝去", "のご逝去", "の訃報", "死去"}

// rejectHonorificShopOrClan は高再現率の敬称パターンで、次の形を敬称付きの氏名とみなさない
// （2026-11-24 に企業の導入事例・自治体の案内・団体のお知らせ・史跡の案内・美術館の連載で実測した
// 偽陽性。いずれも特定の生存する個人を指さない）。
//   - 代理店様・新婚さん（honorificShopNouns）
//   - ㈱<社名>さん（法人の印の直後）
//   - <社名>殿グループ（「殿」で終わる社名）
//   - 優良さんぱいナビ（「さんぱい」= 産廃）
//   - <氏族名>氏屋敷、<地名><氏族名>氏（鎌倉北条氏のように地名を冠した一族）
//   - <氏名>さんを偲んで（亡くなった人）
func rejectHonorificShopOrClan(line string, start, end int) bool {
	v := line[start:end]
	lineStart, lineEnd := physicalLineBounds(line, start, end)
	rest := strings.TrimLeft(line[end:lineEnd], " ")
	if honorificShopNouns[v] {
		return false
	}
	if companyMarkBeforeRe.MatchString(line[lineStart:start]) {
		return false
	}
	if strings.HasPrefix(rest, "さんぱい") || strings.HasPrefix(rest, "殿グループ") {
		return false
	}
	if after, ok := strings.CutPrefix(rest, "氏"); ok {
		for _, t := range ujiResidenceTails {
			if strings.HasPrefix(after, t) {
				return false
			}
		}
		if isPlacePrefixedClan(v) {
			return false
		}
	}
	for _, h := range []string{"さん", "氏", "様", "先生"} {
		if after, ok := strings.CutPrefix(rest, h); ok {
			for _, t := range honorificDeceasedTails {
				if strings.HasPrefix(after, t) {
					return false
				}
			}
		}
	}
	return true
}

// isPlacePrefixedClan は v が「<地名><姓>」（鎌倉北条・小田原北条）の形かを返す。先頭が市区町村の名前
// （「市」「町」を補って実在する 2〜3 字）で、残りが 2 字の辞書の姓であり、残りが名の辞書に無いとき。
func isPlacePrefixedClan(v string) bool {
	rs := []rune(v)
	if len(rs) < 4 || len(rs) > 5 {
		return false
	}
	place, clan := string(rs[:len(rs)-2]), string(rs[len(rs)-2:])
	if !dict.IsSurname(clan) || dict.IsGivenNameExtended(clan) {
		return false
	}
	for _, s := range []string{"市", "町"} {
		if dict.IsMunicipalityOrPrefecture(place + s) {
			return true
		}
	}
	return false
}
