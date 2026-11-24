package rule

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// 2026-11-23 の公開文書の走査（8,396 件）で、既定モードのルールが取りこぼしていた氏名の形
// （person-name-role-label）と、同じ確認で見つけた誤検出の棄却。人を指す語のある無作為 460 行に
// 人手で付けた正解（姓+名 58 人）のうち、既定モードが拾えたのは 41 人だった。偶数番の行の見逃しだけを
// 設計に使い、奇数番の行は検証用に残した。

var (
	// personNameSelfOrgAttachedTitleRe は「本学 <氏名>教授のコメントが掲載されました」のように、自分の組織を
	// 指す語・空白・氏名に教員や役員の職名が直結する形（大学のお知らせで実測。名が辞書に無い 1 字の名で、
	// 既存のパターンは姓 + 名の完全分割を要求していた）。前後の両方に手がかりがあるので、姓が辞書にあり、
	// 残りが 1〜2 字なら採る（validSurnamePlusShortGiven）。
	personNameSelfOrgAttachedTitleRe = regexp.MustCompile(
		`(?:` + selfOrgWords + `)[ ]+([` + kanji + `]{3,5})(?:` + personTitleWords + `)` +
			`(?:[ 、。・，,！!）)（(」がはのをにともへやらか]|$)`,
	)
	// personNameKessanShimeiRe は決算短信の表紙「代表者 （役職名）代表取締役社長 （氏名）<姓> <名>」
	// 「問合せ先責任者（役職名）経理部長 （氏名）<姓> <名> TEL …」のように、同じ行に「（役職名）」があり
	// 「（氏名）」の直後に空白区切りの氏名が続く形（上場企業の決算短信の PDF で実測。姓も名も辞書に無い
	// 氏名を取りこぼしていた）。「（役職名）」と「（氏名）」の 2 つの手がかりがそろうので、辞書に無い氏名も
	// 形と一般語でないことで採る（ValidUncommonSpacedName）。
	personNameKessanShimeiRe = regexp.MustCompile(
		`[（(]役職名[）)][^（）()]{2,40}[（(]氏名[）)][ ]*([` + kanji + `]{1,4}[ ]{1,12}[` + kanji + `]{1,4})(?:[ ]|$)`,
	)
	// personNameCrossTalkRe は「（<職業>・<氏名>氏×<氏名> 対談③）」のように、対談の相手を「×」で
	// つないだ形の 2 人目（団体の対談記事の題名で実測。1 人目は敬称で拾えていた）。「×」の直前が
	// 敬称か氏名で、直後の値が姓 + 名に完全分割でき、対談・鼎談・座談会の語が続くことを要求する。
	personNameCrossTalkRe = regexp.MustCompile(
		`(?:氏|さん|先生|[` + kanji + `])[ ]?[×✕][ ]?([` + kanji + `]{3,6})(?:氏|さん|先生)?[ ]?(?:対談|鼎談|座談会|トーク)`,
	)
)

// validSurnamePlusShortGiven は「<辞書の姓><1〜2 字の名>」の形の値を許可する。姓 + 名の完全分割が
// 成立する値に加えて、辞書の姓で始まり残りが 1〜2 字の漢字である値を採る（名が辞書に無い人）。
// 前後の両方に手がかりがあるパターン専用。値全体が一般語・姓 1 つ・組織名・職名で終わる語は通さない。
func validSurnamePlusShortGiven(v string) bool {
	v = strings.TrimSpace(v)
	if validLooseTitleName(v) {
		return true
	}
	if !notOrgName(v) || !notPlaceholderName(v) || endsWithTitleWord(v) || dict.IsCommonWord(v) || dict.IsSurname(v) ||
		dict.IsMunicipalityOrPrefecture(v) {
		return false
	}
	for _, s := range titleModifierTails {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	rs := []rune(v)
	// 姓は長いほうから試す（2 字の姓 + 1 字の名、3 字の姓 + 1 字の名 …）。
	for n := len(rs) - 1; n >= 2; n-- {
		given := string(rs[n:])
		if len(rs)-n <= 2 && dict.IsSurname(string(rs[:n])) && !dict.IsCommonWord(given) && !shortGivenStopRunes[given] {
			return true
		}
	}
	return false
}

// shortGivenStopRunes は「<姓><1 字>教授」の 1 字が名ではなく職名の一部・敬称である語。
var shortGivenStopRunes = map[string]bool{
	"准": true, "助": true, "元": true, "前": true, "現": true, "故": true, "副": true, "名": true, "氏": true, "新": true, "両": true,
	"特任": true, "客員": true, "名誉": true, "特命": true, "主任": true, "特別": true, "担当": true,
}

// spacedPlaceOrFacilityTailRe は空白区切りの 2 語目が施設・建物の名前である形（「<地名> 二番館」）。
var spacedPlaceOrFacilityTailRe = regexp.MustCompile(`(?:[一二三四五六七八九十0-9]+(?:番館|号館|番街|号棟|号店)|本館|別館|新館|会館|本店|支店|会場)$`)

// isSpacedPlaceOrFacility は、空白で 2 語に分かれた値が氏名ではなく、字間を空けた地名（「岡　山」
// 「福　井」）か、地名 + 施設の名前（「<地名> 二番館」）かを返す。2026-11-23 に大学の説明会の会場一覧
// （地名の見出しの次に日付・会場・電話の行が続く）と、介護施設の催し案内（「開催日：…」の次の行が
// 施設名）で、項目行に隣り合う person-name の偽陽性として実測した。姓の辞書に同形の語（岡・松原）が
// あっても、つなげた語が都道府県・市区町村の名前（「県」「市」などを補った形を含む）なら氏名ではない。
func isSpacedPlaceOrFacility(v string) bool {
	f := strings.Fields(strings.TrimSpace(v))
	if len(f) != 2 {
		return false
	}
	if spacedPlaceOrFacilityTailRe.MatchString(f[1]) {
		return true
	}
	if utf8.RuneCountInString(f[0]) != 1 || utf8.RuneCountInString(f[1]) != 1 {
		return false
	}
	joined := f[0] + f[1]
	if dict.IsMunicipalityOrPrefecture(joined) {
		return true
	}
	for _, s := range []string{"県", "市", "町", "村", "区"} {
		if dict.IsMunicipalityOrPrefecture(joined+s) || dict.MunicipalitySuffixMatch(joined+s) {
			return true
		}
	}
	return false
}

// animalProfileRe は動物の紹介ページで性別を示す印（「<名前> （メス）」「性別：オス」）。
var animalProfileRe = regexp.MustCompile(`[（(][ ]?(?:オス|メス|雄|雌|♂|♀)[ ]?[）)]|性別[ ]?[:：]?[ ]?(?:オス|メス|雄|雌|♂|♀)|[♂♀]`)

// AnimalProfileNear は lines[idx] の前 8 行・後ろ 4 行に、動物の性別を示す印（animalProfileRe）が
// あるかを返す。2026-11-23 に動物園の紹介ページ「<名前> （メス）／誕生日／<日付>／出生地」で
// jp-birthdate の偽陽性として実測した。動物の誕生日は個人情報ではない。
func AnimalProfileNear(lines []string, idx int) bool {
	lo, hi := idx-8, idx+4
	if lo < 0 {
		lo = 0
	}
	if hi >= len(lines) {
		hi = len(lines) - 1
	}
	for i := lo; i <= hi; i++ {
		if utf8.RuneCountInString(lines[i]) <= 60 && animalProfileRe.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

// honorificLeadInTitles は敬称の値の先頭に付くと、その後ろだけが氏名になる役職の語（honorificTitlePrefixes に
// 無いもの）。「入試広報課 課長代理<姓>様をお迎えしました」で、高再現率の無空白の敬称パターンが
// 「課長代理<姓>」を値にしていた（2026-11-23 に高校のお知らせで実測した範囲の誤り）。
var honorificLeadInTitles = []string{"課長代理", "部長代理", "所長代理", "課長補佐", "部長補佐", "係長", "主任", "主査", "主幹", "課長", "部長", "室長", "次長"}

// honorificAmountLeadRe は値の先頭が金額（「二千万円<姓>」）である形。
var honorificAmountLeadRe = regexp.MustCompile(`^[一二三四五六七八九十百千万億兆]+円`)

// splitHonorificLeadIn は高再現率の無空白の敬称パターンの値 v が、氏名でない語（「今」・金額・役職）から
// 始まるとき、その語を除いた残りを返す。会議録の「今<姓>さんの御質問は」（今 = いま）、「<金額>円<姓>さんが」、
// 「課長代理<姓>様」で、値が前の語まで含んでいた（2026-11-23 に国会の会議録と高校のお知らせで実測）。
// 残りが姓の辞書にあるか姓 + 名に完全分割でき、値全体は姓でも姓 + 名でもないときだけ分ける
// （「今」で始まる姓「今井」「今村」はそのまま通す）。
func splitHonorificLeadIn(v string) (rest string, ok bool) {
	isName := func(s string) bool {
		return utf8.RuneCountInString(s) >= 2 && (dict.IsSurname(s) || validPersonNameFullSplit(s))
	}
	if loc := honorificAmountLeadRe.FindStringIndex(v); loc != nil {
		return v[loc[1]:], isName(v[loc[1]:])
	}
	for _, t := range honorificLeadInTitles {
		if r, found := strings.CutPrefix(v, t); found {
			return r, isName(r)
		}
	}
	if r, found := strings.CutPrefix(v, "今"); found && !dict.IsSurname(v) && !dict.IsPersonName(v) && isName(r) {
		return r, true
	}
	return "", false
}

// rejectHonorificLeadIn は、値が splitHonorificLeadIn で分けられる形（氏名でない語から始まる）を棄却する。
// 氏名だけの範囲は personNameHonorificAfterLeadInRe が拾い直す。
func rejectHonorificLeadIn(line string, start, end int) bool {
	_, ok := splitHonorificLeadIn(line[start:end])
	return !ok
}

// personNameHonorificAfterLeadInRe は「今<姓>さん」「<金額>円<姓>さん」「課長代理<姓>様」の、前の語を除いた
// 氏名の範囲（rejectHonorificLeadIn で棄却した値の拾い直し）。
var personNameHonorificAfterLeadInRe = regexp.MustCompile(
	`(?:今|円|` + strings.Join(honorificLeadInTitles, "|") + `)([` + kanji + `]{2,6})(?:様|さん|氏|殿)`,
)

// validHonorificAfterLeadIn は personNameHonorificAfterLeadInRe の値を、姓の辞書か姓 + 名の完全分割で検証する。
func validHonorificAfterLeadIn(v string) bool {
	return notOrgName(v) && (dict.IsSurname(v) || validPersonNameFullSplit(v))
}

// rejectLeadInNotSplit は personNameHonorificAfterLeadInRe の追加検証。前の語（今・円・役職）を含めた値が
// 姓や氏名として成り立つとき（「今井さん」の「井」は 1 字なので一致しないが、「今村田さん」のような形）は
// 拾い直さない。前の語を含む値は元のパターンがそのまま報告する。
func rejectLeadInNotSplit(line string, start, end int) bool {
	head := line[:start]
	if strings.HasSuffix(head, "今") {
		whole := "今" + line[start:end]
		return !dict.IsSurname(whole) && !dict.IsPersonName(whole)
	}
	if strings.HasSuffix(head, "円") {
		return honorificAmountLeadRe.MatchString(lastKanjiNumeralRun(head))
	}
	return true
}

// lastKanjiNumeralRun は s の末尾の「<漢数字>円」を返す（無ければ空文字列）。
func lastKanjiNumeralRun(s string) string {
	body, ok := strings.CutSuffix(s, "円")
	if !ok {
		return ""
	}
	rs := []rune(body)
	i := len(rs)
	for i > 0 && strings.ContainsRune("一二三四五六七八九十百千万億兆", rs[i-1]) {
		i--
	}
	if i == len(rs) {
		return ""
	}
	return string(rs[i:]) + "円"
}

// honorificGenericNounsWide は敬称の前に来る、特定の個人を指さない一般語（2026-11-23 に結婚式場の案内
// 「新郎様・新婦様入場体験」で実測した高再現率モードの偽陽性）。
var honorificGenericNounsWide = map[string]bool{
	"新郎": true, "新婦": true, "新郎新婦": true, "両家": true, "媒酌人": true, "列席者": true, "参列者": true,
}

// pointedPersonsRe は「右四氏の御報告」「以上三氏」のように、人数を数える「<指示語><数>氏」。
var pointedPersonsRe = regexp.MustCompile(`^(?:右|左|上記|以上|前記|同|この|これら)?[一二三四五六七八九十両0-9]+$`)

// diseaseYouTails は「喘息様の症状」のように、病名に付く「様」（〜のような）の後に続く語。
var diseaseYouTails = []string{"の症状", "症状", "の発作", "発作", "の所見", "所見", "の病変", "病変", "の皮疹", "皮疹", "の疼痛", "疼痛", "の反応", "反応", "の変化", "の状態", "顔貌", "物質", "作用"}

// rejectHonorificGenericOrCount は高再現率の敬称パターンで、次の形を敬称付きの氏名とみなさない
// （2026-11-23 に結婚式場の案内・国会の会議録・病院の感染症の案内・神社の由緒で実測した偽陽性。
// いずれも特定の個人を指さない）。
//   - 新郎様・新婦様（honorificGenericNounsWide）
//   - 右四氏・以上三氏（人数を数える「氏」）
//   - 喘息様の症状（病名 + 様 = 〜のような）
//   - 渡来氏族（「氏族」の「氏」）、<氏族名>氏の歴史・氏遺跡
func rejectHonorificGenericOrCount(line string, start, end int) bool {
	v := line[start:end]
	rest := strings.TrimLeft(line[end:], " ")
	if honorificGenericNounsWide[v] {
		return false
	}
	if after, ok := strings.CutPrefix(rest, "氏"); ok {
		if pointedPersonsRe.MatchString(v) {
			return false
		}
		for _, t := range []string{"族", "の歴史", "遺跡", "館跡", "庭園", "の興亡", "の城下"} {
			if strings.HasPrefix(after, t) {
				return false
			}
		}
	}
	if after, ok := strings.CutPrefix(rest, "様"); ok && !dict.IsSurname(v) {
		for _, t := range diseaseYouTails {
			if strings.HasPrefix(after, t) {
				return false
			}
		}
	}
	return true
}

// 以下は、同じ確認で検出の付いていない「氏名らしい行」（検出器と関係ない正規表現で抜き出した 170 行）を
// 読んで見つけた見逃しの形。いずれも姓の辞書（空白区切り）か姓 + 名の完全分割（無空白）を要求する。
const spacedKanjiName = `[` + kanji + `]{1,4}[ ]{1,2}[` + kanji + `]{1,4}`

var (
	// personNameAttachedDoctorRe は「<氏名>さんと<氏名>医師のクロストーク」のように、氏名に「医師」が直結する形
	// （大学の催し案内で実測）。
	personNameAttachedDoctorRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|[のにでとはがをもへや])([` + kanji + `]{3,6}?)医師` +
			`(?:[ 、。・，,！!）)（(」がはのをにともへやらか]|$)`,
	)
	// personNameBreadcrumbRe は「トップ > 医師紹介 > <姓> <名>」のように、パンくずリストの末尾が氏名の形
	// （病院の医師紹介ページで実測）。
	personNameBreadcrumbRe = regexp.MustCompile(
		`(?:紹介|スタッフ|メンバー)[ ]?[>＞›»][ ]?(` + spacedKanjiName + `)[ ]*$`,
	)
	// personNameMobileParenRe は「採用担当連絡先 <姓> <名>(090-…)」のように、氏名の直後の括弧に携帯電話の
	// 番号が続く形（企業の採用ページで実測。氏名と個人の携帯番号の組）。
	personNameMobileParenRe = regexp.MustCompile(
		`(?:^|[^` + kanji + `])(` + spacedKanjiName + `|[` + kanji + `]{3,6})[ ]?[（(][ ]?0[5789]0[-ー－‐][0-9]{4}[-ー－‐][0-9]{4}`,
	)
	// personNameChairLineEndRe は「委員長　<姓>　<名>」のように、会議体の役の名前・空白・空白区切りの氏名で
	// 行が終わる形（団体の委員会の名簿で実測）。
	personNameChairLineEndRe = regexp.MustCompile(
		`(?:^|[ ])(?:副委員長|委員長|副議長|議長|座長|副座長|部会長|幹事長|実行委員長)[ ]{1,4}(` + spacedKanjiName + `)[ ]*$`,
	)
	// personNameStaffTitleLineEndRe は「担当者：<部署>看護師長　<氏名>」「部長 <氏名>」のように、職場の役職・
	// 空白・無空白の氏名で行が終わる形（病院の案内で実測）。
	personNameStaffTitleLineEndRe = regexp.MustCompile(
		`(?:看護師長|師長|技師長|士長|科長|係長|主任|主査|主幹|課長補佐|課長代理|本部長|事務局長|部長|課長|室長|次長|局長)[ ]{1,4}([` + kanji + `]{3,6})[ ]*$`,
	)
	// personNameCreditLineEndRe は「監修<姓> <名>」「<外来名>担当<姓> <名>」のように、担当・監修などの語に
	// 空白区切りの氏名が直結して行が終わる形（企業の記事のクレジット、病院の外来の担当表で実測）。
	personNameCreditLineEndRe = regexp.MustCompile(
		`(?:監修|文責|撮影|執筆|取材|司会|翻訳|担当)[ ]?[:：]?[ ]?(` + spacedKanjiName + `)[ ]*$`,
	)
	// personNameThenDeptTitleLineRe は「<氏名> <部署名>部長」のように、行全体が氏名・空白・部署 + 役職の形
	// （病院の職員の紹介で実測）。
	personNameThenDeptTitleLineRe = regexp.MustCompile(
		`^[ ]*([` + kanji + `]{3,6})[ ]{1,2}[` + kanji + katakana + `・]{2,12}(?:本部長|事務局長|部長|課長|室長|所長|センター長|局長|科長|師長)[ ]*$`,
	)
)
