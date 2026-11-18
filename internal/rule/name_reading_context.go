package rule

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// 2026-11-18 の公開文書の走査（4,198 件）で、既定モードのルールが取りこぼしていた氏名の形
// （person-name-role-label）。人を指す語のある無作為 520 行に人手で付けた正解（姓+名 77 人）のうち、
// 設計用の 38 人で既定モードが拾えたのは 28 人だった。ここではそのうち次の形を拾う。
// 読みがなの括弧・職名に続く字間を空けた氏名・所属 + 職名の行のように、氏名の辞書とは別の手がかりが
// あるときは「辞書の姓 + 1〜3 字の名」まで採り、手がかりが弱い形は姓名辞書の完全分割を必須にする。

// letterSpacedTitleWords は、PDF の均等割付で字間を空けた氏名の前に来る職名。
const letterSpacedTitleWords = `弁護士|弁理士|司法書士|取締役|執行役員|執行役|監査役|社長|副社長|会長|頭取|専務|常務|` +
	`理事長|理事|監事|市長|町長|村長|区長|知事|議長|教育長|部長|課長|室長|班長|所長|館長|校長|学長|院長|局長|委員長|代表`

// readingRoleWords は「<役割>の<氏名>氏」「<役割>・<氏名>氏」の役割の語。
const readingRoleWords = `名誉教授|准教授|教授|講師|作家|著者|通訳|記者|アナウンサー|評論家|学者|研究者|監督|弁護士|医師|` +
	`編集長|デザイナー|建築家|写真家|翻訳家|ジャーナリスト|プロデューサー|アドバイザー|コンサルタント`

var (
	// personNameReadingPairRe は「<氏名>（<姓の読み> <名の読み>）」。読みがなが空白・中黒で 2 つに
	// 分かれていること自体が氏名の手がかりになる（施設・用語の読みがなは 1 語で書かれる）。
	personNameReadingPairRe = regexp.MustCompile(
		`(?:^|[^` + kanji + `])([` + kanji + `]{1,4}[ ]?[` + kanji + `]{1,4})[（(][` + hiragana + `]{2,6}[ ・][` + hiragana + `]{1,6}[）)]`,
	)
	// personNameReadingHonorificRe は「<氏名>（<読みがな>）さん」のように、区切りのない読みがなの括弧に
	// 敬称・職名が続く形。
	personNameReadingHonorificRe = regexp.MustCompile(
		`(?:^|[^` + kanji + `])([` + kanji + `]{3,6})[（(][` + hiragana + `]{3,12}[）)][ ]?(?:さん|氏|先生|選手|教授|准教授|講師|議員|委員)`,
	)
	// personNameLetterSpacedExecRe は「代表取締役副社長執行役員 <姓 1 字> <姓 1 字> <名 1 字> <名 1 字>」
	// 「同訴訟代理人弁護士　<1 字ずつの氏名>」のように、職名の後に 1 字ずつ空白で区切った氏名が続く形
	// （決算短信・判決書の PDF の均等割付）。既存の personNameLetterSpacedTitleRe は首長・会長などの職名の
	// 後に空白 2 個以上、行末か括弧で終わる形だけだった。値の検証は同じ validLetterSpacedName を使う。
	personNameLetterSpacedExecRe = regexp.MustCompile(
		`(?:` + letterSpacedTitleWords + `)[ ]+([` + kanji + `](?:[ ]{1,8}[` + kanji + `]){2,4})[ ]*(?:$|[（(様殿]|[ ]{2}|[ ][^ ][^ ])`,
	)
	// personNameRosterDeptTitleRe は教員一覧の「<姓> <名>　<研究科>　教授（<在任期間>）」の行。
	personNameRosterDeptTitleRe = regexp.MustCompile(
		`^[ ]*([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + `]{1,4})[ ]+[` + kanji + katakana + `]{2,12}(?:研究科|学部|学科|学群|学系|研究所|センター|病院)[ ]+` +
			`(?:特任|客員|名誉)?(?:教授|准教授|講師|助教)`,
	)
	// personNameSpaceDeptTitleRe は「<氏名> <学部>教授（<講座>）が」のように、氏名 + 空白 + 所属 + 職名。
	personNameSpaceDeptTitleRe = regexp.MustCompile(
		`(?:^|[^` + kanji + `])([` + kanji + `]{3,6})[ ][` + kanji + `]{1,8}(?:学部|研究科|学科|学群)[ ]?(?:教授|准教授|講師|助教)`,
	)
	// personNameRoleNoShiRe は「<大学>名誉教授の<氏名>氏をお迎えし」「著者・<氏名>氏の講演会」のように、
	// 役割の語 + の／中黒 + 氏名 + 氏。名が辞書にない氏名を拾う（辞書の完全分割は既存のパターンの範囲）。
	personNameRoleNoShiRe = regexp.MustCompile(
		`(?:` + readingRoleWords + `)[ ]?[の・][ ]?([` + kanji + `]{3,6})氏`,
	)
	// personNameDaihyoParticleRe は「我が党の<氏名>代表が、」のように、氏名 + 代表 + 助詞。
	personNameDaihyoParticleRe = regexp.MustCompile(
		`(?:^|[^` + kanji + katakana + `])([` + kanji + `]{3,6}?)代表(?:[がはにと、])`,
	)
	// personNameQuotedHonorificRe は「本校 2 年生『<姓>　<名>』さんが」のように、かぎ括弧で囲んだ氏名 + 敬称。
	personNameQuotedHonorificRe = regexp.MustCompile(
		`[『「]([` + kanji + `]{1,4}[ ]{1,2}[` + kanji + hiragana + `]{1,4})[』」](?:さん|氏|様|君)`,
	)
	// personNameHonorificCreditRe は「（<氏名>さん主演）」のように、氏名 + 敬称 + 出演・制作の役割。
	personNameHonorificCreditRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|[のでとはがにらをもへ])([` + kanji + `]{3,6}?)(?:さん|氏)(?:主演|監修|原作|脚本|作詞|作曲)`,
	)
	// personNameTitleKanaGivenRe は「所長　<姓><ひらがなの名>子氏」のように、職名 + 空白 + 姓 + ひらがなを
	// 含む名 + 敬称。
	personNameTitleKanaGivenRe = regexp.MustCompile(
		`(?:` + letterSpacedTitleWords + `)[ ]+([` + kanji + `]{1,3}[` + hiragana + `]{2,4}[子美恵代江]?)(?:氏|さん|様)`,
	)
	// personNameContactDeptRe は決算短信の「問合せ先責任者　<部署> <姓> <名>」（職名ではなく部署名が入る形）。
	personNameContactDeptRe = regexp.MustCompile(
		`問合せ先責任者[ ]+[^ ]{2,12}[ ]+([` + kanji + `]{1,4}[ ][` + kanji + `]{1,3})[ ]*(?:$|TEL|[（(])`,
	)
)

// validSurnamePrefixName は、氏名の辞書とは別の手がかり（読みがなの括弧・役割の語 + 氏）がある値を
// 検証する。姓名辞書の完全分割か、「辞書の姓 + 1〜3 字の漢字の名」（名が辞書にない氏名）を採る。
// 値全体・名の部分が一般語のとき、組織名・職名で終わる語のときは採らない。
func validSurnamePrefixName(v string) bool {
	v = strings.TrimSpace(v)
	if !notOrgName(v) || !notPlaceholderName(v) || endsWithTitleWord(v) {
		return false
	}
	if strings.Contains(v, " ") {
		return validSpacedNameOneSideDict(v)
	}
	if !allKanji(v) || dict.IsCommonWord(v) || dict.IsSurname(v) || dict.IsMunicipalityOrPrefecture(v) {
		return false
	}
	if validPersonNameFullSplit(v) {
		return true
	}
	r := []rune(v)
	if len(r) < 3 || len(r) > 6 {
		return false
	}
	for k := 3; k >= 1; k-- {
		if len(r)-k < 1 || len(r)-k > 3 {
			continue
		}
		sur, given := string(r[:k]), string(r[k:])
		if dict.IsSurname(sur) && !dict.IsCommonWord(given) && !dict.IsSurname(given) {
			return true
		}
	}
	return false
}

// validTitleKanaGivenName は「<辞書の姓> + ひらがな 2〜4 字（+ 子・美・恵・代・江）」を検証する。
func validTitleKanaGivenName(v string) bool {
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
	if sur == "" || utf8.RuneCountInString(given) < 2 || !notOrgName(v) || !notPlaceholderName(v) {
		return false
	}
	// 「部長 山田より様」「会長 林からさん」のような助詞を名として取り込んだ形は通さない。
	for _, s := range []string{"より", "から", "まで", "および", "ほか", "など", "さま", "あて", "です", "ます", "した", "あいさつ"} {
		if strings.HasPrefix(given, s) || strings.HasSuffix(given, s) {
			return false
		}
	}
	return dict.IsSurname(sur) && !dict.IsCommonWord(given) && !dict.IsCommonWord(v)
}

// rejectDaihyoFragment は personNameDaihyoParticleRe の値の追加検証。「<県>代表」「<競技>日本代表」
// 「<姓>副代表」のように、代表の前の語まで取り込んだ形を通さない。
func rejectDaihyoFragment(line string, start, end int) bool {
	v := line[start:end]
	for _, s := range []string{"県", "都", "府", "道", "市", "国", "日本", "副", "元", "前", "新", "地区", "学校", "選手権", "共同", "常駐", "特別", "通商",
		// 「<姓>公明代表」「<姓>立憲代表」は「<姓>・<政党の略称>代表」で、政党名は名ではない（2026-11-18 に国会の会議録で実測）。
		"公明", "自民", "民主", "立憲", "維新", "共産", "社民", "国民", "民進", "自由"} {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	return rejectPostTitleFragment(line, start, end)
}

// rejectSpacedNumberRow は jp-my-number の 4-4-4 の空白区切りの値が、寸法・数量の表の行に並んだ
// 数値である場合に棄却する（2026-11-18 に企業の製品仕様の表で実測した偽陽性。3〜4 桁の寸法が空白区切りで
// 10 個並ぶ行の末尾 3 つの 4 桁が、検査用数字に偶然一致していた）。値の前か後ろに、空白を
// はさんで別の数値が続くときを数値の並びとみなす。「個人番号」「マイナンバー」の語がある行は従来どおり。
var (
	numberTokenBeforeRe = regexp.MustCompile(`\d[ ]+$`)
	numberTokenAfterRe  = regexp.MustCompile(`^[ ]+\d`)
)

func rejectSpacedNumberRow(line string, start, end int) bool {
	if !strings.Contains(line[start:end], " ") {
		return true
	}
	if strings.Contains(line, "個人番号") || strings.Contains(line, "マイナンバー") {
		return true
	}
	return !numberTokenBeforeRe.MatchString(line[:start]) && !numberTokenAfterRe.MatchString(line[end:])
}

// IsRegionPlacePair は「<地域名> <市町村名>」のように、2 語目が実在の市区町村名である空白区切りの値を
// 返す（2026-11-18 に村の公式サイトの標語「<地域名> <村名>。」で実測した偽陽性。1 語目が姓の辞書と
// 同形でも、2 語目が市区町村名なら氏名ではない）。名の辞書にある語（同形の名）は対象にしない。
func IsRegionPlacePair(v string) bool {
	f := strings.Fields(v)
	if len(f) != 2 || dict.IsGivenName(f[1]) {
		return false
	}
	r := []rune(f[1])
	switch r[len(r)-1] {
	case '市', '町', '村', '区', '郡', '県':
		return len(r) >= 2 && (dict.IsMunicipalityOrPrefecture(f[1]) || dict.MunicipalitySuffixMatch(f[1]))
	}
	return false
}

// rejectHonorificOrgOrSample は高再現率の敬称パターンで、団体の種類を表す語に付く「さん」「様」
// （「農協さん」「<取引所名>様」）と、記入例の定番の名だけの「花子さん」「太郎さん」を敬称付きの氏名とみなさない
// （2026-11-18 に国会の会議録・企業のお知らせ・市の講座の題名で実測した高再現率モードの偽陽性。
// いずれも特定の個人を指さない）。
func rejectHonorificOrgOrSample(line string, start, end int) bool {
	v := line[start:end]
	rest := line[end:]
	if !strings.HasPrefix(rest, "さん") && !strings.HasPrefix(rest, "様") {
		return true
	}
	if v == "農協" || v == "漁協" || v == "生協" || v == "森林組合" || v == "花子" || v == "太郎" {
		return false
	}
	for _, s := range []string{"取引所", "協同組合", "農協", "漁協", "商工会", "商工会議所", "信用金庫", "信用組合", "銀行"} {
		if strings.HasSuffix(v, s) && utf8.RuneCountInString(v) > utf8.RuneCountInString(s) {
			return false
		}
	}
	return true
}
