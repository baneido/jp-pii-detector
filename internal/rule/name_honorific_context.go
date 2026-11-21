package rule

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// 2026-11-21 の公開文書の走査（15,575 件）で、既定モードのルールが取りこぼしていた氏名の形
// （person-name-role-label）と、同じ確認で見つけた誤検出の棄却。人を指す語のある無作為 450 行に
// 人手で付けた正解（姓+名 98 人）のうち、既定モードが拾えたのは 79 人だった。高再現率モードだけが
// 拾っていた敬称付きの氏名 2,344 件のうち、姓名辞書で完全に分割できる 642 件を無作為に 90 件読むと、
// 氏名でないものは 1 件（副詞 + 姓 + 1 字の語）、文中で故人と分かる氏名が 3 件だった。

// honorificSpaceTitleWords は「<職名> <氏名>が」「<職名> <姓> <名>より」の職名（空白の前の語の末尾）。
const honorificSpaceTitleWords = `代表取締役社長|代表取締役|代表理事|代表社員|代表|本部長|事業部長|支店長|工場長|部長|課長|室長|局長|` +
	`所長|館長|園長|校長|院長|店長|支配人|編集長|監督|コーチ|主将|キャプテン|オーナー|主宰|宮司|住職|会長|社長|理事長|塾長|団長`

// honorificNamePrefixWords は「<職業><氏名>さん」「<卒業生><氏名>さん」のように、氏名に直結する
// 職業・立場の語。敬称のパターンは漢字の並び全体を値にするので、これらの語まで値に入っていた。
const honorificNamePrefixWords = `絵本作家|小説家|漫画家|写真家|陶芸家|建築家|音楽家|演出家|脚本家|彫刻家|書道家|作曲家|作家|画家|書家|` +
	`卒業生|修了生|在校生|在学生|大学院生|同窓生|受講生|研究生|留学生|特派員|親善大使|観光大使|大使`

var (
	// personNameWideHonorificRe は「<氏名>さん」「<氏名> 氏」のうち、既定モードの personNameStrictHonorificRe が
	// 拾わない形: 前に日本語の語か記号がある行末（「3年 <氏名>さん」「研究内容説明・<氏名>氏」）、敬称の前の空白、敬称の後が括弧・記号・英数字・カタカナ
	// （「<氏名>さん「<題名>」」「<氏名>さんインタビュー」）や「です」「からの」などの語。
	// 値は 3〜6 字の漢字で、直前は行頭か、漢字・かなでない字（空白・記号・英数字）に限り、姓名辞書の
	// 完全分割（validLooseTitleName）と高再現率の敬称パターンと同じ棄却をすべて通す。
	// 「様」、ひらがなに直結する形、敬称の後に漢字が続く形、辞書にない氏名・姓だけは、従来どおり
	// 高再現率（person-name-high-recall）の範囲。
	personNameWideHonorificRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `])([` + kanji + `]{3,6})[ ]?(?:さん|氏)`,
	)
	// personNameTitleSpaceNameParticleRe は「<屋号> 代表 <氏名>が」「<部署> 部長 <姓> <名>のコメント」
	// 「本部長 <姓> <名>より」「<市名>市長 <氏名>様」のように、職名・空白・氏名に助詞か敬称が続く形
	// （企業のお知らせ・来賓の一覧で実測）。既存の「職名 + 空白 + 氏名」のパターンは行末・括弧が必要だった。
	personNameTitleSpaceNameParticleRe = regexp.MustCompile(
		`(?:` + honorificSpaceTitleWords + `|` + localTitleWords + `|` + personTitleWords + `)[ ]+` +
			`([` + kanji + `]{1,4}[ ][` + kanji + `]{1,4}|[` + kanji + `]{3,6}?)` +
			`(?:が|は|の|より|による|を|に|と|も|[ ]?(?:様|氏|さん))`,
	)
	// personNameTitleDotNameParticleRe は「<法人>理事長・<氏名>の新刊が」のように、職名と氏名を中黒で
	// つなぎ、助詞・敬称が続く形（団体のお知らせで実測）。括弧・読点・行末で終わる形は
	// personNameTitleDotNameRe が拾う。
	personNameTitleDotNameParticleRe = regexp.MustCompile(
		`(?:理事長|会長|社長|学長|総長|院長|館長|所長|校長|園長|監督|市長|町長|村長|知事|頭取|代表|准教授|教授)・[ ]?` +
			`([` + kanji + `]{1,4}[ ][` + kanji + `]{1,4}|[` + kanji + `]{3,6}?)(?:の|が|は|を|に|と|も|さん)`,
	)
	// personNamePrefixedHonorificRe は「<絵本作家><氏名>さん」「<卒業生><氏名>さんが」のように、職業・立場の
	// 語に直結する氏名 + 敬称の、氏名だけを拾い直す（高再現率の敬称パターンは職業の語まで値に含めていた）。
	personNamePrefixedHonorificRe = regexp.MustCompile(
		`(?:` + honorificNamePrefixWords + `)([` + kanji + `]{3,6})[ ]?(?:さん|氏|様)`,
	)
)

// deceasedContextWords は氏名の前後にあると、その人が亡くなっていることを示す語。
var deceasedContextWords = []string{"逝去", "死去", "享年", "故人", "追悼", "没後", "冥福", "訃報", "偲ぶ", "偲ん", "遺作", "遺族", "永眠", "他界"}

// wideHonorificHiraganaTails は敬称の後に続いてよいひらがなの語（文が続く形）。これ以外のひらがな
// （「さんさん」「さんま」「さんぽ」）は敬称ではない語の一部とみなす。
var wideHonorificHiraganaTails = []string{
	"です", "でした", "でし", "から", "より", "への", "へ", "による", "について", "おすすめ", "と", "が", "は", "の", "を", "に", "も", "や", "など", "ら",
}

// rejectWideHonorificFragment は personNameWideHonorificRe の値の追加検証。既定モードの
// personNameStrictHonorificRe と同じ棄却（姓 1 つ・職業の字で終わる語・「故」の後・肩書きの一部）に
// 加えて、次の形を棄却する。
//   - 敬称の後に漢字が続く形（「氏名」「様式」のような別の語と、高再現率の範囲として残す「<氏名>さん受賞」）
//   - 敬称の後のひらがなが wideHonorificHiraganaTails の語でない形
//   - 前後 16 字に逝去・享年などの語がある形（個人情報保護法の個人情報は生存する個人の情報）
//   - 連体修飾の語（各・全・当・同など）から始まる値
func rejectWideHonorificFragment(line string, start, end int) bool {
	v := line[start:end]
	// 隣り合う 2 行を改行でつないだ文字列でも呼ばれるので、値のある行だけを見る。
	lineStart, lineEnd := physicalLineBounds(line, start, end)
	rest := strings.TrimLeft(line[end:lineEnd], " ")
	for _, h := range []string{"さん", "氏", "様"} {
		after, ok := strings.CutPrefix(rest, h)
		if !ok {
			continue
		}
		after = strings.TrimLeft(after, " ")
		if after == "" {
			// 行末の「<氏名>さん」は、氏名の前に日本語の語（学年・所属・職名・見出し）か記号（中黒・読点・括弧）が
			// あるときだけ既定モードで拾う。行全体が「<氏名>さん」だけの行と、英数字の後の「<氏名>さん」は、
			// 手がかりが敬称しかないので従来どおり高再現率の範囲。
			before := strings.TrimRight(line[lineStart:start], " ")
			if r, _ := utf8.DecodeLastRuneInString(before); before == "" || r < 0x80 {
				return false
			}
		}
		if r, _ := utf8.DecodeRuneInString(after); after != "" {
			switch {
			case r >= 0x4E00 && r <= 0x9FFF || r == '々':
				return false
			case r >= 0x3041 && r <= 0x309E:
				ok := false
				for _, t := range wideHonorificHiraganaTails {
					if strings.HasPrefix(after, t) {
						ok = true
						break
					}
				}
				if !ok {
					return false
				}
			}
		}
		break
	}
	for _, h := range []string{"各", "全", "当", "同", "両", "次期", "歴代", "初代"} {
		if strings.HasPrefix(v, h) {
			return false
		}
	}
	if deceasedNear(line, start, end) {
		return false
	}
	return rejectStrictHonorificFragment(line, start, end) && rejectShiInsideGivenName(line, start, end)
}

// deceasedNear は値の前後 16 字に deceasedContextWords のいずれかがあるかを返す。
func deceasedNear(line string, start, end int) bool {
	before := lastRunes(line[:start], 16)
	after := firstRunes(line[end:], 16)
	for _, w := range deceasedContextWords {
		if strings.Contains(before, w) || strings.Contains(after, w) {
			return true
		}
	}
	return false
}

func lastRunes(s string, n int) string {
	i := len(s)
	for ; n > 0 && i > 0; n-- {
		_, size := utf8.DecodeLastRuneInString(s[:i])
		i -= size
	}
	return s[i:]
}

func firstRunes(s string, n int) string {
	i := 0
	for ; n > 0 && i < len(s); n-- {
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
	}
	return s[:i]
}

// honorificOrgWideTails は敬称の前の値の末尾に来る、事業者・官署・団体・役割の語
// （2026-11-21 に企業の導入事例・取引先向けの案内・国会の会議録で実測した高再現率モードの偽陽性。
// 「<社名>自動織機様」「<社名>開発様」「特約店様」「<県名>警察様」「<地方>整備局様」「<放送局>様」
// 「製造業様」「法定代理人様」「世帯主様」。いずれも特定の個人を指さない）。
var honorificOrgWideTails = []string{
	"織機", "開発", "瓦斯", "警察", "整備局", "消防局", "港湾局", "消防署", "警察署", "放送", "製薬", "工務店", "材木店", "特約店", "取次店",
	"料飲店", "販売店", "鉄道", "道路", "観光", "新聞社", "競馬会", "映像", "技工所", "研究所", "宝物館", "博物館", "美術館", "図書館", "士会",
	"製造業", "小売業", "建設業", "卸売業", "運送業", "投資家", "代理人", "弁護人", "世帯主", "担当",
}

// rejectHonorificOrgWide は高再現率の敬称パターンで、値が honorificOrgWideTails の語で終わる形と、
// 企業の略称・方角 + 日本・挨拶の語に付く「さん」「様」を敬称付きの氏名とみなさない。
// 姓名辞書に一致する値（姓が「開発」などで終わる人）は通す。
func rejectHonorificOrgWide(line string, start, end int) bool {
	v := line[start:end]
	rest := strings.TrimLeft(line[end:], " ")
	if !strings.HasPrefix(rest, "さん") && !strings.HasPrefix(rest, "様") {
		return true
	}
	switch v {
	case "商船三井", "明治安田", "西日本", "東日本", "御母堂", "御苦労", "大変御苦労", "節分鬼":
		return false
	}
	if dict.IsPersonName(v) {
		return true
	}
	for _, s := range honorificOrgWideTails {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	// 「粘液腫様」「肉腫様」は医学の用語（〜のような）。
	return !strings.HasSuffix(v, "腫") || !strings.HasPrefix(rest, "様")
}

// rejectHonorificNamePrefix は高再現率の無空白の敬称パターンで、値が honorificNamePrefixWords の語から
// 始まり、その後ろが姓名辞書で完全に分割できる形を棄却する。氏名だけの範囲は
// personNamePrefixedHonorificRe（既定モード）が拾い直す。
func rejectHonorificNamePrefix(line string, start, end int) bool {
	v := line[start:end]
	for _, p := range strings.Split(honorificNamePrefixWords, "|") {
		if rest, ok := strings.CutPrefix(v, p); ok && utf8.RuneCountInString(rest) >= 3 && validPersonNameFullSplit(rest) {
			return false
		}
	}
	return true
}

// notProseEAILocal は email-address-eai の値のローカル部が、アドレスではなく説明の文の一部である場合に
// 棄却する（2026-11-21 に大学の案内「学園指定アドレス（ドメインが@<ドメイン>）のみ」で実測した
// 高再現率モードの偽陽性。「ドメインが」は文で、特定の個人のアドレスではない）。
func notProseEAILocal(v string) bool {
	local, _, ok := strings.Cut(v, "@")
	if !ok {
		return true
	}
	for _, w := range []string{"ドメイン", "アドレス", "メール"} {
		if strings.Contains(local, w) {
			return false
		}
	}
	// 「<カタカナ・漢字の語>が@…」「…は@…」のように助詞で終わるローカル部は文の一部。ひらがなの名
	// （「まなと」「あやの」）を落とさないよう、助詞の直前がカタカナ・漢字のときだけ棄却する。
	rs := []rune(local)
	if n := len(rs); n >= 3 && strings.ContainsRune("がはをのにでとも", rs[n-1]) {
		if p := rs[n-2]; (p >= 0x30A1 && p <= 0x30FC) || (p >= 0x4E00 && p <= 0x9FFF) {
			return false
		}
	}
	return true
}

// rejectTitleSpaceNameFragment は personNameTitleSpaceNameParticleRe と personNameTitleDotNameParticleRe の
// 値の追加検証。次の形を棄却する。
//   - 前後に逝去・永眠などの語がある（亡くなった人）
//   - 値が姓 1 つ・自治体名・「〜的」（「<姓>国務大臣　根本的には」）・地名（瀬戸内海）
//   - 値が「先生」で終わる（「<職名> <姓> <名>先生は」の敬称まで値に入った形。氏名だけの範囲は既存のパターンが拾う）
//   - 行が会議録の発言者の印（○）で始まる（「○<姓>国務大臣　<発言>」は職名の後が発言の本文）
func rejectTitleSpaceNameFragment(line string, start, end int) bool {
	v := line[start:end]
	if deceasedNear(line, start, end) || dict.IsSurname(v) || dict.IsMunicipalityOrPrefecture(v) {
		return false
	}
	if strings.HasSuffix(v, "的") || strings.HasSuffix(v, "先生") || v == "瀬戸内海" {
		return false
	}
	lineStart, _ := physicalLineBounds(line, start, end)
	head := strings.TrimLeft(line[lineStart:], " ")
	return !strings.HasPrefix(head, "○") && !strings.HasPrefix(head, "〇")
}

// physicalLineBounds は値のある物理行の範囲を返す。検出器は隣り合う 2 行を改行でつないだ文字列も
// 走査するので、行頭・行末を見る検証はこの範囲の中で行う。
func physicalLineBounds(line string, start, end int) (int, int) {
	lineStart := strings.LastIndexByte(line[:start], '\n') + 1
	lineEnd := len(line)
	if i := strings.IndexByte(line[end:], '\n'); i >= 0 {
		lineEnd = end + i
	}
	return lineStart, lineEnd
}
