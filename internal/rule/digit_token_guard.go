package rule

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// 数値ルール（マイナンバー・クレジットカード）の、OSS コーパスで実測した
// 偽陽性の型を棄却する ValidateLine 群（docs/development.md「OSS コーパスでの
// 偽陽性率計測」）。共有の境界ガード（dgNoAlnumHyphen 等）を厳しくすると全数値
// ルールの再現率に波及するため、実測で偽陽性が集中したルールのパターンにだけ使う。

// allValidateLine は、すべての ValidateLine が true を返すときだけ true を返す。
func allValidateLine(fs ...func(string, int, int) bool) func(string, int, int) bool {
	return func(line string, start, end int) bool {
		for _, f := range fs {
			if !f(line, start, end) {
				return false
			}
		}
		return true
	}
}

func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

// rejectNumericTokenPart は、数字列が独立した番号ではなく、より大きな数値・
// 識別子トークンの一部である場合に棄却する。
//   - 小数の一部: 直前が「数字 + .」（"29.7062300000000015" の小数部、
//     "0.968994140625"）、または直後が「. + 数字」（"148966367200.372"）。
//   - 識別子の一部: 直前・直後がアンダースコア（"blk_3550669278239526374"）。
//     英数字・ハイフンの連結は境界ガードが既に除外しており、それと同じ扱い。
func rejectNumericTokenPart(line string, start, end int) bool {
	if start > 0 {
		switch line[start-1] {
		case '_':
			return false
		case '.':
			if start > 1 && isASCIIDigit(line[start-2]) {
				return false
			}
		}
	}
	if end < len(line) {
		switch line[end] {
		case '_':
			return false
		case '.':
			if end+1 < len(line) && isASCIIDigit(line[end+1]) {
				return false
			}
		}
	}
	return true
}

// hexDumpNeighborTokens は、前後それぞれ何トークンまで 16 進ダンプの判定に見るか。
const hexDumpNeighborTokens = 8

// rejectHexDumpGroup は、空白区切りの 16 進ダンプ（"ffff 54cd 7484 9797 9999"、
// "00000130  64 67 69 74 73 20 50 74  79 20 4c 74"、PNG テストデータの
// 12 桁ずつの 16 進の並び等）の中で、たまたま英字 a-f を含まない
// グループの並びを棄却する。マッチの前後 hexDumpNeighborTokens 個以内に、
// マッチの先頭グループと同じ幅で英字 a-f を含む 16 進トークンが空白区切りで
// 連続して並んでいれば 16 進ダンプとみなす（途中に 16 進でないトークンがあれば
// そこで打ち切る）。
func rejectHexDumpGroup(line string, start, end int) bool {
	width := 0
	for i := start; i < end && isASCIIDigit(line[i]); i++ {
		width++
	}
	if width == 0 {
		return true
	}
	return !hexNeighbor(strings.Fields(line[:start]), width, true) &&
		!hexNeighbor(strings.Fields(line[end:]), width, false)
}

// hexNeighbor は、tokens（reverse なら末尾から）を最大 hexDumpNeighborTokens 個
// 見て、幅 width で英字 a-f を含む 16 進トークンがあるかを返す。
func hexNeighbor(tokens []string, width int, reverse bool) bool {
	for k := 0; k < len(tokens) && k < hexDumpNeighborTokens; k++ {
		t := tokens[k]
		if reverse {
			t = tokens[len(tokens)-1-k]
		}
		letter, ok := hexToken(t)
		if !ok {
			return false
		}
		if letter && len(t) == width {
			return true
		}
	}
	return false
}

// hexToken は、t が 16 進数字だけからなるか（ok）と、英字 a-f を含むか（letter）を返す。
func hexToken(t string) (letter, ok bool) {
	if t == "" {
		return false, false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case isASCIIDigit(c):
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			letter = true
		default:
			return false, false
		}
	}
	return letter, true
}

// rejectLogTimestamp66 は、マイナンバーの 6-6 空白区切り形のうち、ログの
// タイムスタンプ（YYMMDD HHMMSS。Hadoop 等のログで行頭に並ぶ）と
// 同形のものを、行にマイナンバーのラベル（context）が無い場合に限り棄却する。
// 6-6 形はチェックディジットで約 1/11 しか絞れず、ログ 1 行ごとに偽陽性を生んでいた。
func rejectLogTimestamp66(context []string) func(string, int, int) bool {
	return func(line string, start, end int) bool {
		m := line[start:end]
		if len(m) != 13 || m[6] != ' ' || !yymmdd(m[:6]) || !hhmmss(m[7:]) {
			return true
		}
		lower := strings.ToLower(line)
		for _, c := range context {
			if strings.Contains(lower, strings.ToLower(c)) {
				return true
			}
		}
		return false
	}
}

func twoDigits(s string) int { return int(s[0]-'0')*10 + int(s[1]-'0') }

func yymmdd(s string) bool {
	m, d := twoDigits(s[2:4]), twoDigits(s[4:6])
	return m >= 1 && m <= 12 && d >= 1 && d <= 31
}

func hhmmss(s string) bool {
	return twoDigits(s[0:2]) <= 23 && twoDigits(s[2:4]) <= 59 && twoDigits(s[4:6]) <= 59
}

// youCompoundStems は、「様」と続けて敬称ではない一般語（同様・仕様・模様・
// 異様・多種多様）を作る直前の文字列。
var youCompoundStems = []string{"同", "仕", "模", "異", "種多"}

// youCompoundTails は、「様」の直後に続いて敬称ではない一般語（様式・様相・様態）を
// 作る文字。行政文書の「申請書様式」「共通様式」「別添様式２」で、直前の漢字列
// （申請書・共通・別添）を敬称付き氏名として切り出す偽陽性を公開文書で実測した
// （様式は書式を指す一般名詞で、個人情報保護法上の個人情報に当たらない）。
//
// 「5年間様子を見た」の「様子」も 2026-10-30 08:00 に実測した（直前の「年間」を氏名として報告していた）。
var youCompoundTails = []string{"式", "相", "態", "子"}

// rejectYouCompound は、敬称アンカーの「様」が一般語の一部（「新品同様」
// 「従来同様」「構文仕様」「多種多様」「申請書様式」）である場合に棄却する。日本語ドキュメントの
// コーパスで、敬称の直前の漢字 2〜8 文字（「新品同」「構文仕」）を氏名として
// 切り出す偽陽性を実測した。「本多様」のような姓 + 様や、1 文字名「一」+ 様は棄却しない。
func rejectYouCompound(line string, start, end int) bool {
	if !strings.HasPrefix(line[end:], "様") {
		return true
	}
	after := line[end+len("様"):]
	for _, t := range youCompoundTails {
		if strings.HasPrefix(after, t) {
			return false
		}
	}
	for _, s := range youCompoundStems {
		if strings.HasSuffix(line[start:end], s) {
			return false
		}
	}
	return true
}

// rejectShimeiCompound は、敬称アンカーの「氏」が一般語「氏名」の一部である場合に棄却する。
// 個人情報漏えいの公表文書の「生徒氏名、学年」「職員氏名」で、直前の一般語（生徒・職員）を
// 敬称付き氏名として切り出す偽陽性を公開文書で実測した（「氏名」は項目名で、直前の語は
// 人を特定しない）。「<姓>氏名義の口座」のように「氏」+「名義」と読む形は棄却しない。
func rejectShimeiCompound(line string, start, end int) bool {
	rest := line[end:]
	if !strings.HasPrefix(rest, "氏名") {
		return true
	}
	return strings.HasPrefix(rest, "氏名義")
}

// rejectHonorificWordCompound は、敬称アンカーの「様」「さん」「氏」「殿」が一般語の一部で
// ある場合に棄却する。県・市の公開ページで「生物多様性」「総合企画部多様性社会推進課」
// （多様）、「県史編さん」「野外炊さん」（編さん・炊さん）、「皇族各殿下」「女王殿下」（名を含まない殿下）、
// 「選択的夫婦別氏制度」（別氏）、「朝倉氏遺跡」「西山氏庭園」（史跡名）を
// 敬称付き氏名として切り出す偽陽性を実測した。2026-10-30 には自治体名 + 様/さん、
// 殿を含む建物・地名（社殿・本殿・御殿・紫宸殿・沈殿・殿ケ谷・御殿場）、さんぽ、
// 故人（故・〜氏）も実測したため棄却する。
func rejectHonorificWordCompound(line string, start, end int) bool {
	val := line[start:end]
	rest := line[end:]
	switch {
	case strings.HasSuffix(val, "多") && (strings.HasPrefix(rest, "様性") || strings.HasPrefix(rest, "様化") || strings.HasPrefix(rest, "様な")):
		// 「本多様」「喜多様」のような姓 + 様は残し、多様性・多様化・多様な だけを棄却する。
		return false
	case (strings.HasSuffix(val, "編") || strings.HasSuffix(val, "炊")) && strings.HasPrefix(rest, "さん"):
		return false
	case strings.HasPrefix(rest, "殿下") && (strings.HasSuffix(val, "両") || strings.HasSuffix(val, "各") ||
		val == "女王" || val == "親王" || val == "内親王"):
		// 「両殿下」「各殿下」「女王殿下」のように名を含まない敬称だけを棄却する。
		// 「<名>女王殿下」「<宮家>妃<名>殿下」は特定の個人を指すため残す。
		return false
	case strings.HasSuffix(val, "夫婦別") && strings.HasPrefix(rest, "氏"):
		return false
	}
	for _, w := range []string{"氏遺跡", "氏庭園", "氏館跡", "氏城跡"} {
		if strings.HasPrefix(rest, w) {
			return false
		}
	}
	// 「荒川さんぽ」「新宿桜さんぽ」（散歩の催し名）。
	if strings.HasPrefix(rest, "さんぽ") {
		return false
	}
	// 「北九州市様」「兵庫県様」「横須賀市さん」（導入事例・取引先としての自治体）。
	// 自治体名は個人を識別しないため、市区町村名・都道府県名との完全一致だけを棄却する。
	if (strings.HasPrefix(rest, "様") || strings.HasPrefix(rest, "さん")) && dict.IsMunicipalityOrPrefecture(val) {
		return false
	}
	if strings.HasPrefix(rest, "殿") {
		// 「瑞穂町殿ケ谷」「同町殿ヶ谷」（地名の 殿ケ谷）と「御殿場」。
		if strings.HasPrefix(rest, "殿ケ") || strings.HasPrefix(rest, "殿ヶ") || strings.HasPrefix(rest, "殿場") {
			return false
		}
		// 「東照宮社殿」「神社本殿」「本丸御殿」「紫宸殿」「沈殿池」のように、殿が建物・
		// 一般語の一部である場合。「山本殿」「御手洗殿」のように候補全体が姓名辞書に
		// 一致する値は宛名の敬称として残す。
		for _, w := range []string{"社", "本", "御", "宸", "寓", "沈", "拝", "寝", "宝", "仏"} {
			if strings.HasSuffix(val, w) && !dict.IsPersonName(val) && !dict.SplitsAsFullName(val) {
				return false
			}
		}
	}
	// 文書館の目録の「<院号>院様御法事」「<戒名>院殿<道号>居士」（2026-10-31 00:00 に文書館の
	// 近世文書目録で実測した高再現率モードの偽陽性）。「院」で終わる値は将軍・大名家の夫人の院号や
	// 戒名の院殿号で、生存する個人の氏名ではない。「主殿頭」（官職名）・「<姓>殿内文庫」（沖縄の
	// 家の呼び名）の「殿」と、「新撰姓氏録」の「姓氏」も敬称ではない。値が「様」で始まるのは
	// 「<院号>様<院号>様」の 2 つ目の敬称を跨いだ範囲の誤り。
	if strings.HasSuffix(val, "院") && (strings.HasPrefix(rest, "様") || strings.HasPrefix(rest, "殿")) {
		return false
	}
	// 「競艇殿堂入り」「<分野>殿堂選考委員会」の「殿堂」も敬称ではない（2026-10-31 06:00 に競艇場の
	// サイトで実測した高再現率モードの偽陽性）。
	if strings.HasPrefix(rest, "殿頭") || strings.HasPrefix(rest, "殿内") || strings.HasPrefix(rest, "殿堂") {
		return false
	}
	if strings.HasSuffix(val, "姓") && strings.HasPrefix(rest, "氏") {
		return false
	}
	if strings.HasPrefix(val, "様") {
		return false
	}
	// 「故・<姓><名>氏」「故 <姓><名>様」は亡くなった人を指す。個人情報保護法の個人情報は
	// 生存する個人に関する情報なので、故人の表記は氏名として報告しない。
	// 「交通事故 <姓>様」の「事故」は故人の意味ではないため、故の直前が漢字なら残す。
	before := strings.TrimRight(line[:start], " 　・")
	if b, ok := strings.CutSuffix(before, "故"); ok && !endsWithKanji(b) {
		return false
	}
	if v, ok := strings.CutPrefix(val, "故"); ok && v != "" && !strings.HasPrefix(v, "郷") && !strings.HasPrefix(v, "障") {
		return false
	}
	return true
}

// rejectURLUserinfo は、メールアドレス形の候補が URL のユーザー情報
// （"http://gopher@test.com"、"ssh://git@github.com/user/repo"、
// "http://user:pass@host"）である場合に棄却する。候補を含む空白・引用符区切りの
// トークンで、候補より前に "://" があれば URL とみなす（mailto: は "://" を
// 含まないので棄却しない）。
func rejectURLUserinfo(line string, start, end int) bool {
	i := start
	for i > 0 {
		c := line[i-1]
		if c == ' ' || c == '\t' || c == '"' || c == '\'' || c == '`' || c == '(' || c == '<' || c == '[' || c == '=' || c == ',' {
			break
		}
		i--
	}
	return !strings.Contains(line[i:start], "://")
}

// honorificCommonNouns は、「さん」「様」を付けて人を指すが氏名ではない一般語
// （客・常連・初見・大家 等）。敬称アンカーの直前の漢字列がこれと完全一致する
// 場合に棄却する。初見・大家・奥 のように同表記の姓が辞書にある語も含むが、
// 「さん」「様」付きではまず一般語として使われるため、姓としての再現率より
// 偽陽性の抑制を優先する（「初見太郎さん」のように名が続く値は完全一致しないので
// 引き続き検出する）。
var honorificCommonNouns = map[string]bool{
	"初見": true, "常連": true, "新規": true, "古参": true, "新参": true, "新人": true, "一見": true,
	"旦那": true, "親御": true, "大家": true, "家主": true, "地主": true, "運営": true, "相方": true,
	"奥方": true, "女将": true, "親方": true, "坊主": true, "和尚": true, "住職": true, "神主": true,
	"皆": true, "皆皆": true, "各位": true, "常連客": true, "乗客": true, "顧客": true, "来店客": true,
	"御客": true, "親父": true, "母親": true, "父親": true, "隣人": true, "近所": true, "御近所": true,
	// 企業 IR の「株主様向けイベント」「個人投資家様向け説明会」と、自治体の「里親さんを知る日」
	// （2026-10-30 04:00 に実測した偽陽性。いずれも立場を表す一般語で特定の個人を指さない）。
	"株主": true, "個人投資家": true, "投資家": true, "里親": true,
	// 自治体の広報紙名「広報さんむ」等（「広報」+ ひらがなの紙名の先頭が「さん」）と、
	// 「子供さん」「サンタさん」（2026-10-30 06:00 に実測した高再現率モードの偽陽性）。
	"広報": true, "子供": true, "サンタ": true,
	// 「妊婦さん」「産婦さん」「農家さん」「宮司さん」「花嫁さん」（2026-10-30 08:00 に実測した
	// 高再現率モードの偽陽性。母子保健・催しの案内で立場を指す一般語）。
	"妊婦": true, "産婦": true, "妊産婦": true, "経産婦": true, "農家": true, "宮司": true, "花嫁": true,
	// 県の会議録の「市町村さんの方から」（2026-10-30 10:00 に実測した高再現率モードの偽陽性）。
	"市町村": true,
	// 企業サイトの「法人・事業主様」「販売店様向けサービス」と、テレビ CM の題名「義姉さんの家」
	// （2026-10-30 14:00 に実測した高再現率モードの偽陽性。立場・続柄を指す一般語）。
	"事業主": true, "販売店": true, "義姉": true, "義兄": true, "義妹": true, "義弟": true, "義母": true, "義父": true,
	// 不動産買取の案内の「売主様」「買主様」（2026-10-30 14:00 に実測した高再現率モードの偽陽性）。
	"売主": true, "買主": true,
	// 宗教団体のサイトの「教主様のお言葉」、道の駅・温泉の「お1家族様につき」、住宅会社の「施工店様」
	// （2026-10-31 02:00 に実測した高再現率モードの偽陽性。立場を指す一般語で特定の個人ではない）。
	"教主": true, "家族": true, "施工店": true, "工務店": true,
	// 「企業様・団体様」「放送局様」「神父様」「声優さん」「代理人様の場合は」「将軍様の」
	// （2026-10-30 16:00 に企業・団体・図書館のサイトで実測した高再現率モードの偽陽性。
	// いずれも立場・職業・組織を指す一般語で、特定の個人の氏名ではない）。
	"企業": true, "団体": true, "放送局": true, "神父": true, "声優": true, "代理人": true, "将軍": true,
	// 神社・寺院のサイトの「氏神様」「天神様」「聖天様」「大神様」「菅公様」「楠公さん」「孝徳天皇様」
	// 「王太子様」と、「檀家さん」「叔父さん」「店舗様」「書店様」「個人様」（2026-10-30 18:00 に
	// 神社・寺院・出版社のサイトで実測した高再現率モードの偽陽性。神仏・歴史上の人物の尊称や、
	// 立場・続柄・取引先を指す一般語で、生存する特定の個人の氏名ではない）。
	"氏神": true, "天神": true, "聖天": true, "大神": true, "菅公": true, "楠公": true, "王太子": true,
	"檀家": true, "叔父": true, "叔母": true, "伯父": true, "伯母": true, "店舗": true, "書店": true, "個人": true,
	"神様": true, "仏様": true, "明神": true,
	// 「加盟店さんこんにちは」「息子さんが通い」「黄門様も会員の」（2026-10-30 20:00 にラジオ局・
	// 社会福祉法人・鉄道会社のサイトで実測した高再現率モードの偽陽性。取引先・続柄を指す一般語と
	// 時代劇の登場人物の通称で、特定の個人の氏名ではない）。
	"加盟店": true, "息子": true, "娘": true, "黄門": true,
	// 「観音様のお年夜」「大黒様のお歳夜」「教皇様にお会いできる」「職人さんの謡曲教室」
	// 「飲食店様からのお問い合わせ」「作家様への申請」（2026-10-30 22:00 に商業施設・教会・
	// 温泉・レコード会社のサイトで実測した高再現率モードの偽陽性。神仏・聖職の尊称と、
	// 職業・取引先を指す一般語で、特定の個人の氏名ではない）。
	"観音": true, "大黒": true, "教皇": true, "職人": true, "飲食店": true, "作家": true,
	// 「同業他社さんとのお付き合い」「大国様と八幡様」「親王様はその句を」（2026-10-31 04:00 に
	// 和菓子店・祭りのサイトで実測した高再現率モードの偽陽性。取引先を指す一般語と、神・皇族の尊称）。
	"同業他社": true, "他社": true, "同業者": true, "大国": true, "親王": true, "内親王": true,
	// 「教育機関様専用ご注文用紙」「取扱店様一覧」「各社様」「生徒さんがデザインした」「風邪様症状」
	// （2026-10-31 06:00 に天文台・企業・キャンプ場のサイトで実測した高再現率モードの偽陽性。取引先・
	// 立場を指す一般語と、「〜のような」の意味の「様」で、特定の個人の氏名ではない）。
	"教育機関": true, "取扱店": true, "各社": true, "生徒": true, "風邪": true,
}

// honorificCommonNounSuffixes は、「社員皆さん」「来場者皆様」「常連客様」の
// ように、一般語 + 敬称の前に別の語が付いた形の語尾。
//
// 「出荷農家さん」「潮来花嫁さん」「<神社名>宮司さん」「<市名>災害協力会様」「旧<姓>印刷さん」
// （2026-10-30 08:00 に実測した偽陽性）のように、立場を指す一般語や団体・店の名称の
// 語尾も含める。団体・店は個人を識別しない（代表者名を含まない）。
// 「対象株主様」「<社名> <地名>工場様」（2026-10-30 14:00 に企業の IR・事業所案内で実測した偽陽性）の
// 「株主」「工場」「販売店」「事業主」と、業界団体の「<業界>連合会様」も語尾に含める。
var honorificCommonNounSuffixes = []string{"皆", "客", "農家", "花嫁", "宮司", "妊婦", "産婦", "協力会", "自治会", "町内会", "生徒会", "児童会", "保護者会", "組合", "印刷", "株主", "工場", "販売店", "事業主", "連合会", "企業", "団体", "放送局",
	// 「<諡号>天皇様」「秘仏毘沙門天様」「不動明王様」「<地名>大明神様」（2026-10-30 18:00 に神社・寺院の
	// 由緒の案内で実測した偽陽性。神仏と歴史上の天皇の尊称）。
	"天皇", "毘沙門天", "弁財天", "弁才天", "大黒天", "明王", "菩薩", "如来", "権現", "明神", "大神", "檀家", "書店", "店舗",
	// 「別途作家様」「<地名>職人さん」「<地名>刑務所さんとの連携」「<神社名>下社様」「<色・花>組さん」
	// （2026-10-30 22:00 にレコード会社・専門学校・建設会社・幼稚園のサイトで実測した偽陽性。
	// 職業・施設・神社の名称と、幼稚園のクラス名で、個人を識別しない）。
	"作家", "職人", "飲食店", "刑務所", "観音", "神社", "下社", "上社", "大社", "組",
	// 「<人名>記念館さんのご協力により」「<市>博物館様」（2026-10-31 00:00 に音楽ホール・文書館の
	// サイトで実測した偽陽性。施設の名称で、個人を識別しない）。「古館さん」のような姓を巻き添えに
	// しないよう、「館」1 字ではなく施設の種類を表す語尾だけを入れる。
	"記念館", "博物館", "美術館", "資料館", "文学館", "図書館", "文書館", "公民館", "会館",
	// 宗教団体のサイトの「月日御両神様」（2026-10-31 02:00 に実測した偽陽性。神の尊称で個人ではない）。
	"両神",
	// 「<中学校名>生徒さん制作のポスター」「<地域>教育機関様」（2026-10-31 06:00 に実測した偽陽性）。
	"生徒", "教育機関", "取扱店"}

// countNameRe は「二名」「３名」「数名」のような人数の表記に一致する。
var countNameRe = regexp.MustCompile(`^[一二三四五六七八九十百千数何0-9０-９]+名$`)

// rejectHonorificCommonNoun は、敬称（さん・様）の直前の漢字列が一般語
// （honorificCommonNouns・honorificCommonNounSuffixes）である場合に棄却する。
// 「氏」「殿」は一般語に付くことがほぼ無いので対象外にする。
func rejectHonorificCommonNoun(line string, start, end int) bool {
	rest := line[end:]
	// 「白描源氏絵」「源氏物語」の「源氏」は氏族・作品名で、「<姓>氏」の敬称ではない
	// （2026-10-30 16:00 に美術館の講演会案内で実測した高再現率モードの偽陽性）。
	// ただし「<姓>源氏」のように「源」の前が 2 文字以上の辞書の姓なら、名「源」+ 敬称「氏」とみなす。
	if v := line[start:end]; strings.HasPrefix(rest, "氏") && strings.HasSuffix(v, "源") {
		if sur := strings.TrimSuffix(v, "源"); utf8.RuneCountInString(sur) < 2 || dict.MatchPersonName(sur) != dict.SurnameOnly {
			return false
		}
	}
	// 「南部杜氏の技」「越後杜氏」の「杜氏」は酒造りの職人を指す一般語で、「<姓>氏」の敬称ではない
	// （2026-10-30 18:00 に新聞社サイトの広告文で実測した高再現率モードの偽陽性）。
	if strings.HasPrefix(rest, "氏") && strings.HasSuffix(line[start:end], "杜") {
		return false
	}
	// 「<神社>氏子青年会」「<地区>氏子が」の「氏子」は神社の信者を指す一般語で、「<名>氏」の敬称ではなく、
	// 「横浜港大さん橋」の「さん橋」は桟橋（2026-10-31 04:00 に祭り・アリーナのサイトで実測した
	// 高再現率モードの偽陽性）。
	// 「<姓><名>氏子育て講演会」は「<姓><名>氏」+「子育て」なので、「氏子育」は除外しない。
	if (strings.HasPrefix(rest, "氏子") && !strings.HasPrefix(rest, "氏子育")) || strings.HasPrefix(rest, "さん橋") {
		return false
	}
	if !strings.HasPrefix(rest, "さん") && !strings.HasPrefix(rest, "様") && !strings.HasPrefix(rest, "さま") {
		return true
	}
	v := line[start:end]
	// 「二名様からのご利用」「一名様でのご利用」（2026-10-31 06:00 にキャンプ場のサイトで実測した
	// 偽陽性）。人数 + 「名様」は利用人数で、氏名ではない。
	if countNameRe.MatchString(v) {
		return false
	}
	if honorificCommonNouns[v] {
		return false
	}
	for _, s := range honorificCommonNounSuffixes {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	return true
}

// historicalUjiSurnames / historicalUjiGiven は、名の末字が「氏」の歴史上の人物
// （足利尊氏・足利直義の一族 等）の姓と、「氏」の直前の 1 字。敬称アンカーは
// 「足利尊氏」の「氏」を敬称と読んで「足利尊」を氏名として報告していた
// （2026-10-30 06:00 に自治体の歴史講座の案内で実測した偽陽性）。歴史上の人物は
// 生存する個人ではないため報告しない。現代の「<姓><1 字名>氏」を巻き添えにしないよう、
// 武家の姓と通字に限定する。
var historicalUjiSurnames = []string{"足利", "北条", "今川", "新田", "上杉"}
var historicalUjiGiven = "尊高直義頼泰貞満基"

// rejectHistoricalUjiName は「<武家の姓><通字>氏」を棄却する（historicalUjiSurnames 参照）。
func rejectHistoricalUjiName(line string, start, end int) bool {
	if !strings.HasPrefix(line[end:], "氏") {
		return true
	}
	v := line[start:end]
	for _, s := range historicalUjiSurnames {
		if g, ok := strings.CutPrefix(v, s); ok && utf8.RuneCountInString(g) == 1 && strings.Contains(historicalUjiGiven, g) {
			return false
		}
	}
	return true
}

// rejectGradePrefix は、敬称アンカーの値が「6年生<姓><名>」「2年<姓><名>」のように数字の後の
// 学年表記から始まる場合に棄却する（学年を除いた範囲は専用パターンで拾い直す）。
func rejectGradePrefix(line string, start, end int) bool {
	v := line[start:end]
	if !strings.HasPrefix(v, "年") || start == 0 {
		return true
	}
	c := line[start-1]
	return !(c >= '0' && c <= '9')
}

// shrineHallWords は「中央殿・右脇殿・左脇殿の 3 棟」のように、神社の社殿の名前で「殿」の前に
// 来る語。敬称アンカーは「殿」を敬称と読んで「右脇」を氏名として報告していた（2026-10-30 10:00 に
// 町の文化財の案内で実測した高再現率モードの偽陽性）。「西脇」「東脇」は実在の姓なので含めない。
//
// 「祖霊殿」「参集殿」「宝物殿」「神楽殿」「儀式殿」「極楽殿」「日想殿」「神能殿」「立志殿」「<寺名>霊明殿」
// のような社殿・堂の名前も同じく「殿」の前に来る（2026-10-30 18:00 に神社・寺院のサイトで実測した
// 高再現率モードの偽陽性。新規分の神社・寺院の文書で「殿」の誤検出の大半を占めた）。
var shrineHallWords = map[string]bool{"右脇": true, "左脇": true, "中央": true,
	"祖霊": true, "参集": true, "宝物": true, "神楽": true, "儀式": true, "極楽": true, "日想": true,
	"神能": true, "立志": true, "拝": true, "本": true, "幣": true, "舞": true, "社": true, "客": true,
	"御": true, "宮": true, "寝": true, "仏": true, "祈祷": true, "祈願": true, "授与": true, "能楽": true,
	"斎": true, "祭儀": true, "霊明": true, "舎利": true,
	// 時代小説の紹介文の「伏魔殿」（2026-10-31 00:00 に出版社のサイトで実測した高再現率モードの偽陽性）。
	"伏魔": true,
	// 宗教団体のサイトの「御神殿」（2026-10-31 02:00 に実測した高再現率モードの偽陽性）。
	"御神": true}

// publicFounderSuffixes は学校・施設名の設置者を表す「市立」「県立」などの語尾。
var publicFounderSuffixes = []string{"市立", "町立", "村立", "区立", "県立", "都立", "府立", "道立", "国立", "私立", "公立"}

// shrineHallSuffixes は「<寺名>霊明殿」「<神社名>祖霊殿」のように、前に寺社名が付いた社殿名の語尾。
var shrineHallSuffixes = []string{"祖霊", "霊明", "参集", "宝物", "神楽", "儀式", "祈祷", "祈願", "授与"}

// rejectShrineHall は「<社殿の位置・名前>殿」（shrineHallWords・shrineHallSuffixes 参照）を棄却する。
func rejectShrineHall(line string, start, end int) bool {
	if !strings.HasPrefix(line[end:], "殿") {
		return true
	}
	v := line[start:end]
	// 「<市名>市立殿田小学校」のように、設置者の「<市町村・都道府県>立」の直後に「殿」で始まる
	// 地名が来る学校名（2026-10-30 20:00 に大学のニュース一覧で実測した高再現率モードの偽陽性）。
	for _, s := range publicFounderSuffixes {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	if shrineHallWords[v] {
		return false
	}
	for _, s := range shrineHallSuffixes {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	return true
}

// honorificTitlePrefixes は、敬称アンカーの値の途中に現れたとき、その後ろだけが氏名になる職名。
// 「<町名>町長<姓><名>様」「（委員長<姓><名>氏）」のように職名と氏名が地続きのとき、無空白の
// 敬称パターンは職名まで値に含めていた（2026-10-30 10:00 に実測した範囲の誤り）。
var honorificTitlePrefixes = []string{"委員長", "理事長", "市長", "町長", "村長", "区長", "副会長", "会長", "社長", "校長", "園長", "議長", "館長", "知事"}

// rejectHonorificTitlePrefix は、値が「…<職名><2 字以上>」の形（honorificTitlePrefixes 参照）なら
// 棄却する。職名を除いた範囲は personNameHonorificAfterTitleRe で拾い直す。値が職名で
// 終わる「<姓>社長様」や、職名を含まない値はそのまま通す。
func rejectHonorificTitlePrefix(line string, start, end int) bool {
	v := line[start:end]
	for _, t := range honorificTitlePrefixes {
		if i := strings.Index(v, t); i >= 0 && utf8.RuneCountInString(v[i+len(t):]) >= 2 {
			return false
		}
	}
	return true
}

// addressNonAddressNumberRe は、jp-address-high-recall の値が番地ではなく番号で終わる形。
// 「<市>告示第 12 号」「<年><町>条例第 3 号」「<人名>選手を<町>ふるさと大使第 1 号」のような
// 公文書・称号の番号（第〜号）と、「<町名>112 号線」のような道路の路線名（直後が「線」）。
// 町の入札結果・例規の一覧で、新規分の住所（高再現率）の 15% がこの形だった（2026-10-30 10:00 実測）。
var (
	addressDaiGoTailRe = regexp.MustCompile(`第(?:[0-9０-９]{1,4}|[` + kanjiDigits + `]{1,6})号$`)
	addressGoTailRe    = regexp.MustCompile(`(?:[0-9０-９]{1,4}|[` + kanjiDigits + `]{1,6})号$`)
)

// rejectAddressNonAddressNumber は addressNonAddress* の形（上記参照）を棄却する。丁目・番を含む
// 値（「1 丁目第 2 号」のような実在の番地）は棄却しない。
func rejectAddressNonAddressNumber(line string, start, end int) bool {
	v := line[start:end]
	if strings.Contains(v, "丁目") || strings.Contains(v, "番") {
		return true
	}
	if addressDaiGoTailRe.MatchString(v) {
		return false
	}
	if addressGoTailRe.MatchString(v) && strings.HasPrefix(line[end:], "線") {
		return false
	}
	return true
}

// rejectCommitteeListTail は personNameCommitteeListRe の一致の直後（役職の後）が読点か
// 行末であることを確かめる。「<姓><名>委員会」「<姓><名>会長賞」のように役職語が別の語の
// 一部になる形を棄却する。
func rejectCommitteeListTail(line string, start, end int) bool {
	rest := line[end:]
	for _, t := range []string{"副委員長", "委員長", "副会長", "会長", "副議長", "議長", "委員"} {
		if r, ok := strings.CutPrefix(rest, t); ok {
			r = strings.TrimLeft(r, " ")
			return r == "" || strings.HasPrefix(r, "、") || strings.HasPrefix(r, ",") || strings.HasPrefix(r, "，")
		}
	}
	return false
}

// endsWithKanji は s の最後のルーンが漢字（CJK 統合漢字・々）かを返す。
func endsWithKanji(s string) bool {
	r, _ := utf8.DecodeLastRuneInString(s)
	return r == '々' || unicode.Is(unicode.Han, r)
}

// rejectKaishaChoPrefix は、personNameHonorificAfterTitleRe が「株式会社長江電機様」のような
// 「会社」に続く社名の「社長」を職名と取り違えた値を棄却する（値の直前が「会社長」）。
// 2026-10-30 10:00 の全文書比較で実測した誤検出。
func rejectKaishaChoPrefix(line string, start, end int) bool {
	return !strings.HasSuffix(line[:start], "会社長")
}

// rejectDaiGoNumber は「第491150107800号」のように「第」と「号」で囲まれた数字列を棄却する。
// 古物商許可番号（公安委員会の 12 桁）や各種の許可・登録番号はこの書き方で載り、マイナンバーの
// 検査用数字を偶然満たすと jp-my-number の偽陽性になる。マイナンバーを「第…号」で書く様式はない。
// 「第」「号」と数字の間の空白は許容する。
func rejectDaiGoNumber(line string, start, end int) bool {
	before := strings.TrimRight(line[:start], " ")
	after := strings.TrimLeft(line[end:], " ")
	return !(strings.HasSuffix(before, "第") && strings.HasPrefix(after, "号"))
}
