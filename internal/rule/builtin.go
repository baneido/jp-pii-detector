package rule

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/baneido/jp-pii-detector/internal/checksum"
	"github.com/baneido/jp-pii-detector/internal/dict"
)

// dg は数字エンティティ用の境界ガード付きパターンを生成する。
// 前後が数字でないことを保証する（RE2 は lookaround 非対応のため
// キャプチャグループで切り出す）。
func dg(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9])(` + core + `)(?:[^0-9]|$)`)
}

// dgNoAlnum は dg と同じ境界ガードに加え、前後の ASCII 英字も除外する。
// hex ハッシュや UUID など英数字トークンの内部に偶然現れた数字列を、
// 独立した番号として切り出さないために使う。
func dgNoAlnum(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9A-Za-z])(` + core + `)(?:[^0-9A-Za-z]|$)`)
}

// dgNoDigitBeforeNoAlnumHyphenAfter は左側は数字連結だけを除外し、右側は ASCII
// 英数字・ハイフン連結を除外する。電話番号のように ASCII ラベル直後へ値が続く
// "smartphone090..." は拾いつつ、UUID のようなハイフン区切りトークン内部は
// 除外するために使う。
func dgNoDigitBeforeNoAlnumHyphenAfter(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9])(` + core + `)(?:[^0-9A-Za-z-]|$)`)
}

// dgNoAlnumHyphen は英数字とハイフンで連結されたトークンの内部を除外する。
// UUID のようなハイフン区切り識別子の一部を、番号として切り出さないために使う。
func dgNoAlnumHyphen(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9A-Za-z-])(` + core + `)(?:[^0-9A-Za-z-]|$)`)
}

// dgNoSlash は dg と同じ境界ガードに加え、直前のスラッシュも除外する。
// URL のパス区切り（例: /articles/4608392522393）を数字列の一部と
// みなして誤検出するのを防ぐ。
func dgNoSlash(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9/])(` + core + `)(?:[^0-9]|$)`)
}

// dgNoSlashAlnumHyphen は dgNoSlash と dgNoAlnumHyphen を組み合わせた
// 境界ガード。URL パス直後の数字列と、英数字・ハイフン連結トークン内部を除外する。
func dgNoSlashAlnumHyphen(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9A-Za-z/-])(` + core + `)(?:[^0-9A-Za-z-]|$)`)
}

// ag は英数字エンティティ用の境界ガード付きパターンを生成する。
func ag(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9A-Za-z])(` + core + `)(?:[^0-9A-Za-z]|$)`)
}

func stripSeparators(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, s)
}

const (
	kanji    = `\x{4E00}-\x{9FFF}\x{3005}` // 漢字 + 々
	hiragana = `\x{3041}-\x{3096}`
	katakana = `\x{30A1}-\x{30FA}\x{30FC}` // カタカナ + ー

	digitRuleRequireContextWindow = 40

	// banchi は番地表現（丁目→番地→号）を最後まで捕捉する終端パターン。次を捕捉:
	//   2丁目10番7号 / 2丁目10-7 / 2-10-7 / 10番地の7 / 10番7号 / 2丁目（番地なし）
	// 構造は「任意の N丁目」＋「番地ブロック（番/号/ダッシュ連結のいずれかを必須）」、
	// または「N丁目」単独。番地ブロックは 番[地] か 号 か ダッシュ連結のいずれかを
	// 必ず含み、号は終端（号の後ろは続かない）とすることで、号の後ろの部屋番号・
	// 電話番号や、丁目の後ろの「階」の数字など、単位もダッシュも伴わない裸の数字列を
	// 吸収しない。RE2 は線形時間なので連鎖長による破滅的バックトラックは起きない。
	banchi = `(?:` +
		`(?:\d{1,4}丁目)?(?:\d{1,4}番地?(?:の?\d{1,4})?号?|\d{1,4}号|\d{1,4}(?:-\d{1,4})+)` +
		`|\d{1,4}丁目` +
		`)`
)

// 氏名ルールで共用する部分パターン。正規化済みの行を前提とする
// （全角コロン `：`・全角イコール `＝`・全角スペースは正規化で半角になる）。
var (
	// personNameLabelJP は値の前に来る氏名系の日本語ラベル（語そのものが人物を
	// 表す強いラベル）。氏名漢字 / 氏名カナ / お名前カナ 等は末尾サフィックスで吸収する。
	personNameLabelJP = `(?:氏名|お名前|ご氏名|名前|姓名|フリガナ|ふりがな|フルネーム|` +
		`患者名|契約者名|利用者名|顧客名|会員名|申込者名|請求先名|受取人|担当者名)(?:漢字|カナ|かな)?`
	// personNameLabelASCIIStrong は語そのものが「人」を表す ASCII キー。
	// 辞書照合なしで検出する（収録外の人名も拾う）。user_name / account_name /
	// contact_name はハンドル名・システム名でありうるため強ラベルには入れず、
	// 辞書照合つきの弱ラベル側で扱う。
	personNameLabelASCIIStrong = `(?:full_?name|customer_?name|patient_?name|applicant_?name)`
	// personNameBoundary は強・弱ラベル共通の前方境界。識別子連結文字
	// （英数字・_）に加えて漢字・かなも禁止し、登録名前 / 会社名 / 変数名前 のように
	// ラベル語が複合名詞の一部になっているケースを除外する。
	personNameBoundary = `(?:^|[^` + kanji + hiragana + katakana + `0-9A-Za-z_])`
	// personNameBareNameBoundary は裸の name ラベル専用の前方境界。上記に加えて
	// kebab-case の `-` と dotted key の `.` も禁止し、project-name / company-name /
	// project.name など末尾が name の非人物キーを誤検出しないようにする。
	personNameBareNameBoundary = `(?:^|[^-.` + kanji + hiragana + katakana + `0-9A-Za-z_])`
	// personNameSep はラベルと値の区切り。キー側の閉じ引用符（"name":）と
	// 値側の開き引用符・括弧（: "山田" / ：「山田」）の両方を許容する。
	personNameSep = `["']?\s*[:=]\s*["'「『（(]?\s*`
	// personNameValue は氏名の値（漢字・かな・カナ列。任意で半角スペース
	// 区切りの 2 語）。強いラベル用に 2 文字以上を要求する。
	// 既知の軽微な限界: `氏名: 山田 様` のように値の後に敬称が続くと、敬称まで
	// マスク対象に含まれうる（検出の成否・評価には影響しない表示上の過剰取り込み）。
	personNameValue = `[` + kanji + hiragana + katakana + `]{2,12}` +
		`(?:[ ][` + kanji + hiragana + katakana + `]{1,12})?`
	// personNameValueShort は弱いラベル（姓・名の単一フィールド）用。1 文字も
	// 捕捉し、長さ・人名らしさの最終判断は validSurnameField 等の検証器に委ねる。
	personNameValueShort = `[` + kanji + hiragana + katakana + `]{1,12}` +
		`(?:[ ][` + kanji + hiragana + katakana + `]{1,12})?`
)

// personNamePlaceholders は氏名の値として現れるダミー語（人名ではない）。
// 値の正規表現が末尾の仮名を貪欲に取り込む（未定 → 未定です）ため、完全一致では
// なく部分一致（strings.Contains）で棄却する。
var personNamePlaceholders = []string{
	"未定", "不明", "該当なし", "該当無し", "なし", "無し", "非公開", "匿名",
	"名無し", "未設定", "未記入", "記入例", "空欄", "テスト", "サンプル", "ダミー",
}

// notPlaceholderName は氏名候補 v がプレースホルダ（未定・テスト等）を含まない
// ことを返す。氏名ルールの Validate に使い、ラベルはあるが値がダミーの行
// （氏名: 未定 / 氏名: 未定です など）を棄却する。
func notPlaceholderName(v string) bool {
	v = strings.TrimSpace(v)
	for _, s := range personNamePlaceholders {
		if strings.Contains(v, s) {
			return false
		}
	}
	return true
}

// personNameOrgSuffixes は組織・団体名の語尾。高再現率の敬称パターンで
// 「田中商事様」「○○株式会社様」のような組織名を棄却するために使う。
// 単漢字の語尾（部・課・店・社 等）は姓（阿部・服部 等）と衝突するため含めない。
var personNameOrgSuffixes = []string{
	"株式会社", "有限会社", "合同会社", "合資会社", "会社", "商事", "商店", "銀行",
	"信用金庫", "工業", "産業", "製作所", "事務所", "病院", "医院", "大学", "学校",
	"学園", "学院", "協会", "財団", "法人", "組合", "支店", "本店", "支社", "本社",
}

// notOrgName は氏名候補 v が組織名の語尾で終わらないことを返す。敬称（様/さん）は
// 人物を強く示すため、辞書照合（allowlist）ではなく組織語尾の除外（denylist）で
// 偽陽性を抑え、辞書未収録の実在人名を巻き添えで落とさないようにする。
func notOrgName(v string) bool {
	v = strings.TrimSpace(v)
	for _, s := range personNameOrgSuffixes {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	return true
}

// 弱いラベル（姓・名・last_name 等）の値検証。1 文字の単独要素は日常語と
// 衝突しやすいため、単独要素は 2 文字以上かつラベル種別（姓/名）に一致する
// 場合のみ許可する。「姓 + 名」に分割できる完全な氏名はラベル種別を問わず許可する。
func validSurnameField(v string) bool { return validNameField(v, true, false) }
func validGivenField(v string) bool   { return validNameField(v, false, true) }

// validFullNameField は姓・名のいずれか、または姓+名に分割できる値を許可する
// （name / user_name など姓名どちらが入るか不定のフィールド用）。
func validFullNameField(v string) bool { return validNameField(v, true, true) }

func validNameField(v string, allowSurname, allowGiven bool) bool {
	v = strings.TrimSpace(v)
	if dict.SplitsAsFullName(v) {
		return true
	}
	if len([]rune(v)) < 2 {
		return false
	}
	return (allowSurname && dict.IsSurname(v)) || (allowGiven && dict.IsGivenName(v))
}

// digitRuleNegativeContext は桁ベースのルールを棄却する近傍語
// （金額・数量・連番 ID など PII でない数字列の文脈）。
//
// 重要（隠れ結合）: 各語が「通貨接頭 / 通貨接尾 / カウンタ接尾 / 汎用」の
// どれであるかは internal/detect 側の hasNegativeContextNear が分類する
// （isCurrencyPrefix / isCurrencySuffix / isCounterSuffix・
// negative_context.go）。ここに語を足しても detect 側の分類器を更新しないと
// 黙って「汎用」扱いになり、前後の単位近接判定（数字の直後の「円」等）が
// 効かない。語の追加時は両所を併せて更新すること。
var digitRuleNegativeContext = []string{
	"円", "¥", "￥", "$", "千", "万", "億", "人", "名", "件", "個", "回", "点", "%", "％",
	// 注: "no." や "#" は採番ラベルだが、肯定文脈（口座・免許 等）が既に必須の
	// ため FP 抑制効果は薄く、"license no." のような正規ラベルを誤って棄却する
	// 副作用が大きいため除外している。
	"注文", "伝票", "管理番号", "通し番号", "連番",
}

// Builtin は組み込みルール一覧を返す。
func Builtin() []Rule {
	return []Rule{
		{
			ID:          "jp-my-number",
			Description: "マイナンバー（個人番号）",
			Prefilter:   PrefilterDigit,
			Context:     []string{"マイナンバー", "個人番号", "mynumber", "my number", "my_number"},
			Validate:    validMyNumber,
			Patterns: []Pattern{
				{Re: dgNoAlnumHyphen(`\d{12}`), Base: Medium},
				// 前後にハイフンが続く場合はクレジットカード等の
				// 4-4-4-4 グループの一部とみなして除外する。
				{Re: regexp.MustCompile(`(?:^|[^0-9A-Za-z-])(\d{4}-\d{4}-\d{4})(?:[^0-9A-Za-z-]|$)`), Base: Medium},
			},
		},
		{
			ID:          "jp-phone-number",
			Description: "電話番号（携帯・固定・IP・国際表記）",
			Prefilter:   PrefilterDigit,
			Context:     []string{"電話", "携帯", "連絡先", "tel", "phone", "fax", "mobile", "denwa"},
			Validate:    validPhone,
			Patterns: []Pattern{
				// 区切りあり携帯・IP 電話（060/070/080/090/050）
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0[5-9]0-\d{4}-\d{4}`), Base: High},
				// 区切りなし携帯・IP 電話
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0[5-9]0\d{8}`), Base: Medium},
				// 区切りあり固定電話（市外局番 2〜5 桁）
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{1,4}-\d{1,4}-\d{4}`), Base: Medium},
				// 国際表記 +81
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`\+81[- ]?\d{1,4}[- ]?\d{1,4}[- ]?\d{3,4}`), Base: High},
			},
		},
		{
			ID:          "jp-postal-code",
			Description: "郵便番号",
			Prefilter:   PrefilterDigit,
			Context:     []string{"郵便番号", "郵便", "住所", "postal", "zipcode", "zip code", "〒"},
			// 7 桁完全一致（ビットセット生成済みのとき。未生成なら上位 3 桁実在チェック）。
			Validate: dict.ValidPostalCode,
			Patterns: []Pattern{
				{Re: dg(`〒\s?\d{3}-?\d{4}`), Base: High},
				{Re: dg(`\d{3}-\d{4}`), Base: Medium, RequireContext: true},
			},
		},
		{
			ID:          "jp-address",
			Description: "住所（都道府県〜番地）",
			Prefilter:   PrefilterDigit,
			Context:     []string{"住所", "所在地", "自宅", "address", "居住"},
			Patterns: []Pattern{
				{Re: regexp.MustCompile(
					`((?:北海道|東京都|京都府|大阪府|[` + kanji + `]{2,3}県)` +
						`[` + kanji + hiragana + katakana + `0-9A-Za-z]{1,20}?[市区町村]` +
						`[` + kanji + hiragana + katakana + `0-9-]{0,30}?` +
						banchi + `)`,
				), Base: High},
			},
		},
		{
			ID:          "jp-address-high-recall",
			Description: "住所（都道府県なし・高再現率）",
			Prefilter:   PrefilterDigit,
			Context:     []string{"住所", "所在地", "勤務地", "勤務先", "自宅", "address"},
			Patterns: []Pattern{
				{Re: regexp.MustCompile(
					`(?:住所|所在地|勤務地|勤務先|自宅|address)?\s*[:=]?\s*(` +
						`[` + kanji + hiragana + katakana + `]{1,15}[市区町村]` +
						`[` + kanji + hiragana + katakana + `0-9-]{0,30}?` +
						banchi + `)`,
				), Base: Medium},
			},
		},
		{
			ID:          "email-address",
			Description: "メールアドレス",
			Prefilter:   PrefilterAt,
			Validate:    validEmail,
			Patterns: []Pattern{
				// 右境界ガード `(?:[^A-Za-z0-9_%+:-]|$)` を捕捉グループの外に置き、
				// user@gmail.com_suffix / user@gmail.com+suffix のように直後が
				// 英数字・_ % + - : で続く（メールアドレスの一部ではない）部分一致を
				// 棄却する。`:` は git@github.com:owner/repo.git のような
				// scp 形式の SSH URL をメールとして切り出さないために含める。
				// `.` は除外集合に含めないため、文末ピリオド
				// （…は user@example.com.）は従来どおり検出できる。
				{Re: regexp.MustCompile(`(?:^|[^A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:[^A-Za-z0-9_%+:-]|$)`), Base: High},
			},
		},
		{
			ID:          "credit-card",
			Description: "クレジットカード番号（Luhn + ブランドプレフィックス検証）",
			Prefilter:   PrefilterDigit,
			Context:     []string{"クレジット", "カード番号", "credit", "card"},
			Validate: func(m string) bool {
				return checksum.CreditCard(stripSeparators(m))
			},
			// パターンを 2 つに分ける理由:
			//  1) 区切りなし・区切りあり両方を拾うが、直前がスラッシュの
			//     数字列（URL パスの記事 ID 等）は誤検出を避けるため除外する。
			//  2) 区切り（- または空白）を 1 つ以上含むカード番号は、直前が
			//     スラッシュでも拾う（区切り付きの数字列はまず URL ID ではない）。
			// この割り切りにより、スラッシュ直後の「区切りなし」カード番号は
			// 検出できないが、URL の記事 ID と区別できないため意図的に許容する。
			Patterns: []Pattern{
				{Re: dgNoSlashAlnumHyphen(`\d(?:[- ]?\d){12,18}`), Base: High},
				{Re: dgNoAlnumHyphen(`\d(?:[- ]?\d){0,5}[- ]\d(?:[- ]?\d){6,17}`), Base: High},
			},
		},
		{
			ID:          "jp-drivers-license",
			Description: "運転免許証番号",
			Prefilter:   PrefilterDigit,
			Context: []string{"免許", "driver_license", "drivers_license", "driver's license",
				"drivers license", "driver license", "license no", "license number", "licence"},
			NegativeContext:      digitRuleNegativeContext,
			RequireContextWindow: digitRuleRequireContextWindow,
			Validate:             validDriversLicense,
			Patterns: []Pattern{
				{Re: dg(`\d{12}`), Base: High, RequireContext: true},
			},
		},
		{
			ID:          "jp-passport",
			Description: "旅券（パスポート）番号",
			Prefilter:   PrefilterDigit,
			Context:     []string{"パスポート", "旅券", "passport"},
			Validate:    validPassport,
			Patterns: []Pattern{
				{Re: ag(`[A-Z]{2}\d{7}`), Base: High, RequireContext: true},
			},
		},
		{
			ID:                   "jp-pension-number",
			Description:          "基礎年金番号",
			Prefilter:            PrefilterDigit,
			Context:              []string{"年金", "pension", "nenkin"},
			NegativeContext:      digitRuleNegativeContext,
			RequireContextWindow: digitRuleRequireContextWindow,
			Patterns: []Pattern{
				{Re: dg(`\d{4}-?\d{6}`), Base: High, RequireContext: true},
			},
		},
		{
			ID:          "jp-residence-card",
			Description: "在留カード番号",
			Prefilter:   PrefilterDigit,
			Context:     []string{"在留", "residence card", "zairyu"},
			Validate:    validResidenceCard,
			Patterns: []Pattern{
				{Re: ag(`[A-Z]{2}\d{8}[A-Z]{2}`), Base: High, RequireContext: true},
			},
		},
		{
			ID:                   "jp-bank-account",
			Description:          "銀行口座番号",
			Prefilter:            PrefilterDigit,
			Context:              []string{"口座", "普通預金", "当座預金", "支店番号", "account number", "account_no", "bank account", "kouza"},
			NegativeContext:      digitRuleNegativeContext,
			RequireContextWindow: digitRuleRequireContextWindow,
			Validate:             validBankAccount,
			Patterns: []Pattern{
				{Re: dg(`\d{7}`), Base: Medium, RequireContext: true},
			},
		},
		{
			ID:                   "jp-health-insurance",
			Description:          "健康保険 保険者番号・被保険者番号",
			Prefilter:            PrefilterDigit,
			Context:              []string{"保険者番号", "被保険者", "保険証", "health insurance", "hokensha"},
			NegativeContext:      digitRuleNegativeContext,
			RequireContextWindow: digitRuleRequireContextWindow,
			Validate:             validHealthInsurance,
			Patterns: []Pattern{
				{Re: dg(`\d{8}`), Base: Medium, RequireContext: true},
			},
		},
		{
			ID:          "person-name",
			Description: "氏名（ラベル付き）",
			Prefilter:   PrefilterCJK,
			// ラベル語を 1 つも含まない行（日本語コメント等）は正規表現走査を
			// まるごとスキップする（ホットパス最適化）。
			PrefilterLiterals: []string{
				"名", "姓", "苗字", "フリガナ", "ふりがな", "フルネーム", "受取人", "name",
			},
			// プレースホルダ（未定・該当なし・テスト等）の値はすべてのパターンで
			// 棄却する。非人物キー（project_name 等）はラベルの前方境界で除外する。
			Validate: notPlaceholderName,
			Patterns: []Pattern{
				// 強いラベル: 氏名系の日本語ラベルと、語そのものが「人」を表す
				// 複合 ASCII キー（full_name / customer_name 等）。値が人名らしいかは
				// 問わず（収録外の人名も拾うため）辞書照合はしない。前方境界
				// personNameBoundary で漢字・かな直後（登録名前: 等）を除外する。
				// JSON/YAML のキー引用符（"氏名":）と値の引用符・括弧にも対応。
				{Re: regexp.MustCompile(
					personNameBoundary +
						`(?:` + personNameLabelJP + `|` + personNameLabelASCIIStrong + `)` +
						personNameSep +
						`(` + personNameValue + `)`,
				), Base: Low},
				// 弱いラベル: 姓側（姓・名字・苗字・last_name）。単独要素は 2 文字以上の
				// 姓、または姓+名に分割できる氏名のみ許可する（validSurnameField）。
				{Re: regexp.MustCompile(
					personNameBoundary +
						`(?:姓|名字|苗字|last_?name)` +
						personNameSep +
						`(` + personNameValueShort + `)`,
				), Base: Low, Validate: validSurnameField},
				// 弱いラベル: 名側（名・first_name）。単独要素は 2 文字以上の名、
				// または姓+名に分割できる氏名のみ許可する（validGivenField）。
				// 1 文字名（学・実 等）と姓（名: 田中）は棄却される。
				{Re: regexp.MustCompile(
					personNameBoundary +
						`(?:名|first_?name)` +
						personNameSep +
						`(` + personNameValueShort + `)`,
				), Base: Low, Validate: validGivenField},
				// 弱いラベル: 姓名どちらが入るか不定の ASCII キー
				// （user_name / account_name / contact_name）。ハンドル名・システム名
				// （管理者・共有アカウント 等）を姓名辞書で棄却する。
				{Re: regexp.MustCompile(
					personNameBoundary +
						`(?:user_?name|account_?name|contact_?name)` +
						personNameSep +
						`(` + personNameValueShort + `)`,
				), Base: Low, Validate: validFullNameField},
				// 裸の name ラベル。kebab-case / dotted key（project-name /
				// project.name 等）の末尾 name を誤検出しないよう前方境界で `-` `.`
				// も禁止し、値は姓名辞書で検証する（name: 株式会社 等を棄却）。
				{Re: regexp.MustCompile(
					personNameBareNameBoundary +
						`name` +
						personNameSep +
						`(` + personNameValueShort + `)`,
				), Base: Low, Validate: validFullNameField},
			},
		},
		{
			ID:                "person-name-high-recall",
			Description:       "氏名（敬称・担当者アンカー付き・高再現率）",
			Prefilter:         PrefilterCJK,
			PrefilterLiterals: []string{"担当", "宛名", "連絡先", "様", "さん", "氏", "殿"},
			Validate:          notPlaceholderName,
			Patterns: []Pattern{
				// 担当者・宛名・連絡先ラベル。敬称のような強い人物シグナルが無いため、
				// 組織名・部署名（営業部 等）の誤検出を姓名辞書（allowlist）で抑える。
				// 収録外の実在人名は取りこぼす（コンパクト辞書による再現率の上限）。
				{Re: regexp.MustCompile(
					`(?:担当|担当者|宛名|連絡先)` + personNameSep +
						`([` + kanji + `]{2,8}(?:[ ][` + kanji + `]{1,8})?)`,
				), Base: Medium, Validate: dict.IsPersonName},
				// 敬称アンカー（様/さん/氏/殿）。敬称は人物を強く示すため、辞書 allowlist
				// ではなく組織語尾の denylist（notOrgName）で「田中商事様」等を棄却する。
				// これにより辞書未収録の実在人名（桐谷太郎様 等）を巻き添えで落とさない。
				{Re: regexp.MustCompile(
					`(?:^|[^` + kanji + hiragana + katakana + `])` +
						`([` + kanji + `]{2,8})(?:様|さん|氏|殿)`,
				), Base: Medium, Validate: notOrgName},
			},
		},
		{
			ID:          "person-name-structured",
			Description: "氏名（構造化・ラベルと値が別行・高再現率）",
			Prefilter:   PrefilterCJK,
			// このルールは単一行パターンを持たない。フォーム形式で氏名ラベルと値が
			// 別の行に分かれるケース（氏名:\n山田太郎 等）を、detect.ScanContent の
			// クロスライン走査（scanCrossLineNames）が CrossLineNameLabelRe /
			// CrossLineNameValueRe / ValidCrossLineName を使って検出する。
			// 高再現率モードでのみ有効（HighRecallRuleIDs）。
		},
		{
			ID:          "jp-birthdate",
			Description: "生年月日（ラベル付き）",
			Prefilter:   PrefilterDigit,
			// 形式（西暦・和暦）だけでなく、実在する暦日かを検証する。
			// 2023-99-99 や 2023-02-29（閏年でない）などを棄却する。
			Validate: validBirthdate,
			Patterns: []Pattern{
				{Re: regexp.MustCompile(
					`(?:生年月日|誕生日)\s*[:=]?\s*` +
						`((?:(?:19|20)\d{2}|(?:明治|大正|昭和|平成|令和)\d{1,2})[年/.-]\d{1,2}[月/.-]\d{1,2}日?)`,
				), Base: Medium},
			},
		},
	}
}

// validMyNumber はマイナンバー（個人番号）の検査用数字に加え、ダミー値で
// よく使われる「先頭ゼロ埋め連番」（0000001 等）を棄却する。マイナンバーは
// 日付を符号化しないため、先頭 8 桁が暦日に見えることだけでは棄却しない。
func validMyNumber(m string) bool {
	d := stripSeparators(m)
	if !checksum.MyNumber(d) {
		return false
	}
	if checksum.IsZeroPaddedSequential(d) {
		return false
	}
	return true
}

// validDriversLicense は運転免許証番号（12 桁）のダミー値を棄却する。
// 検査用数字アルゴリズムは公式に非公開のためリバースエンジニアリング由来の
// 実装は採用せず、先頭桁（公安委員会コードは 10 以上 = 先頭桁が 0 でない）と、
// 全桁同一・ゼロ埋め連番のみを見る。
func validDriversLicense(m string) bool {
	return m != "" && m[0] != '0' && !checksum.AllSame(m) && !checksum.IsZeroPaddedSequential(m)
}

// validBankAccount は銀行口座番号（7 桁）の全桁同一・ゼロ埋め連番
// （0000001 等）のダミー値を棄却する。口座番号自体は検査用数字を
// 持たないため、これ以上の検証はできない。
func validBankAccount(m string) bool {
	return !checksum.AllSame(m) && !checksum.IsZeroPaddedSequential(m)
}

// validHealthInsurance は健康保険 保険者番号・被保険者番号（8 桁）の
// 全桁同一・ゼロ埋め連番のダミー値を棄却する。
func validHealthInsurance(m string) bool {
	return !checksum.AllSame(m) && !checksum.IsZeroPaddedSequential(m)
}

// validPassport は旅券（パスポート）番号（英字 2 + 数字 7）の末尾 7 桁が
// 全桁同一の明らかなダミー値（0000000 等）を棄却する。旅券冊子記号の先頭
// 文字制限（[T,M] 等）は外務省/ICAO の一次情報で裏取りができるまで導入しない
// （docs/detection-methods.md 参照）。
func validPassport(m string) bool {
	if len(m) < 7 {
		return false
	}
	return !checksum.AllSame(m[len(m)-7:])
}

// validResidenceCard は在留カード番号（英 2 + 数 8 + 英 2）のうち、
// 出入国在留管理庁の文字集合仕様で使われない英字 I・O を含む値と、
// 数字 8 桁が全桁同一のダミー値を棄却する。
func validResidenceCard(m string) bool {
	if len(m) != 12 {
		return false
	}
	letters := m[:2] + m[10:]
	if strings.ContainsAny(letters, "IO") {
		return false
	}
	return !checksum.AllSame(m[2:10])
}

func validPhone(m string) bool {
	d := stripSeparators(strings.TrimPrefix(m, "+"))
	if checksum.AllSame(d) {
		return false
	}
	// 加入者番号部（末尾 4 桁）が全桁同一はダミー値として棄却する
	// （携帯番号の末尾が 0000 で終わるケース等）。加入者番号部が昇順連番の
	// 値の棄却は、公的な採番禁止規則の一次情報が確認できるまで見送る。
	if len(d) >= 4 && checksum.AllSame(d[len(d)-4:]) {
		return false
	}
	if strings.HasPrefix(d, "81") {
		// 国番号を除いた市外局番以下は、固定 9 桁 / 携帯・IP 10 桁
		// （先頭 0 なし）。10 桁は携帯・IP のプレフィックス X0 のみ。
		rest := d[2:]
		switch len(rest) {
		case 9:
			return rest[0] != '0'
		case 10:
			return rest[0] >= '5' && rest[0] <= '9' && rest[1] == '0'
		}
		return false
	}
	// 国内表記は先頭 0、第 2 桁は 0 以外。固定電話は計 10 桁、
	// 11 桁は携帯・IP（0[5-9]0）のみ。
	if len(d) == 0 || d[0] != '0' {
		return false
	}
	switch len(d) {
	case 10:
		return d[1] != '0'
	case 11:
		return d[1] >= '5' && d[1] <= '9' && d[2] == '0'
	}
	return false
}

// birthdateRe は jp-birthdate の捕捉値（西暦 4 桁 or 和暦元号＋年・月・日）を
// 分解する。グループ: 1=西暦年 / 2=元号 / 3=和暦年 / 4=月 / 5=日。
// 区切りはルールの正規表現と同じ（年→月は [年/.-]、月→日は [月/.-]、末尾 日?）。
var birthdateRe = regexp.MustCompile(
	`^(?:((?:19|20)\d{2})|(明治|大正|昭和|平成|令和)(\d{1,2}))[年/.-](\d{1,2})[月/.-](\d{1,2})日?$`)

// warekiEra は元号の改元年（西暦）と、その元号で取りうる最大の和暦年を返す。
// 改元年を元年（1 年）とし、西暦 = start + 和暦年 - 1 で換算する。令和は
// 現時点で終期がないため正規表現の上限（2 桁）まで許容する。
func warekiEra(era string) (start, maxYear int, ok bool) {
	switch era {
	case "明治": // 1868–1912（明治45年7月30日まで）
		return 1868, 45, true
	case "大正": // 1912–1926（大正15年12月25日まで）
		return 1912, 15, true
	case "昭和": // 1926–1989（昭和64年1月7日まで）
		return 1926, 64, true
	case "平成": // 1989–2019（平成31年4月30日まで）
		return 1989, 31, true
	case "令和": // 2019–（終期なし）
		return 2019, 99, true
	}
	return 0, 0, false
}

// validBirthdate は捕捉した生年月日が実在する暦日かを検証する。形式上は
// 成立しても暦として無効な値（2023-99-99 / 2023-02-29 / 昭和65年… 等）を棄却する。
// 未来日や年齢の妥当性までは判定しない（信頼度ではなく検出可否のみを扱うため）。
func validBirthdate(m string) bool {
	sub := birthdateRe.FindStringSubmatch(m)
	if sub == nil {
		return false
	}
	var year int
	if sub[1] != "" {
		year, _ = strconv.Atoi(sub[1])
	} else {
		eraYear, _ := strconv.Atoi(sub[3])
		start, maxYear, ok := warekiEra(sub[2])
		if !ok || eraYear < 1 || eraYear > maxYear {
			return false
		}
		year = start + eraYear - 1
	}
	month, _ := strconv.Atoi(sub[4])
	day, _ := strconv.Atoi(sub[5])
	return validCalendarDate(year, month, day)
}

// validCalendarDate は西暦の年月日が実在する日付かを time.Date の
// ラウンドトリップで検証する（閏年・月ごとの日数を含む）。
func validCalendarDate(year, month, day int) bool {
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return false
	}
	t := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	return t.Year() == year && int(t.Month()) == month && t.Day() == day
}

// emailDummyWords はメールのダミー値でよく使われるローカル部・ドメイン第 1
// ラベルの語（personNamePlaceholders と同じ「部分一致 denylist」方式で棄却）。
// 既知の限界: 部分一致のため、これらの語を偶然含む実在のローカル部・ドメイン
// （barclays.co.jp の "bar" 等）を巻き添えで棄却しうる。hoge@fuga.co.jp や
// test1@sample.com のような明らかなダミー値の抑制を優先するトレードオフ。
var emailDummyWords = []string{"hoge", "fuga", "dummy", "hogehoge", "sample", "foo", "bar"}

// containsEmailDummyWord は s（ローカル部またはドメイン第 1 ラベル）が
// emailDummyWords のいずれかを部分一致で含むかを返す。
func containsEmailDummyWord(s string) bool {
	s = strings.ToLower(s)
	for _, w := range emailDummyWords {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// validEmail は予約済みドメイン（RFC 2606/6761）・ダミー値でよく使われる
// ローカル部/ドメイン語等を除外する。
func validEmail(m string) bool {
	at := strings.LastIndexByte(m, '@')
	if at <= 0 || at == len(m)-1 {
		return false
	}
	local := m[:at]
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return false
	}
	if !containsASCIIAlnum(local) {
		return false
	}
	domain := strings.ToLower(m[at+1:])
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	if containsEmailDummyWord(local) || containsEmailDummyWord(labels[0]) {
		return false
	}
	tld := labels[len(labels)-1]
	switch tld {
	case "test", "invalid", "localhost", "example", "local":
		return false
	}
	return !slices.Contains(labels, "example") && dict.ValidTLD(tld)
}

// containsASCIIAlnum はローカル部に英数字が 1 文字以上あるかを返す。
// ローカル部はパターンの文字クラス上 ASCII のみのためバイト走査でよい。
func containsASCIIAlnum(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			return true
		}
	}
	return false
}
