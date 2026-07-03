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
	// 既知の軽微な限界: ラベル値の後に「様」等の敬称が続くと（例: 山田 様）、敬称まで
	// マスク対象に含まれうる（検出の成否・評価には影響しない表示上の過剰取り込み）。
	personNameValue = `[` + kanji + hiragana + katakana + `]{2,12}` +
		`(?:[ ][` + kanji + hiragana + katakana + `]{1,12})?`
	// personNameValueShort は弱いラベル（姓・名の単一フィールド）用。1 文字も
	// 捕捉し、長さ・人名らしさの最終判断は validSurnameField 等の検証器に委ねる。
	personNameValueShort = `[` + kanji + hiragana + katakana + `]{1,12}` +
		`(?:[ ][` + kanji + hiragana + katakana + `]{1,12})?`
)

// person-name ルールの一部パターンは、辞書検証ありの Medium 判定と辞書照合
// なしの Low 判定を同一正規表現の 2 枚組（twin）で持つ。twin 間で正規表現
// オブジェクトを共有し、二重コンパイルを避けるためパッケージ変数として
// 定義する。
var (
	// personNameStrongLabelRe は強いラベル（氏名系日本語ラベル / full_name 等）
	// 用パターン。
	personNameStrongLabelRe = regexp.MustCompile(
		personNameBoundary +
			`(?:` + personNameLabelJP + `|` + personNameLabelASCIIStrong + `)` +
			personNameSep +
			`(` + personNameValue + `)`,
	)
	// personNameUserNameRe は姓名どちらが入るか不定の ASCII キー
	// （user_name / account_name / contact_name）用パターン。
	personNameUserNameRe = regexp.MustCompile(
		personNameBoundary +
			`(?:user_?name|account_?name|contact_?name)` +
			personNameSep +
			`(` + personNameValueShort + `)`,
	)
	// personNameBareRe は裸の name ラベル用パターン。
	personNameBareRe = regexp.MustCompile(
		personNameBareNameBoundary +
			`name` +
			personNameSep +
			`(` + personNameValueShort + `)`,
	)
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

// personNameRoleSuffixes は職業・役割・部署を表す語尾。敬称パターンの実測 FP
// である 本屋さん・運転手さん（職業）、取引先様・関係者様・保護者様・御中様
// （役割語）、経理部殿・総務課殿（部署）を棄却するために使う。単漢字の語尾
// （屋・部・課 等）は姓（阿部・服部・土屋・北条 等）と衝突するため、
// honorificPersonNameValid は辞書照合（dict.IsPersonName）を先に評価する順序で
// この denylist を適用し、辞書収録済みの衝突姓を巻き添えにしない。
var personNameRoleSuffixes = []string{
	"者", "員", "手", "屋", "師", "士", "長", "生", "部", "課", "係", "室", "先", "中",
}

// notRoleWord は氏名候補 v が職業・役割・部署の語尾（personNameRoleSuffixes）で
// 終わらないことを返す。
func notRoleWord(v string) bool {
	v = strings.TrimSpace(v)
	for _, s := range personNameRoleSuffixes {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	return true
}

// honorificPersonNameValid は敬称（様/さん/氏/殿）付き漢字氏名候補 v の検証器。
// 組織名の語尾（notOrgName）は常に棄却する。姓名辞書（dict.IsPersonName）に
// 一致すれば単漢字語尾の姓（阿部・土屋 等）でも許可し、辞書に無い値だけを
// 職業・役割・部署語尾（notRoleWord）で追加検証する。この評価順序により、
// 辞書未収録の実在人名（denylist 非該当）は引き続き Medium で検出される
// （detect_test.go の「敬称 + 辞書外の姓」ケースを参照）。
func honorificPersonNameValid(v string) bool {
	v = strings.TrimSpace(v)
	if !notOrgName(v) {
		return false
	}
	if dict.IsPersonName(v) {
		return true
	}
	return notRoleWord(v)
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
			Validate: func(m string) bool {
				return checksum.MyNumber(stripSeparators(m))
			},
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
			// 桁ベースの区切りなし固定電話パターンは業務 ID・型番等と衝突しやすいため、
			// 金額・数量・連番 ID 文脈での棄却（NegativeContext）を全パターンに適用する。
			NegativeContext:      digitRuleNegativeContext,
			RequireContextWindow: digitRuleRequireContextWindow,
			Validate:             validPhone,
			Patterns: []Pattern{
				// 区切りあり携帯・IP 電話（060/070/080/090/050）
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0[5-9]0-\d{4}-\d{4}`), Base: High},
				// 区切りなし携帯・IP 電話
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0[5-9]0\d{8}`), Base: Medium},
				// 区切りあり固定電話（市外局番 2〜5 桁）
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{1,4}-\d{1,4}-\d{4}`), Base: Medium},
				// 区切りなし固定電話（10 桁）。裸の \d{10} は型番・伝票番号等との
				// 衝突が非常に多く単独では出せないため、コンテキストキーワード必須
				// （RequireContext）にした上で validPhone が市外局番辞書
				// （dict.ValidAreaCode）で先頭一致の実在性を検証する。
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{9}`), Base: Medium, RequireContext: true},
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
			Validate: func(m string) bool {
				// 先頭 2 桁は公安委員会コードで 10 以上
				// （= 先頭桁が 0 でないことと等価）
				return !checksum.AllSame(m) && m[0] != '0'
			},
			Patterns: []Pattern{
				{Re: dg(`\d{12}`), Base: High, RequireContext: true},
			},
		},
		{
			ID:          "jp-passport",
			Description: "旅券（パスポート）番号",
			Prefilter:   PrefilterDigit,
			Context:     []string{"パスポート", "旅券", "passport"},
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
				// 複合 ASCII キー（full_name / customer_name 等）。前方境界
				// personNameBoundary で漢字・かな直後（登録名前: 等）を除外する。
				// JSON/YAML のキー引用符（"氏名":）と値の引用符・括弧にも対応。
				// 同一正規表現の 2 枚組（twin）: 値が姓名辞書に一致すれば Medium
				// （既定 min_confidence=medium で報告）、一致しない収録外の実在
				// 人名は Low のまま拾う。resolveOverlaps が同一スパンで信頼度の
				// 高い Medium を残す。
				{Re: personNameStrongLabelRe, Base: Medium, Validate: dict.IsPersonName},
				{Re: personNameStrongLabelRe, Base: Low},
				// 弱いラベル: 姓側（姓・名字・苗字・last_name）。validSurnameField が
				// 姓名辞書で検証済み（単独要素は 2 文字以上の姓、または姓+名に
				// 分割できる氏名のみ許可）のため、Base は Medium。
				{Re: regexp.MustCompile(
					personNameBoundary +
						`(?:姓|名字|苗字|last_?name)` +
						personNameSep +
						`(` + personNameValueShort + `)`,
				), Base: Medium, Validate: validSurnameField},
				// 弱いラベル: 名側（名・first_name）。validGivenField が姓名辞書で
				// 検証済み（単独要素は 2 文字以上の名、または姓+名に分割できる
				// 氏名のみ許可。1 文字名（学・実 等）と姓（名: 田中）は棄却）
				// のため、Base は Medium。
				{Re: regexp.MustCompile(
					personNameBoundary +
						`(?:名|first_?name)` +
						personNameSep +
						`(` + personNameValueShort + `)`,
				), Base: Medium, Validate: validGivenField},
				// 弱いラベル: 姓名どちらが入るか不定の ASCII キー
				// （user_name / account_name / contact_name）。ハンドル名・システム名
				// （管理者・共有アカウント 等）は姓名辞書で棄却する。同一正規表現の
				// 2 枚組: 姓+名に分割できる値のみ Medium（dict.SplitsAsFullName）。
				// name フィールドの値が単独の姓（大和 等、地名・一般名詞と同形になり
				// やすい）のみの場合は Low のまま昇格させない。
				{Re: personNameUserNameRe, Base: Medium, Validate: dict.SplitsAsFullName},
				{Re: personNameUserNameRe, Base: Low, Validate: validFullNameField},
				// 裸の name ラベル。kebab-case / dotted key（project-name /
				// project.name 等）の末尾 name を誤検出しないよう前方境界で `-` `.`
				// も禁止し、値は姓名辞書で検証する（name: 株式会社 等を棄却）。
				// user_name 系と同様、姓+名に分割できる値のみ Medium とし、
				// 値が単独の姓（大和 等）のみの場合は Low のまま昇格させない。
				{Re: personNameBareRe, Base: Medium, Validate: dict.SplitsAsFullName},
				{Re: personNameBareRe, Base: Low, Validate: validFullNameField},
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
				// 敬称アンカー（氏名の漢字表記 + 様/さん/氏/殿）。組織語尾
				// （notOrgName）は常に棄却し、辞書一致（dict.IsPersonName）を
				// 優先しつつ、辞書に無い値は職業・役割・部署の語尾 denylist
				// （notRoleWord）でも検証する（honorificPersonNameValid）。
				// これにより辞書未収録の実在人名（denylist 非該当）は Medium の
				// まま検出しつつ、職業語・役割語・部署語を伴う実測 FP を追加で
				// 棄却する。
				{Re: regexp.MustCompile(
					`(?:^|[^` + kanji + hiragana + katakana + `])` +
						`([` + kanji + `]{2,8})(?:様|さん|氏|殿)`,
				), Base: Medium, Validate: honorificPersonNameValid},
				// 敬称アンカー（ひらがな・カタカナの氏名 + 様/さん/氏/殿）。この
				// 文字種には notRoleWord のような語尾 denylist が効かないほど
				// 日常語との衝突が多いため、辞書一致必須の allowlist 方式
				// （dict.IsPersonName）で検証する。辞書収録済みのひらがな名
				// （例: さくら）は敬称付きでも検出され、日常語（例: たくさん・
				// みなさん）は辞書不在で棄却される。カタカナ人名は辞書未収録の
				// ため、外来語名の敬称付き表記はこのパターンでは解消しない
				// （辞書拡充は別課題として切り離す）。
				{Re: regexp.MustCompile(
					`(?:^|[^` + kanji + hiragana + katakana + `])` +
						`([` + hiragana + katakana + `]{2,8})(?:様|さん|氏|殿)`,
				), Base: Medium, Validate: dict.IsPersonName},
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

func validPhone(m string) bool {
	d := stripSeparators(strings.TrimPrefix(m, "+"))
	if checksum.AllSame(d) {
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
	// 国内表記は先頭 0。固定電話は計 10 桁、11 桁は携帯・IP（0[5-9]0）のみ。
	if len(d) == 0 || d[0] != '0' {
		return false
	}
	switch len(d) {
	case 10:
		if strings.ContainsAny(m, "- ") {
			return d[1] != '0'
		}
		// 区切りなし固定電話は市外局番辞書（dict.ValidAreaCode）で先頭一致の
		// 実在性を検証する。area_codes.txt は seed のため、区切りあり表記では
		// この辞書を必須にしない。
		_, ok := dict.ValidAreaCode(d)
		return ok
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

// validEmail は予約済みドメイン（RFC 2606/6761）等のダミー値を除外する。
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
