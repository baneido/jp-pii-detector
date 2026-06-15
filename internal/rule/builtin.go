package rule

import (
	"regexp"
	"slices"
	"strings"

	"github.com/baneido/jp-pii-detecter/internal/checksum"
	"github.com/baneido/jp-pii-detecter/internal/dict"
)

// dg は数字エンティティ用の境界ガード付きパターンを生成する。
// 前後が数字でないことを保証する（RE2 は lookaround 非対応のため
// キャプチャグループで切り出す）。
func dg(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9])(` + core + `)(?:[^0-9]|$)`)
}

// dgNoSlash は dg と同じ境界ガードに加え、直前のスラッシュも除外する。
// URL のパス区切り（例: /articles/4608392522393）を数字列の一部と
// みなして誤検出するのを防ぐ。
func dgNoSlash(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9/])(` + core + `)(?:[^0-9]|$)`)
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
)

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
				{Re: dg(`\d{12}`), Base: Medium},
				// 前後にハイフンが続く場合はクレジットカード等の
				// 4-4-4-4 グループの一部とみなして除外する。
				{Re: regexp.MustCompile(`(?:^|[^0-9-])(\d{4}-\d{4}-\d{4})(?:[^0-9-]|$)`), Base: Medium},
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
				{Re: dg(`0[5-9]0-\d{4}-\d{4}`), Base: High},
				// 区切りなし携帯・IP 電話
				{Re: dg(`0[5-9]0\d{8}`), Base: Medium},
				// 区切りあり固定電話（市外局番 2〜5 桁）
				{Re: dg(`0\d{1,4}-\d{1,4}-\d{4}`), Base: Medium},
				// 国際表記 +81
				{Re: dg(`\+81[- ]?\d{1,4}[- ]?\d{1,4}[- ]?\d{3,4}`), Base: High},
			},
		},
		{
			ID:          "jp-postal-code",
			Description: "郵便番号",
			Prefilter:   PrefilterDigit,
			Context:     []string{"郵便番号", "郵便", "住所", "postal", "zipcode", "zip code", "〒"},
			Validate:    dict.ValidPostalCodePrefix,
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
						`\d{1,4}(?:丁目|番地?|号|(?:-\d{1,4}){1,2}))`,
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
						`\d{1,4}(?:丁目|番地?|号|(?:-\d{1,4}){1,2}))`,
				), Base: Medium},
			},
		},
		{
			ID:          "email-address",
			Description: "メールアドレス",
			Prefilter:   PrefilterAt,
			Validate:    validEmail,
			Patterns: []Pattern{
				{Re: regexp.MustCompile(`(?:^|[^A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})`), Base: High},
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
				{Re: dgNoSlash(`\d(?:[- ]?\d){12,18}`), Base: High},
				{Re: dg(`\d(?:[- ]?\d){0,5}[- ]\d(?:[- ]?\d){6,17}`), Base: High},
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
			Patterns: []Pattern{
				{Re: regexp.MustCompile(
					`(?:氏名|名前|姓名|フリガナ|ふりがな)\s*[:=]\s*` +
						`([` + kanji + hiragana + katakana + `]{2,12}(?:[ ][` + kanji + hiragana + katakana + `]{1,12})?)`,
				), Base: Low},
			},
		},
		{
			ID:          "person-name-high-recall",
			Description: "氏名（敬称・担当者アンカー付き・高再現率）",
			Prefilter:   PrefilterCJK,
			Patterns: []Pattern{
				{Re: regexp.MustCompile(
					`(?:担当|担当者|宛名|連絡先)\s*[:=]\s*` +
						`([` + kanji + `]{2,8}(?:[ ][` + kanji + `]{1,8})?)`,
				), Base: Medium},
				{Re: regexp.MustCompile(
					`(?:^|[^` + kanji + hiragana + katakana + `])` +
						`([` + kanji + `]{2,8})(?:様|さん|氏|殿)`,
				), Base: Medium},
			},
		},
		{
			ID:          "jp-birthdate",
			Description: "生年月日（ラベル付き）",
			Prefilter:   PrefilterDigit,
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
