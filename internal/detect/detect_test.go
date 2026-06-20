package detect

import (
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/piifixtures"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

func newDetector(t *testing.T, toml string) *Detector {
	t.Helper()
	cfg, err := config.Parse(toml)
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func ruleIDs(fs []Finding) []string {
	ids := make([]string, len(fs))
	for i, f := range fs {
		ids[i] = f.RuleID
	}
	return ids
}

func assertRules(t *testing.T, fs []Finding, want ...string) {
	t.Helper()
	got := map[string]bool{}
	for _, f := range fs {
		got[f.RuleID] = true
	}
	if len(fs) != len(want) {
		t.Fatalf("findings = %v, want rules %v", ruleIDs(fs), want)
	}
	for _, w := range want {
		if !got[w] {
			t.Fatalf("findings = %v, want rules %v", ruleIDs(fs), want)
		}
	}
}

// detect.mynumber_valid はテスト用に検査用数字を計算したダミーのマイナンバー。
func TestMyNumberRule(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	mynum := piifixtures.MustGet(t, "detect.mynumber_valid")
	mynumSep := piifixtures.MustGet(t, "detect.mynumber_valid_sep")
	mynumWide := piifixtures.MustGet(t, "detect.mynumber_valid_fullwidth")
	tests := []struct {
		name, line string
		want       []string
		conf       rule.Confidence
	}{
		{"コンテキストあり区切りあり", "マイナンバー: " + mynumSep, []string{"jp-my-number"}, rule.High},
		{"コンテキストなし", "value = " + mynum, []string{"jp-my-number"}, rule.Medium},
		{"全角数字", "個人番号：" + mynumWide, []string{"jp-my-number"}, rule.High},
		{"検査用数字不一致", "value = 123456789012", nil, 0},
		{"より長い数字列の一部は対象外", "id = 9" + mynum, nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanLine("f.txt", 1, tt.line)
			assertRules(t, fs, tt.want...)
			if len(fs) == 1 && fs[0].Confidence != tt.conf {
				t.Errorf("confidence = %v, want %v", fs[0].Confidence, tt.conf)
			}
		})
	}
}

func TestPhoneRule(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"携帯区切りあり", "TEL: " + piifixtures.MustGet(t, "detect.phone_mobile_sep"), []string{"jp-phone-number"}},
		{"携帯区切りなしコンテキストあり", "携帯 " + piifixtures.MustGet(t, "detect.phone_mobile_nosep"), []string{"jp-phone-number"}},
		{"固定電話区切りあり", "本社: " + piifixtures.MustGet(t, "detect.phone_fixed_tokyo"), []string{"jp-phone-number"}},
		{"国際表記", piifixtures.MustGet(t, "detect.phone_intl_mobile"), []string{"jp-phone-number"}},
		{"IP電話", piifixtures.MustGet(t, "detect.phone_ip"), []string{"jp-phone-number"}},
		{"全角と長音記号", "電話番号：" + piifixtures.MustGet(t, "detect.phone_mobile_fullwidth_longvowel"), []string{"jp-phone-number"}},
		{"桁数不正", "0123-456-78", nil},
		{"第2桁が0", "00-1234-5678", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestPhoneNoSepWithoutContextIsMedium(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	fs := d.ScanLine("f.txt", 1, piifixtures.MustGet(t, "detect.phone_mobile_nosep"))
	assertRules(t, fs, "jp-phone-number")
	if fs[0].Confidence != rule.Medium {
		t.Errorf("confidence = %v, want medium", fs[0].Confidence)
	}
}

func TestPostalAndAddress(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	postalOsaka := piifixtures.MustGet(t, "detect.postal_osaka")
	postalShibuya := piifixtures.MustGet(t, "detect.postal_shibuya")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"郵便マークと住所", "〒" + postalOsaka + " " + piifixtures.MustGet(t, "detect.address_umeda"), []string{"jp-postal-code", "jp-address"}},
		{"コンテキスト付き郵便番号", "郵便番号: " + postalShibuya, []string{"jp-postal-code"}},
		{"実在しない地域コードの郵便番号", "郵便番号: 000-0000", nil},
		{"コンテキストなし NNN-NNNN は対象外", "version " + postalShibuya, nil},
		{"番地つき住所", piifixtures.MustGet(t, "detect.address_shibuya"), []string{"jp-address"}},
		{"番地なしの地名のみは対象外", "東京都渋谷区では雨が降った", nil},
		{"号まで", "住所: " + piifixtures.MustGet(t, "detect.address_umeda_full"), []string{"jp-address"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestEmailRule(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"通常", "contact: " + piifixtures.MustGet(t, "detect.email_gmail"), []string{"email-address"}},
		{"全角アット", piifixtures.MustGet(t, "detect.email_gmail_fullwidth_at"), []string{"email-address"}},
		{"ドットとプラスとサブドメイン", "contact: " + piifixtures.MustGet(t, "detect.email_subdomain"), []string{"email-address"}},
		{"予約ドメイン example は除外", "user@example.com / user@sub.example.co.jp", nil},
		{"予約 TLD test は除外", "user@foo.test", nil},
		{"実在しない TLD は除外", "user@service.notatld", nil},
		{"IANA 登録済み TLD は検出", "contact: " + piifixtures.MustGet(t, "detect.email_dev"), []string{"email-address"}},
		{"Ruby インスタンス変数チェーンは除外", "@dates_by_month ||= (@participant.starts_on..@participant.finishes_on_by_status).group_by(&:beginning_of_month)", nil},
		{"Ruby unary minus receiver is not an email", "number_to_currency(-@bill.withholding_tax(worked_on))", nil},
		{"ローカル部の連続ドットは除外", "contact: taro..yamada@gmail.com", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestCreditCardRule(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"Visa 区切りあり", "card: 4111-1111-1111-1111", []string{"credit-card"}},
		{"JCB 区切りなし", "3530111333300000", []string{"credit-card"}},
		{"slash-prefixed separated card is still detected", "/4111-1111-1111-1111", []string{"credit-card"}},
		// 区切りなしカードがスラッシュ直後にある場合は、URL の記事 ID と
		// 区別できないため意図的に検出しない（割り切り）。同じ桁は
		// 区切りありなら上で検出される Luhn 妥当な Visa 番号。
		{"slash-prefixed contiguous card is intentionally not detected", "/4111111111111111", nil},
		{"Luhn 不正", "4111-1111-1111-1112", nil},
		{"URL article ID is not a card", "https://support.otetsutabi.com/hc/ja/articles/46129829524505", nil},
		{"URL article ID with shorter Luhn-passing number is not a card", "https://support.otetsutabi.com/hc/ja/articles/4608392522393", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestContextRequiredRules(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	license := piifixtures.MustGet(t, "detect.drivers_license")
	passport := piifixtures.MustGet(t, "detect.passport")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"運転免許", "免許証番号: " + license, []string{"jp-drivers-license"}},
		{"運転免許コンテキストなし", "id: " + license, nil},
		{"パスポート", "パスポート番号: " + passport, []string{"jp-passport"}},
		{"パスポートコンテキストなし", passport, nil},
		{"基礎年金番号", "基礎年金番号: " + piifixtures.MustGet(t, "detect.pension_number_sep"), []string{"jp-pension-number"}},
		{"在留カード", "在留カード番号 " + piifixtures.MustGet(t, "detect.residence_card"), []string{"jp-residence-card"}},
		{"銀行口座", "口座番号: " + piifixtures.MustGet(t, "detect.bank_account"), []string{"jp-bank-account"}},
		{"保険者番号", "保険者番号: " + piifixtures.MustGet(t, "detect.health_insurance"), []string{"jp-health-insurance"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestASCIIContextRequiresWordBoundary(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	license := piifixtures.MustGet(t, "detect.drivers_license")
	tests := []struct {
		name, line string
		want       []string
		conf       rule.Confidence
	}{
		{"tel は hotel の一部では成立しない", "hotel " + piifixtures.MustGet(t, "detect.phone_fixed_tokyo"), []string{"jp-phone-number"}, rule.Medium},
		{"license no は sublicense no の一部では成立しない", "sublicense no " + license, nil, 0},
		{"ASCII 語が独立していれば成立する", "license no " + license, []string{"jp-drivers-license"}, rule.High},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanLine("f.txt", 1, tt.line)
			assertRules(t, fs, tt.want...)
			if len(fs) == 1 && fs[0].Confidence != tt.conf {
				t.Errorf("confidence = %v, want %v", fs[0].Confidence, tt.conf)
			}
		})
	}
}

func TestIdentifierTokenContext(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	license := piifixtures.MustGet(t, "detect.drivers_license")
	bankAccount := piifixtures.MustGet(t, "detect.bank_account")
	tests := []struct {
		name, line string
		want       []string
	}{
		// camelCase / snake_case / kebab-case のラベルでも、構成語に分割して
		// コンテキストを満たせば RequireContext ルールが成立する。
		{"camelCase 口座番号", "bankAccountNo: " + bankAccount, []string{"jp-bank-account"}},
		{"camelCase 免許番号", "driverLicenseNumber: " + license, []string{"jp-drivers-license"}},
		{"camelCase 旅券番号", "passportNumber: " + piifixtures.MustGet(t, "detect.passport"), []string{"jp-passport"}},
		{"camelCase 在留カード", "residenceCardNumber: " + piifixtures.MustGet(t, "detect.residence_card"), []string{"jp-residence-card"}},
		{"snake_case 年金番号", "pension_number: " + piifixtures.MustGet(t, "detect.pension_number"), []string{"jp-pension-number"}},
		// 識別子の途中に語が埋もれている場合は成立しない（FP 抑制を維持）。
		{"smartphone は phone の語ではない", "smartphone" + piifixtures.MustGet(t, "detect.phone_mobile_nosep"), []string{"jp-phone-number"}},
		{"sublicense は license の語ではない", "sublicenseNumber: " + license, nil},
		{"無関係な camelCase ラベル", "userId: " + bankAccount, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestTokenizeIdentifiers(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"bankAccountNo", []string{"bank", "account", "no"}},
		{"driver_license_no", []string{"driver", "license", "no"}},
		{"birth-date", []string{"birth", "date"}},
		{"residenceCardNumber", []string{"residence", "card", "number"}},
		{"phoneNumber: 00000000000", []string{"phone", "number", "00000000000"}},
		{"userID", []string{"user", "id"}},
		{"APIKey", []string{"api", "key"}},
		{"HTTPServer", []string{"http", "server"}},
		{"smartphone", []string{"smartphone"}},
		// 連続大文字（頭字語）: 末尾の大文字を語頭として扱う。
		{"userID", []string{"user", "id"}},
		{"APIKey", []string{"api", "key"}},
		{"HTTPServer", []string{"http", "server"}},
		{"ID", []string{"id"}},
		{"", nil},
	}
	for _, tt := range tests {
		got := tokenizeIdentifiers(tt.in)
		if len(got) != len(tt.want) {
			t.Errorf("tokenizeIdentifiers(%q) = %v, want %v", tt.in, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("tokenizeIdentifiers(%q) = %v, want %v", tt.in, got, tt.want)
				break
			}
		}
	}
}

func TestDigitRulesRejectNearbyNegativeContext(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
	}{
		{"口座文脈下の金額", "口座開設は1234567円から可能"},
		{"免許文脈下の手数料", "免許の更新手数料 123456789012 円"},
		{"年金文脈下の受給額", "年金の受給額 1234567890 円"},
		{"保険文脈下の人数", "被保険者数は12345678人"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line))
		})
	}
}

func TestDigitRulesAllowIdentityWordsContainingNegativeCharacters(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"口座番号と名義", "口座番号: " + piifixtures.MustGet(t, "detect.bank_account") + " 名義: " + piifixtures.MustGet(t, "detect.name_full"), []string{"jp-bank-account"}},
		{"保険者番号と本人確認", "保険者番号: " + piifixtures.MustGet(t, "detect.health_insurance") + " 本人確認済み", []string{"jp-health-insurance"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestDigitRulesRequireNearbyPositiveContext(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	bankAccount := piifixtures.MustGet(t, "detect.bank_account")
	assertRules(t, d.ScanLine("f.txt", 1, "口座番号: "+bankAccount), "jp-bank-account")

	line := "口座番号は別紙に記載しています。" + strings.Repeat("あ", 40) + bankAccount
	assertRules(t, d.ScanLine("f.txt", 1, line))
}

func TestDigitRulesIgnoreDistantNegativeContext(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	line := "口座番号: " + piifixtures.MustGet(t, "detect.bank_account") + strings.Repeat("あ", 25) + "円"
	assertRules(t, d.ScanLine("f.txt", 1, line), "jp-bank-account")
}

func TestLabeledRules(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, `min_confidence = "low"`)
	tests := []struct {
		name, line string
		want       []string
	}{
		{"氏名", "氏名: " + piifixtures.MustGet(t, "detect.name_full_spaced"), []string{"person-name"}},
		{"フリガナ", "フリガナ＝" + piifixtures.MustGet(t, "detect.name_kana_full_wide"), []string{"person-name"}},
		{"生年月日 西暦", "生年月日: " + piifixtures.MustGet(t, "detect.birthdate_seireki"), []string{"jp-birthdate"}},
		{"生年月日 和暦", "生年月日：" + piifixtures.MustGet(t, "detect.birthdate_wareki"), []string{"jp-birthdate"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestPersonNameHiddenByDefault(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "") // 既定 min_confidence = medium
	assertRules(t, d.ScanLine("f.txt", 1, "氏名: "+piifixtures.MustGet(t, "detect.name_full_spaced")))
}

func TestHighRecallRulesDisabledByDefault(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	assertRules(t, d.ScanLine("f.txt", 1, "勤務地: "+piifixtures.MustGet(t, "detect.address_shibuya_ward")))
	assertRules(t, d.ScanLine("f.txt", 1, "担当: "+piifixtures.MustGet(t, "detect.name_full")))
}

func TestHighRecallRulesOptIn(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, `
[rules]
high_recall = true
`)
	assertRules(t, d.ScanLine("f.txt", 1, "勤務地: "+piifixtures.MustGet(t, "detect.address_shibuya_ward")), "jp-address-high-recall")
	assertRules(t, d.ScanLine("f.txt", 1, "担当: "+piifixtures.MustGet(t, "detect.name_full")), "person-name-high-recall")
}

func TestPersonNameLabeledExpansion(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, `min_confidence = "low"`)
	satoHanako := piifixtures.MustGet(t, "detect.name_sato_hanako")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"お名前 全角コロン", "お名前：" + piifixtures.MustGet(t, "detect.name_suzuki_hanako"), []string{"person-name"}},
		{"患者名", "患者名: " + piifixtures.MustGet(t, "detect.name_sato_ichiro_spaced"), []string{"person-name"}},
		{"顧客名", "顧客名: " + piifixtures.MustGet(t, "detect.name_tanaka_hanako"), []string{"person-name"}},
		{"担当者名", "担当者名: " + piifixtures.MustGet(t, "detect.name_ito_misaki_spaced"), []string{"person-name"}},
		{"氏名カナ サフィックス", "氏名カナ: " + piifixtures.MustGet(t, "detect.name_kana_full"), []string{"person-name"}},
		{"ASCII customer_name", "customer_name: " + satoHanako, []string{"person-name"}},
		{"ASCII full_name 日本語値", "full_name: " + piifixtures.MustGet(t, "detect.name_full"), []string{"person-name"}},
		{"JSON 風キー引用符", `{"customer_name": "` + satoHanako + `"}`, []string{"person-name"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestPersonNameWeakFieldsDictGated(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, `min_confidence = "low"`)
	sei := piifixtures.MustGet(t, "detect.name_sei") // 姓名辞書に載る姓
	mei := piifixtures.MustGet(t, "detect.name_mei") // 姓名辞書に載る名
	tests := []struct {
		name, line string
		want       []string
	}{
		// 姓名辞書に載る値は検出する。
		{"姓", "姓: " + sei, []string{"person-name"}},
		{"名", "名: " + mei, []string{"person-name"}},
		{"last_name", "last_name: " + sei, []string{"person-name"}},
		{"first_name", "first_name: " + mei, []string{"person-name"}},
		// 辞書に載らない一般名詞は弱いラベルでは棄却する。
		{"名 + 一般名詞", "名: 一覧", nil},
		{"last_name + 一般名詞", "last_name: 合計", nil},
		// ラベル種別を意識した検証: 名フィールドに姓だけが入る値は棄却する。
		{"名 + 姓のみ", "名: 田中", nil},
		{"first_name + 姓のみ", "first_name: 山田", nil},
		// 1 文字の単独要素（日常語と衝突しやすい）は棄却する。
		{"名 + 1文字", "名: 学", nil},
		{"first_name + 1文字", "first_name: 実", nil},
		// 「姓 + 名」に分割できる完全氏名はラベル種別を問わず許可する。
		{"名フィールドに姓名", "名: " + piifixtures.MustGet(t, "detect.name_full"), []string{"person-name"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// TestPersonNameAmbiguousASCIIKeysDictGated は user_name/account_name/contact_name/
// 裸 name（ハンドル名・キーになりうる）を辞書照合で絞ることを確認する（レビュー #1）。
func TestPersonNameAmbiguousASCIIKeysDictGated(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, `min_confidence = "low"`)
	tests := []struct {
		name, line string
		want       []string
	}{
		// 人名らしくない値は棄却。
		{"user_name + 管理者", "user_name: 管理者", nil},
		{"account_name + システム名", "account_name: 共有アカウント", nil},
		{"contact_name + 窓口", "contact_name: 問い合わせ窓口", nil},
		{"name + 会社名", "name: 株式会社", nil},
		// 人名らしい値は検出。
		{"user_name + 姓名", "user_name: " + piifixtures.MustGet(t, "detect.name_full"), []string{"person-name"}},
		{"name + 姓名", "name: " + piifixtures.MustGet(t, "detect.name_tanaka_taro"), []string{"person-name"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// TestPersonNameJPLabelBoundaryBlocksCompound は強い日本語ラベルが複合名詞の
// 一部（登録名前・変数名前 等）では発火しないことを確認する（レビュー #1）。
func TestPersonNameJPLabelBoundaryBlocksCompound(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	for _, line := range []string{
		"登録名前: 初期値",
		"変数名前: x値",
		"項目名前: テスト",
	} {
		t.Run(line, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, line))
		})
	}
}

// TestPersonNamePlaceholderSuffix は接尾辞付きプレースホルダ（未定です 等）も
// 棄却することを確認する（レビュー #2）。
func TestPersonNamePlaceholderSuffix(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	for _, line := range []string{
		"氏名: 未定です",
		"お名前: 非公開です",
		"氏名: 該当なしでした",
	} {
		t.Run(line, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, line))
		})
	}
}

func TestPersonNamePlaceholderRejected(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	for _, line := range []string{
		"氏名: 未定",
		"氏名: 該当なし",
		"お名前: 非公開",
		"担当者名: テストユーザー",
		"customer_name: サンプル太郎",
	} {
		t.Run(line, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, line))
		})
	}
}

func TestPersonNameNonPersonKeysExcluded(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, `min_confidence = "low"`)
	nameFull := piifixtures.MustGet(t, "detect.name_full")
	tanakaHanako := piifixtures.MustGet(t, "detect.name_tanaka_hanako")
	// 末尾が name の非人物 ASCII キーは前方境界で除外する。snake_case だけでなく
	// kebab-case（project-name）・dotted key（project.name）も裸の name ラベルの
	// 前方境界で除外する。会社名・品名・件名は日本語の非人物キーで、単一ラベル 名
	// の前方境界で除外する。
	for _, line := range []string{
		"project_name: " + nameFull,
		"company_name: " + tanakaHanako,
		"service_name: 鈴木システム",
		"package_name: 佐藤モジュール",
		"project-name: " + nameFull,
		"company-name: " + tanakaHanako,
		"service-name: " + piifixtures.MustGet(t, "detect.name_suzuki_ichiro"),
		"project.name: " + piifixtures.MustGet(t, "detect.name_sato_hanako"),
		"app.name: " + piifixtures.MustGet(t, "detect.name_takahashi_kenta"),
		"会社名: 山田商事株式会社",
		"品名: りんご",
		"件名: 重要なお知らせ",
	} {
		t.Run(line, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, line))
		})
	}
}

func TestPersonNameBareNameLabelDetected(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, `min_confidence = "low"`)
	// 裸の name ラベルは行頭・引用符・区切り直後など、識別子の一部でない
	// 位置でのみ人名として検出する（kebab/dotted の除外と両立させる回帰ガード）。
	tests := []struct {
		name, line string
		want       []string
	}{
		{"行頭 name", "name: " + piifixtures.MustGet(t, "detect.name_tanaka_taro"), []string{"person-name"}},
		{"JSON 風 name キー", `{"name": "` + piifixtures.MustGet(t, "detect.name_sato_hanako") + `"}`, []string{"person-name"}},
		{"カンマ直後 name", "id,name: " + piifixtures.MustGet(t, "detect.name_suzuki_ichiro"), []string{"person-name"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestPersonNameHighRecallDictGated(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, `
[rules]
high_recall = true
`)
	tests := []struct {
		name, line string
		want       []string
	}{
		// 姓名辞書に載る人名は敬称・担当ラベルで検出する。
		{"敬称 + 姓", piifixtures.MustGet(t, "detect.name_sei") + "様より連絡あり", []string{"person-name-high-recall"}},
		{"担当 + 姓名", "担当: " + piifixtures.MustGet(t, "detect.name_full"), []string{"person-name-high-recall"}},
		// 敬称は人物を強く示すため、辞書未収録の実在人名も取りこぼさない（レビュー #5）。
		{"敬称 + 辞書外の姓", piifixtures.MustGet(t, "detect.name_dict_external_full") + "様より連絡", []string{"person-name-high-recall"}},
		{"敬称 + 1文字名", piifixtures.MustGet(t, "detect.name_sei_plus_one_mei") + "様", []string{"person-name-high-recall"}},
		// 組織名 + 敬称は組織語尾で棄却する。
		{"組織 + 敬称", "田中商事様より連絡あり", nil},
		{"株式会社 + 敬称", "山田工業株式会社様", nil},
		// 担当ラベル（敬称なし）は姓名辞書で組織・部署を棄却する。
		{"部署 + 担当", "担当: 営業部", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestAllowlist(t *testing.T) {
	piifixtures.Require(t)
	stopword := piifixtures.MustGet(t, "detect.phone_mobile_stopword")
	phone := piifixtures.MustGet(t, "detect.phone_mobile_sep")
	d := newDetector(t, `
[allowlist]
stopwords = ["`+stopword+`"]
regexes = ["@baneido\\.com$"]
`)
	tests := []struct {
		name, line string
		want       []string
	}{
		{"stopword", "TEL: " + stopword, nil},
		{"regex 除外", piifixtures.MustGet(t, "detect.email_baneido"), nil},
		{"インラインマーカー", "TEL: " + phone + " // pii-allow ダミー", nil},
		{"ignore コメント", "TEL: " + phone + " # jp-pii-detector:ignore", nil},
		{"除外対象外は検出", "TEL: " + phone, []string{"jp-phone-number"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestDisabledRule(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, `
[rules]
disabled = ["jp-phone-number"]
`)
	assertRules(t, d.ScanLine("f.txt", 1, "TEL: "+piifixtures.MustGet(t, "detect.phone_mobile_sep")))
}

func TestOverlapResolution(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	// 「住所」コンテキスト下では郵便番号パターン \d{3}-\d{4} が電話番号
	// の先頭部分（例: "090-0000"）にもマッチし、範囲が重なる。長い方（電話番号）
	// だけが残ることを確認する（重複解決ロジックを実際に通るケース）。
	fs := d.ScanLine("f.txt", 1, "住所・電話: "+piifixtures.MustGet(t, "detect.phone_mobile_sep"))
	assertRules(t, fs, "jp-phone-number")
}

func TestResolveOverlaps(t *testing.T) {
	mk := func(id string, conf rule.Confidence, start, end int) Finding {
		return Finding{RuleID: id, Confidence: conf, start: start, end: end}
	}
	tests := []struct {
		name string
		in   []Finding
		want []string
	}{
		{"重複なしは全件残る", []Finding{mk("a", rule.High, 0, 5), mk("b", rule.High, 5, 10)}, []string{"a", "b"}},
		{"信頼度が高い方が勝つ", []Finding{mk("lo", rule.Medium, 0, 8), mk("hi", rule.High, 4, 10)}, []string{"hi"}},
		{"同率なら長い方が勝つ", []Finding{mk("short", rule.High, 0, 6), mk("long", rule.High, 4, 16)}, []string{"long"}},
		{"同率同長は先勝ち", []Finding{mk("first", rule.High, 0, 6), mk("second", rule.High, 3, 9)}, []string{"first"}},
		// 後から来た 1 件が既存の複数と重なるケース（旧実装は最初の 1 件
		// としか比較せず重複が残った）。
		{"複数と重なる場合は全部置き換える",
			[]Finding{mk("a", rule.Medium, 0, 5), mk("b", rule.Medium, 6, 10), mk("big", rule.High, 0, 10)},
			[]string{"big"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, resolveOverlaps(tt.in), tt.want...)
		})
	}
}

// 境界ガードが区切り文字を消費しても、隣接する次の PII を
// 取りこぼさないこと（回帰テスト: 旧実装は 2 件目以降を見逃した）。
func TestAdjacentFindings(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	pa := piifixtures.MustGet(t, "detect.phone_mobile_sep_a")
	pb := piifixtures.MustGet(t, "detect.phone_mobile_sep_b")
	pc := piifixtures.MustGet(t, "detect.phone_mobile_sep_c")
	na := piifixtures.MustGet(t, "detect.phone_mobile_nosep_a")
	nb := piifixtures.MustGet(t, "detect.phone_mobile_nosep_b")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"カンマ区切りの電話番号 2 件", pa + "," + pb,
			[]string{"jp-phone-number", "jp-phone-number"}},
		{"CSV 行の電話番号 3 件", piifixtures.MustGet(t, "detect.name_sei") + "," + pa + "," + pb + "," + pc,
			[]string{"jp-phone-number", "jp-phone-number", "jp-phone-number"}},
		{"区切りなし携帯の隣接", "tel: " + na + "," + nb,
			[]string{"jp-phone-number", "jp-phone-number"}},
		{"メールアドレス 2 件", piifixtures.MustGet(t, "detect.email_gmail_a") + "," + piifixtures.MustGet(t, "detect.email_gmail_b"),
			[]string{"email-address", "email-address"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// docs 4.4「4-4-4-4 グループ除外」: クレジットカード様式の数字列の先頭
// 12 桁が偶然マイナンバーの検査用数字を通過しても検出しない。
func TestMyNumber4x4GroupExcluded(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	// 有効なマイナンバー（区切りあり）は検査用数字を通過するが、後ろに -3456 が続く。
	assertRules(t, d.ScanLine("f.txt", 1, "code: "+piifixtures.MustGet(t, "detect.mynumber_valid_sep")+"-3456"))
}

// RequireContext のパターンはキーワードの存在が検出の前提のため High に
// 昇格せず、Base の信頼度のまま報告される（docs/detection-methods.md 4.3）。
// 旧実装は常に High へ昇格し、min_confidence = "high" で△ルールを
// 絞り込めなかった。
func TestContextRequiredConfidenceNotPromoted(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	bankAccount := piifixtures.MustGet(t, "detect.bank_account")
	license := piifixtures.MustGet(t, "detect.drivers_license")
	tests := []struct {
		name, line string
		want       string
		conf       rule.Confidence
	}{
		{"銀行口座は base の medium のまま", "口座番号: " + bankAccount, "jp-bank-account", rule.Medium},
		{"保険者番号は base の medium のまま", "保険者番号: " + piifixtures.MustGet(t, "detect.health_insurance"), "jp-health-insurance", rule.Medium},
		{"運転免許は base が high", "免許証番号: " + license, "jp-drivers-license", rule.High},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanLine("f.txt", 1, tt.line)
			assertRules(t, fs, tt.want)
			if fs[0].Confidence != tt.conf {
				t.Errorf("confidence = %v, want %v", fs[0].Confidence, tt.conf)
			}
		})
	}
	// min_confidence = "high" で medium 止まりの△ルールが除外できる。
	dh := newDetector(t, `min_confidence = "high"`)
	assertRules(t, dh.ScanLine("f.txt", 1, "口座番号: "+bankAccount))
	assertRules(t, dh.ScanLine("f.txt", 1, "免許証番号: "+license), "jp-drivers-license")
}

func TestReasonRecordsPromotionAndContext(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	fs := d.ScanLine("f.txt", 1, "tel: "+piifixtures.MustGet(t, "detect.phone_mobile_nosep"))
	assertRules(t, fs, "jp-phone-number")
	reason := fs[0].Reason
	if reason.BaseConfidence != "medium" || reason.FinalConfidence != "high" || !reason.ContextPromoted {
		t.Fatalf("reason = %+v, want medium->high promotion", reason)
	}
	if len(reason.ContextKeywords) != 1 || reason.ContextKeywords[0] != "tel" {
		t.Fatalf("context keywords = %v, want [tel]", reason.ContextKeywords)
	}
	if !reason.Validated {
		t.Fatalf("validated = false, want true")
	}
}

func TestReasonNotValidatedWhenNoValidator(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	fs := d.ScanLine("f.txt", 1, "住所: "+piifixtures.MustGet(t, "detect.address_shibuya"))
	assertRules(t, fs, "jp-address")
	if fs[0].Reason.Validated {
		t.Fatalf("validated = true, want false (jp-address has no validator)")
	}
}

func TestReasonRecordsRequiredNearbyContext(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	fs := d.ScanLine("f.txt", 1, "口座番号: "+piifixtures.MustGet(t, "detect.bank_account"))
	assertRules(t, fs, "jp-bank-account")
	reason := fs[0].Reason
	if !reason.RequireContext || reason.ContextPromoted {
		t.Fatalf("reason = %+v, want required context without promotion", reason)
	}
	if reason.ContextWindow != 40 {
		t.Fatalf("context window = %d, want 40", reason.ContextWindow)
	}
	if len(reason.ContextKeywords) == 0 || reason.ContextKeywords[0] != "口座" {
		t.Fatalf("context keywords = %v, want first keyword 口座", reason.ContextKeywords)
	}
}

func TestMinConfidenceHigh(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, `min_confidence = "high"`)
	// 区切りなし携帯（コンテキストなし）は medium なので報告されない。
	assertRules(t, d.ScanLine("f.txt", 1, piifixtures.MustGet(t, "detect.phone_mobile_nosep")))
	// 区切りあり携帯は high なので報告される。
	assertRules(t, d.ScanLine("f.txt", 1, piifixtures.MustGet(t, "detect.phone_mobile_sep")), "jp-phone-number")
}

// stopword は全角表記とも正規化済みで照合される。
func TestStopwordNormalized(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, `
[allowlist]
stopwords = ["`+piifixtures.MustGet(t, "detect.phone_mobile_stopword")+`"]
`)
	assertRules(t, d.ScanLine("f.txt", 1, "TEL: "+piifixtures.MustGet(t, "detect.phone_mobile_stopword_fullwidth")))
}

// 固定電話は 10 桁のみ。11 桁は携帯・IP（0[5-9]0）に限る。
func TestPhoneDigitCountStrict(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	assertRules(t, d.ScanLine("f.txt", 1, "0123-456-7890"))                                                       // 11 桁の固定様式は実在しない
	assertRules(t, d.ScanLine("f.txt", 1, piifixtures.MustGet(t, "detect.phone_intl_fixed")), "jp-phone-number")  // +81 + 9 桁 = 固定 OK
	assertRules(t, d.ScanLine("f.txt", 1, "+81-12-3456-7890"))                                                    // +81 + 10 桁で携帯以外は不正
	assertRules(t, d.ScanLine("f.txt", 1, piifixtures.MustGet(t, "detect.phone_intl_mobile")), "jp-phone-number") // +81 携帯
}

func TestPositionReporting(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	phone := piifixtures.MustGet(t, "detect.phone_mobile_fullwidth")
	fs := d.ScanLine("f.txt", 7, "電話："+phone)
	assertRules(t, fs, "jp-phone-number")
	f := fs[0]
	if f.Line != 7 {
		t.Errorf("line = %d, want 7", f.Line)
	}
	if f.Column != 4 {
		t.Errorf("column = %d, want 4", f.Column)
	}
	if f.Match != phone {
		t.Errorf("match = %q (元テキストを保持すべき)", f.Match)
	}
}

func TestScanContent(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", "line1\nTEL: "+piifixtures.MustGet(t, "detect.phone_mobile_sep")+"\r\nline3")
	assertRules(t, fs, "jp-phone-number")
	if fs[0].Line != 2 {
		t.Errorf("line = %d, want 2", fs[0].Line)
	}
}

func TestScanContentSplitLabelAndValue(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	bankAccount := piifixtures.MustGet(t, "detect.bank_account")
	fs := d.ScanContent("f.txt", "口座番号:\n"+bankAccount)
	assertRules(t, fs, "jp-bank-account")
	if fs[0].Line != 2 || fs[0].Column != 1 {
		t.Fatalf("location = %d:%d, want 2:1", fs[0].Line, fs[0].Column)
	}
	if fs[0].Match != bankAccount {
		t.Fatalf("match = %q, want %q", fs[0].Match, bankAccount)
	}
}

func TestScanContentSplitValueAndLabel(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", piifixtures.MustGet(t, "detect.bank_account")+"\n口座番号:")
	assertRules(t, fs, "jp-bank-account")
	if fs[0].Line != 1 || fs[0].Column != 1 {
		t.Fatalf("location = %d:%d, want 1:1", fs[0].Line, fs[0].Column)
	}
}

func TestScanContentDoesNotDuplicateInlineContext(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", "口座番号: "+piifixtures.MustGet(t, "detect.bank_account")+"\n備考")
	assertRules(t, fs, "jp-bank-account")
}

func TestScanContentPreservesDocumentOrderWithAdjacentLineFindings(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", "口座番号:\n"+piifixtures.MustGet(t, "detect.bank_account")+"\nTEL: "+piifixtures.MustGet(t, "detect.phone_mobile_sep"))
	assertRules(t, fs, "jp-bank-account", "jp-phone-number")

	if fs[0].RuleID != "jp-bank-account" || fs[0].Line != 2 {
		t.Fatalf("first finding = %s at line %d, want jp-bank-account at line 2", fs[0].RuleID, fs[0].Line)
	}
	if fs[1].RuleID != "jp-phone-number" || fs[1].Line != 3 {
		t.Fatalf("second finding = %s at line %d, want jp-phone-number at line 3", fs[1].RuleID, fs[1].Line)
	}
}

func TestScanContentRejectsCrossLineNegativeContext(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	bankAccount := piifixtures.MustGet(t, "detect.bank_account")
	// 口座番号に見えるが、次の行に金額マーカーがある場合は検出しない。
	assertRules(t, d.ScanContent("f.txt", "口座番号: "+bankAccount+"\n円"))
	// 3 行にまたがるケースも、隣接行のネガティブコンテキストを抑制する。
	assertRules(t, d.ScanContent("f.txt", "口座番号:\n"+bankAccount+"\n円"))
	// ネガティブコンテキストが遠い場合は検出する。
	assertRules(t, d.ScanContent("f.txt", "口座番号: "+bankAccount+strings.Repeat("あ", 25)+"\n円"), "jp-bank-account")
}

// メールアドレスの右境界ガード。直後が英数字・_ % + - で続く部分一致を棄却し、
// 文末ピリオドや句点で終わる正当なアドレスは検出する。実在 PII ではない
// gmail.com の合成アドレスを inline で用いる。
func TestEmailRightBoundary(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       string // 期待する検出値。"" は非検出。
	}{
		{"通常", "連絡先: taro@gmail.com", "taro@gmail.com"},
		{"文末ピリオド", "連絡は taro@gmail.com.", "taro@gmail.com"},
		{"日本語句点", "連絡は taro@gmail.com。", "taro@gmail.com"},
		{"空白で区切り", "foo taro@gmail.com bar", "taro@gmail.com"},
		{"アンダースコアで継続は棄却", "value=taro@gmail.com_suffix", ""},
		{"プラスで継続は棄却", "value=taro@gmail.com+suffix", ""},
		{"英数字で継続は棄却", "id=taro@gmail.com2", ""},
		{"ハイフンで継続は棄却", "x taro@gmail.com-foo", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanLine("f.txt", 1, tt.line)
			var got string
			for _, f := range fs {
				if f.RuleID == "email-address" {
					got = f.Match
				}
			}
			if got != tt.want {
				t.Errorf("ScanLine(%q) email = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// 住所の番地連鎖（丁目→番→号）を最後まで捕捉する。合成住所を inline で用いる。
func TestAddressBanchiChain(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line, want string
	}{
		{"丁目番号の連鎖", "住所: 東京都渋谷区道玄坂2丁目10番7号", "東京都渋谷区道玄坂2丁目10番7号"},
		{"丁目とダッシュ", "住所: 大阪府大阪市北区梅田1丁目2-3", "大阪府大阪市北区梅田1丁目2-3"},
		{"ダッシュ連結3組", "住所: 東京都千代田区丸の内2-1-5", "東京都千代田区丸の内2-1-5"},
		{"番地の号", "住所: 神奈川県横浜市西区みなとみらい10番地の7", "神奈川県横浜市西区みなとみらい10番地の7"},
		{"丁目のみ", "住所: 東京都渋谷区道玄坂2丁目", "東京都渋谷区道玄坂2丁目"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanLine("f.txt", 1, tt.line)
			var got string
			for _, f := range fs {
				if f.RuleID == "jp-address" {
					got = f.Match
				}
			}
			if got != tt.want {
				t.Errorf("ScanLine(%q) jp-address = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// jp-birthdate ルール全体として、無効な暦日が検出されないことを確認する
// （validBirthdate の単体テストは internal/rule/builtin_test.go）。
func TestBirthdateRejectsInvalidDates(t *testing.T) {
	d := newDetector(t, "")
	assertRules(t, d.ScanLine("f.txt", 1, "生年月日: 2023-99-99"))
	assertRules(t, d.ScanLine("f.txt", 1, "生年月日: 2023-02-29"))
	assertRules(t, d.ScanLine("f.txt", 1, "生年月日: 2000-01-01"), "jp-birthdate")
}
