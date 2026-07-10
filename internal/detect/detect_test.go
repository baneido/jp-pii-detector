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

func TestNumericEntitiesInsideASCIIIdentifiersExcluded(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
	}{
		{"hex ハッシュ内のマイナンバー候補", "AssetHash: 100d177e8a8a510247564347f3827927"},
		{"ASCII トークン内の有効な電話番号", "id: tokenA09012345678Z"},
		{"ASCII トークン内の有効なクレジットカード番号", "id: tokenA4111111111111111Z"},
		{"UUID 内の数字混在 hex", "id: 510919b2-bbfe-4452-826e-a3d8d0674f59"},
		{"UUID 内の固定電話風部分", "id: 01adf5d1-0a06-4946-9681-49f35f03cf58"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line))
		})
	}
}

func TestUUIDv4FragmentsWithPIIContextExcluded(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
	}{
		{"電話番号文脈", "電話番号: 01adf5d1-0a06-4946-9681-49f35f03cf58"},
		{"郵便番号文脈", "郵便番号: aaaaa100-0001-4abc-8def-123456789abc"},
		{"口座番号文脈", "口座番号: a1234567-bbbb-4abc-8def-123456789abc"},
		{"保険者番号文脈", "保険者番号: 12345678-bbbb-4abc-8def-123456789abc"},
		{"免許番号文脈", "免許番号: aaaaaaaa-bbbb-4abc-8def-123456789012"},
		{"年金番号文脈", "年金番号: aaaaaaaa-bbbb-4abc-8def-1234567890ab"},
		{"在留カード文脈", "在留カード番号: aaaaaaaa-bbbb-4abc-8def-AB12345678CD"},
		{"コンパクト UUID の口座番号文脈", "口座番号: a1234567bbbb4abc8def123456789abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line))
		})
	}
}

func TestPhoneNumberAdjacentToASCIILeftLabelIsDetected(t *testing.T) {
	d := newDetector(t, "")
	phone := "090" + "1234" + "5678"

	assertRules(t, d.ScanLine("f.txt", 1, "smartphone"+phone), "jp-phone-number")
	assertRules(t, d.ScanLine("f.txt", 1, "id: tokenA"+phone+"Z"))
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

// TestPersonNameDefaultVisibility は既定 min_confidence=medium での可視化を
// 検証する（issue #44）。姓名辞書に一致する値はラベルだけで Medium に昇格し
// 既定で報告されるが、辞書に一致しない値（辞書外の実在人名・非人名の値・
// 単独姓のみの曖昧フィールド一致）は引き続き Low のまま既定では報告されない。
func TestPersonNameDefaultVisibility(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "") // 既定 min_confidence = medium
	tests := []struct {
		name, line string
		want       []string
	}{
		{"辞書一致の氏名は既定で可視化", "氏名: 山田太郎", []string{"person-name"}},
		{"辞書一致の氏名（name + 姓+名分割）", "name: 田中太郎", []string{"person-name"}},
		{"辞書外の実在人名は既定では非表示", "氏名: " + piifixtures.MustGet(t, "detect.name_dict_external_full"), nil},
		{"非人名の値は既定では非表示", "氏名: 株式会社", nil},
		{"単独姓のみの曖昧 name ラベルは既定では非表示", "name: 大和", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// TestPersonNameConfidencePromotion は辞書検証済みマッチが Medium に、
// 辞書に一致しないマッチが Low に留まることを信頼度レベルで検証する
// （issue #44: person-name Medium twin）。
func TestPersonNameConfidencePromotion(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, `min_confidence = "low"`)
	tests := []struct {
		name, line string
		conf       rule.Confidence
	}{
		// 強いラベル + 姓名辞書に分割できる値 → Medium。
		{"氏名 + 辞書一致（分割可）", "氏名: 山田太郎", rule.Medium},
		// 強いラベル + 辞書外の実在人名 → 収録外なので Low のまま。
		{"氏名 + 辞書外の実在人名", "氏名: " + piifixtures.MustGet(t, "detect.name_dict_external_full"), rule.Low},
		// 強いラベル + 非人名の値（組織名等）→ Low のまま。
		{"氏名 + 非人名の値", "氏名: 株式会社", rule.Low},
		// 曖昧な name ラベル + 単独姓のみ（分割不可）→ Low のまま
		// （地名・一般名詞と同形の単独姓による FP を Medium に上げない）。
		{"name + 単独姓のみ", "name: 大和", rule.Low},
		// 曖昧な name ラベル + 姓+名に分割できる値 → Medium。
		{"name + 姓+名に分割できる値", "name: 田中太郎", rule.Medium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanLine("f.txt", 1, tt.line)
			assertRules(t, fs, "person-name")
			if fs[0].Confidence != tt.conf {
				t.Errorf("confidence = %v, want %v", fs[0].Confidence, tt.conf)
			}
		})
	}
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

func TestPersonNameExpandedDictionaryWeakFields(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	tests := []struct {
		name, line string
	}{
		{"追加姓", "姓: 一ノ瀬"},
		{"追加名", "名: 凪沙"},
		{"曖昧 name キーの姓名", "name: 一ノ瀬 伊織"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), "person-name")
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
		// 単漢字語尾の姓は辞書一致（dict.IsPersonName）を先に評価するため、
		// 職業・役割・部署 denylist（notRoleWord）の巻き添えにならない。
		// 値はいずれも実在頻出姓（辞書収録済み）で、単独では特定個人を
		// 識別しないためリテラルで安全（田中/山田 と同様の扱い）。
		{"衝突姓（屋）+ さん", "土屋さんから電話がありました", []string{"person-name-high-recall"}},
		{"衝突姓（部）+ 様", "阿部様がいらっしゃいました", []string{"person-name-high-recall"}},
		{"衝突姓（部）+ さん", "服部さんに確認する", []string{"person-name-high-recall"}},
		// 職業語尾（者/員/手/屋/師/士/長/生/部/課/係/室/先/中）は辞書非一致の場合に
		// 棄却する。実測 FP をリテラルで安全に再現する。
		{"職業（屋）+ さん", "近所の本屋さんに行った", nil},
		{"職業（手）+ さん", "バスの運転手さんに聞いた", nil},
		{"役割語（先）+ 様", "取引先様各位にご連絡します", nil},
		{"役割語（者）+ 様", "関係者様各位へ通知する", nil},
		{"役割語（者）+ 様（保護者）", "保護者様へお知らせします", nil},
		{"御中 + 様（中）", "株式会社サンプル御中様", nil},
		{"部署（部）+ 殿", "経理部殿までご提出ください", nil},
		{"部署（課）+ 殿", "総務課殿へ提出", nil},
		// かな氏名は辞書一致必須の allowlist 方式（dict.IsPersonName）で検証する。
		// さくら は辞書収録済みのひらがな名として検出され、たくさん・みなさん は
		// 「たく」「みな」が辞書に無いため棄却される。
		{"かな氏名 + さん", "さくらさんと話した", []string{"person-name-high-recall"}},
		{"かな日常語（たくさん）", "在庫がたくさんある", nil},
		{"かな日常語（みなさん）", "みなさんこんにちは", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// TestPersonNameASCIILabelCaseInsensitive は ASCII 強ラベル（full_name 等）と
// 裸の name ラベルが大文字・キャメルケース表記でも検出されることを確認する
// （#48）。normalize は ASCII の大小文字を変換しないため、ラベルの
// `(?i:...)` 化と PrefilterLiterals 側の大小文字無視比較の両方が必要になる。
// 弱いラベル（last_name/first_name 等）は今回のスコープ外で、大文字表記のままでは
// 引き続き検出されないことも合わせて確認する。
func TestPersonNameASCIILabelCaseInsensitive(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	tests := []struct {
		name, line string
		want       []string
	}{
		{"大文字 FULL_NAME", "FULL_NAME: 田中太郎", []string{"person-name"}},
		{"混在 Customer_Name", "Customer_Name: 山田花子", []string{"person-name"}},
		{"大文字 PATIENT_NAME", "PATIENT_NAME: 田中太郎", []string{"person-name"}},
		{"キャメルケース customerName", "customerName: 山田花子", []string{"person-name"}},
		{"大文字 裸 NAME", "NAME: 田中太郎", []string{"person-name"}},
		{"混在 裸 Name", "Name: 山田花子", []string{"person-name"}},
		{"JSON 風大文字キー", `{"FULL_NAME": "田中太郎"}`, []string{"person-name"}},
		// スコープ外: 弱いラベル（last_name/first_name）は大文字表記では
		// 引き続き検出しない（#48 の対応方針どおり強ラベル・裸 name のみ対応）。
		{"弱いラベル大文字は対象外", "LAST_NAME: 田中太郎", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// TestPersonNameKatakanaMiddleDotValue はカタカナ中黒区切りの氏名
// （「ジョン・スミス」等）が強いラベルで全体（中黒を含む）を捕捉することを
// 確認する（#48）。personNameValue のみを拡張し、弱いラベル用の
// personNameValueShort は対象外のため、その境界も確認する。
func TestPersonNameKatakanaMiddleDotValue(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	t.Run("full_name 中黒区切り", func(t *testing.T) {
		fs := d.ScanLine("f.txt", 1, "full_name: ジョン・スミス")
		assertRules(t, fs, "person-name")
		if fs[0].Match != "ジョン・スミス" {
			t.Fatalf("match = %q, want %q", fs[0].Match, "ジョン・スミス")
		}
	})
	t.Run("氏名 中黒区切り", func(t *testing.T) {
		fs := d.ScanLine("f.txt", 1, "氏名：メアリー・ジョーンズ")
		assertRules(t, fs, "person-name")
		if fs[0].Match != "メアリー・ジョーンズ" {
			t.Fatalf("match = %q, want %q", fs[0].Match, "メアリー・ジョーンズ")
		}
	})
	// スコープ外: 弱いラベル（姓）は personNameValueShort を使うため中黒を
	// またいで値を捕捉せず、辞書照合にも通らないため検出しない。
	t.Run("姓ラベルは対象外", func(t *testing.T) {
		assertRules(t, d.ScanLine("f.txt", 1, "姓: ジョン・スミス"))
	})
}

// TestPersonNameBracketAdjacentLabel は強いラベルに鉤括弧・丸括弧が
// コロンなしで直結するケース（ご氏名「田中美咲」等）を検出することを確認する
// （#48）。personNameSepOrBracket は強いラベル専用で、弱いラベル（姓 等）には
// 適用しないことも確認する。
func TestPersonNameBracketAdjacentLabel(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	tests := []struct {
		name, line, wantMatch string
	}{
		{"日本語ラベル 鉤括弧直結", "ご氏名「田中太郎」", "田中太郎"},
		{"日本語ラベル 二重鉤括弧直結", "お名前『山田花子』", "山田花子"},
		{"ASCII強ラベル 丸括弧直結", "full_name(田中太郎)", "田中太郎"},
		{"ASCII強ラベル 全角丸括弧直結", "customer_name（山田花子）", "山田花子"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanLine("f.txt", 1, tt.line)
			assertRules(t, fs, "person-name")
			if fs[0].Match != tt.wantMatch {
				t.Fatalf("match = %q, want %q", fs[0].Match, tt.wantMatch)
			}
		})
	}
	// スコープ外: 弱いラベル（姓）はコロン必須の personNameSep のままで、
	// 鉤括弧直結では検出しない。
	t.Run("弱いラベルは対象外", func(t *testing.T) {
		assertRules(t, d.ScanLine("f.txt", 1, "姓「田中」"))
	})
}

// TestPersonNameSingleCharSurnameAllowed は姓ラベル（姓/last_name）専用で、
// 辞書収録済みの実在 1 文字姓（林・東 等）を許可することを確認する（#48）。
// 名ラベル・姓名不定の name ラベルは「名: 東」のような方角語等との衝突を
// 避けるため、引き続き 1 文字を許可しない（validGivenField/validFullNameField
// は allow1CharSurname=false のまま）。
func TestPersonNameSingleCharSurnameAllowed(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	tests := []struct {
		name, line string
		want       []string
	}{
		{"姓ラベル + 実在1字姓(林)", "姓: 林", []string{"person-name"}},
		{"姓ラベル + 実在1字姓(東)", "姓: 東", []string{"person-name"}},
		{"last_name + 実在1字姓", "last_name: 林", []string{"person-name"}},
		// 辞書未収録の1文字は従来どおり棄却する。
		{"姓ラベル + 辞書外1文字", "姓: 私", nil},
		// スコープ外: 名・姓名不定ラベルは1文字姓を許可しない。
		{"名ラベルは対象外", "名: 林", nil},
		{"nameラベルは対象外", "name: 林", nil},
		{"first_nameは対象外", "first_name: 東", nil},
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

// ignore マーカーはトークン境界一致で判定する（#50）。単純な部分文字列一致
// だと、旧マーカー pii-allow が pii-allowlist のような無関係な識別子・
// ファイル名にも一致し、行ごと誤って不可視化されてしまう。フィクスチャ不要の
// 電話番号リテラル（090-1234-5678、区切りありなので Base High で単体検出）を
// 使い、外部データなしで実行できるようにしている。
func TestMarkerTokenBoundary(t *testing.T) {
	d := newDetector(t, "")
	phone := "090-1234-5678"
	tests := []struct {
		name, line string
		want       []string
	}{
		{"pii-allow 単独では従来通り抑制される", "TEL: " + phone + " // pii-allow", nil},
		{"pii-allowlist は無関係な文字列として抑制しない", "TEL: " + phone + " // pii-allowlist.md 参照", []string{"jp-phone-number"}},
		{"文字列リテラル内の pii-allow を含む識別子は抑制しない", `errCode := "pii-allowlist-violation"; TEL: ` + phone, []string{"jp-phone-number"}},
		{"prefix-pii-allow のようにハイフンで連結された継続文字は抑制しない", "TEL: " + phone + " // prefix-pii-allow", []string{"jp-phone-number"}},
		{"jp-pii-detector:ignore 単独では従来通り抑制される", "TEL: " + phone + " // jp-pii-detector:ignore", nil},
		{"jp-pii-detector:ignored のような接尾辞つき識別子は抑制しない", "TEL: " + phone + " // jp-pii-detector:ignored-reason", []string{"jp-phone-number"}},
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
		// 信頼度・長さが同率のときは RuleID の辞書順で決める（挿入順＝
		// Builtin() 定義順には依存しない、issue #64 の付随改善）。
		{"同率同長は RuleID の辞書順", []Finding{mk("first", rule.High, 0, 6), mk("second", rule.High, 3, 9)}, []string{"first"}},
		// 挿入順を逆にしても RuleID の辞書順という結果は変わらないことを
		// 確認する（旧実装は挿入順＝先勝ちだったため、ここが "zzz" になっていた）。
		{"同率同長は挿入順に依存しない", []Finding{mk("zzz", rule.High, 0, 6), mk("aaa", rule.High, 3, 9)}, []string{"aaa"}},
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

// TestResolveOverlapsPerLine は resolveOverlapsPerLine 単体のテスト（issue #64）。
// File+Line でグループ化してから resolveOverlaps を再適用することを確認する。
func TestResolveOverlapsPerLine(t *testing.T) {
	mk := func(file string, line int, id string, conf rule.Confidence, start, end int) Finding {
		return Finding{File: file, Line: line, RuleID: id, Confidence: conf, start: start, end: end}
	}
	tests := []struct {
		name string
		in   []Finding
		want []string
	}{
		{
			"同一行で重なるパス間 finding は高信頼度のみ残る",
			[]Finding{
				mk("f.txt", 2, "jp-my-number", rule.Medium, 0, 12),
				mk("f.txt", 2, "jp-drivers-license", rule.High, 0, 12),
			},
			[]string{"jp-drivers-license"},
		},
		{
			"別の行にある finding は行を無視して統合されない（同じ列・同じ長さでも別行なら両方残る）",
			[]Finding{
				mk("f.txt", 1, "jp-phone-number", rule.High, 5, 18),
				mk("f.txt", 2, "jp-phone-number", rule.High, 5, 18),
			},
			[]string{"jp-phone-number", "jp-phone-number"},
		},
		{
			"別ファイルの finding も行を無視して統合されない",
			[]Finding{
				mk("a.txt", 1, "jp-phone-number", rule.High, 5, 18),
				mk("b.txt", 1, "jp-phone-number", rule.High, 5, 18),
			},
			[]string{"jp-phone-number", "jp-phone-number"},
		},
		{
			"重ならない finding は同一行でも両方残る",
			[]Finding{
				mk("f.txt", 1, "a", rule.High, 0, 5),
				mk("f.txt", 1, "b", rule.High, 5, 10),
			},
			[]string{"a", "b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, resolveOverlapsPerLine(tt.in), tt.want...)
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

// issue #68 段階1(b): RequireContext のないパターンを Base から High へ昇格
// させる判定は、RequireContextWindow 未設定でも既定半径
// （defaultPromotionContextWindow = 40 ルーン）に制限される。昇格前は行全体を
// 無制限に探索していたため、長い行の遠方にある無関係な 1 語だけで行全体の
// マッチが昇格していた（FP 増幅要因）。マイナンバーの検査用数字
// "123456789018" は internal/checksum.TestMyNumber の genMyNumber("12345678901")
// と同じ値でフィクスチャなしに使える。
func TestPromotionRequiresNearbyContext(t *testing.T) {
	d := newDetector(t, "")
	const mynum = "123456789018"
	tests := []struct {
		name      string
		line      string
		wantConf  rule.Confidence
		wantPromo bool
	}{
		{
			name:      "直後40ルーン以内のキーワードは昇格する",
			line:      mynum + strings.Repeat("あ", 10) + "マイナンバー",
			wantConf:  rule.High,
			wantPromo: true,
		},
		{
			name:      "直後40ルーンを超えるキーワードは昇格しない",
			line:      mynum + strings.Repeat("あ", 50) + "マイナンバー",
			wantConf:  rule.Medium,
			wantPromo: false,
		},
		{
			name:      "直前40ルーン以内のキーワードは昇格する",
			line:      "マイナンバー" + strings.Repeat("あ", 10) + mynum,
			wantConf:  rule.High,
			wantPromo: true,
		},
		{
			name:      "直前40ルーンを超えるキーワードは昇格しない",
			line:      "マイナンバー" + strings.Repeat("あ", 50) + mynum,
			wantConf:  rule.Medium,
			wantPromo: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanLine("f.txt", 1, tt.line)
			assertRules(t, fs, "jp-my-number")
			if fs[0].Confidence != tt.wantConf {
				t.Errorf("confidence = %v, want %v", fs[0].Confidence, tt.wantConf)
			}
			if fs[0].Reason.ContextPromoted != tt.wantPromo {
				t.Errorf("context promoted = %v, want %v", fs[0].Reason.ContextPromoted, tt.wantPromo)
			}
		})
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

// 実在の銀行名（辞書照合）は、既存の 8 語 Context が無い典型的な記載形式
// （銀行名＋支店＋普通/当座）でも jp-bank-account を発火させる。値は
// 辞書収録の銀行名（実在の固有名詞）とダミーの 7 桁を組み合わせただけで、
// 実在しうる口座番号ではないため外部フィクスチャなしでテストできる
// （internal/dict/names_test.go と同じ方針）。
func TestBankNameContextEnablesDetection(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"銀行名＋支店＋普通（既存 Context 語なし）", "三菱UFJ銀行 渋谷支店 普通 1234567", []string{"jp-bank-account"}},
		{"銀行名が行頭でなくても検出", "口座は みずほ銀行渋谷支店 普通預金 7654321 です", []string{"jp-bank-account"}},
		{"助詞が銀行名の直前に続いても検出", "取引銀行はみずほ銀行本店です 1234567", []string{"jp-bank-account"}},
		{"熟語が信用金庫名の直前に続いても検出", "取引先は京都信用金庫の支店です 2345678", []string{"jp-bank-account"}},
		{"地の文が英字混じり銀行名の直前に続いても検出", "先方の三菱UFJ銀行本店営業部 3456789", []string{"jp-bank-account"}},
		{"辞書未収録の架空銀行名は昇格しない", "架空銀行 渋谷支店 普通 1234567", nil},
		{"支店・普通単体はいまだに Context ではない", "支店 普通 1234567", nil},
		{"銀行名が 40 ルーン窓の外だと届かない", "みずほ銀行" + strings.Repeat("あ", 40) + "1234567", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// 銀行名の辞書照合は RequireContext の前提であり信頼度昇格の根拠にはならない
// （TestContextRequiredConfidenceNotPromoted と同じ不変条件）ため、Base の
// medium のまま報告される。
func TestBankNameContextDoesNotPromoteConfidence(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanLine("f.txt", 1, "三菱UFJ銀行 渋谷支店 普通 1234567")
	assertRules(t, fs, "jp-bank-account")
	if fs[0].Confidence != rule.Medium {
		t.Fatalf("confidence = %v, want medium", fs[0].Confidence)
	}
}

// 銀行名の辞書照合を追加しても、既存の金額・数量ネガティブコンテキストは
// 引き続き検出を抑制する。
func TestBankNameContextStillRejectsNegativeContext(t *testing.T) {
	d := newDetector(t, "")
	assertRules(t, d.ScanLine("f.txt", 1, "みずほ銀行の株価は1234567円です"))
	assertRules(t, d.ScanLine("f.txt", 1, "管理番号1234567（みずほ銀行の資料）"))
}

// ゆうちょ銀行の記号番号（記号5桁・先頭は必ず1、番号6〜8桁をハイフンで相関）。
// 値はダミーの数字列と辞書収録の「ゆうちょ銀行」表記のみを使い、外部フィクスチャ
// なしでテストできる。
func TestYuchoAccountRule(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"記号番号＋ゆうちょ表記", "ゆうちょ銀行 記号12340-7654321", []string{"jp-yucho-account"}},
		{"地の文に埋め込まれたゆうちょ銀行名", "取引銀行はゆうちょ銀行本店です 12340-7654321", []string{"jp-yucho-account"}},
		{"記号番号＋記号ラベル", "記号12345-1234567 ゆうちょ口座", []string{"jp-yucho-account"}},
		{"記号番号＋日本郵政系文脈", "日本郵政 12345-1234567", []string{"jp-yucho-account"}},
		{"通常銀行名はゆうちょ文脈にしない", "三菱UFJ銀行 12345-1234567", []string{"jp-bank-account"}},
		{"コンテキストなしは検出しない", "12345-1234567", nil},
		{"記号が1始まりでない", "記号22345-1234567 ゆうちょ", nil},
		{"記号が全桁同一のダミー値", "記号11111-111111 ゆうちょ", nil},
		{"番号が全桁同一のダミー値", "記号12345-9999999 ゆうちょ", nil},
		{"金額の負コンテキストで抑制", "ゆうちょ記号12345-1234567円", nil},
		{"長い数字列の一部は対象外", "8" + "12345-1234567" + " ゆうちょ", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// jp-yucho-account が共有する銀行名 ContextPattern も、空白なしの地の文から
// 「ゆうちょ銀行」だけを回収する。通常 Context にも「ゆうちょ」があるため、
// ContextPattern 自体の回帰を直接検証する。
func TestYuchoAccountContextPatternFindsEmbeddedBankName(t *testing.T) {
	var patterns []rule.ContextPattern
	for _, r := range rule.Builtin() {
		if r.ID == "jp-yucho-account" {
			patterns = r.ContextPatterns
			break
		}
	}
	got := matchContextPatterns("取引銀行はゆうちょ銀行本店です", patterns)
	if len(got) != 1 || got[0] != "ゆうちょ銀行" {
		t.Fatalf("matching contexts = %q, want [ゆうちょ銀行]", got)
	}
}

// jp-yucho-account の RequireContext パターンも Base の High のまま報告される
// （RequireContext は昇格の根拠にならない不変条件）。
func TestYuchoAccountConfidenceIsBaseHigh(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanLine("f.txt", 1, "ゆうちょ銀行 記号12340-7654321")
	assertRules(t, fs, "jp-yucho-account")
	if fs[0].Confidence != rule.High {
		t.Fatalf("confidence = %v, want high", fs[0].Confidence)
	}
	if fs[0].Match != "12340-7654321" {
		t.Fatalf("match = %q, want 12340-7654321", fs[0].Match)
	}
}

func TestScanContentUsesSourceContext(t *testing.T) {
	d := newDetector(t, "")
	assertRules(t, d.ScanContent("user.ts", `const bankAccountNo = "1234567"`), "jp-bank-account")
}

func TestScanContentSourceContextIgnoresQuotedOperators(t *testing.T) {
	d := newDetector(t, "")
	assertRules(t, d.ScanContent("user.ts", `const bankAccountNo = "version:1234567"`), "jp-bank-account")
}

func TestScanContentSourceNegativeContext(t *testing.T) {
	d := newDetector(t, "")
	assertRules(t, d.ScanContent("user.ts", `const bankAccountId = "1234567"`))
}

func TestScanContentSourceContextDoesNotLeakAcrossCommaStatements(t *testing.T) {
	d := newDetector(t, "")
	content := `const values = { bankAccountNo: "none", orderId: "1234567" }`
	assertRules(t, d.ScanContent("user.ts", content))
}

func TestScanContentSourceContextSplitKeyValue(t *testing.T) {
	d := newDetector(t, "")
	content := "bankAccountNo:\n" + strings.Repeat(" ", 48) + `"1234567"`
	assertRules(t, d.ScanContent("user.yaml", content), "jp-bank-account")
}

func TestScanContentAdjacentKeepsSourceNegativeContextOnValueLine(t *testing.T) {
	d := newDetector(t, "")
	content := "bankAccountId:\n" + `bankAccountId: "1234567"`
	assertRules(t, d.ScanContent("user.yaml", content))
}

// 回帰テスト（#50）: scanAdjacentLines は隣接 2 行を結合した文字列に対して
// 旧実装では ScanLine（＝ignoredLine を結合文字列全体に適用）を呼んでいたため、
// ラベル行に残った ignore マーカーが、マーカーを持たない値行の検出まで
// 巻き添えで抑制してしまっていた。scanAdjacentLinesDiff と同じく
// scanLineNoIgnore ＋ 値が乗る行だけの ignoredLine チェックに揃えたことで、
// 値行（マーカーなし）の検出は巻き添えにされない。
func TestScanContentAdjacentIgnoreDoesNotSuppressOtherLine(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", "口座番号 // jp-pii-detector:ignore\n1234567")
	assertRules(t, fs, "jp-bank-account")
	if fs[0].Line != 2 || fs[0].Column != 1 {
		t.Fatalf("location = %d:%d, want 2:1", fs[0].Line, fs[0].Column)
	}
}

// 逆方向: 値そのものが乗る行に ignore マーカーがあれば、従来どおり抑制される
// （巻き添え防止の修正が、値行自身の抑制まで壊していないことの確認）。
func TestScanContentAdjacentIgnoreSuppressesOwnLine(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", "口座番号\n1234567 // jp-pii-detector:ignore")
	assertRules(t, fs)
}

func TestScanDiffHunkSourceContextFromContextLine(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanDiffHunk("user.yaml", []DiffLine{
		{Text: "bankAccountNo:", Added: false},
		{Text: strings.Repeat(" ", 48) + `"1234567"`, Added: true},
	})
	assertRules(t, fs, "jp-bank-account")
}

func TestScanDiffHunkKeepsSourceNegativeContextOnAddedLine(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanDiffHunk("user.yaml", []DiffLine{
		{Text: "bankAccountId:", Added: false},
		{Text: `bankAccountId: "1234567"`, Added: true},
	})
	assertRules(t, fs)
}

// issue #68 段階1(a): 同一文にこのルール自身の正ラベルが（負文脈語を伴わずに）
// 明示されている場合、hasNegativeNear は離れた場所の一般的な負文脈語（連番等）
// で誤って値を棄却しない（正ラベル優先）。一方、ラベル自体が id 等の負文脈語を
// 伴う場合（bankAccountId）は対象外で、旧来どおり（無条件ハードドロップ）棄却
// され続ける。この2ケースを直接対比する。
func TestSourceContextPositiveLabelOverridesDistantNegativeContext(t *testing.T) {
	d := newDetector(t, "")

	// 正ラベル（bankAccountNo）+ 同一文内の離れた一般負文脈語（連番）。
	// 新方式では棄却されない（旧方式は無条件ドロップしていた＝FN）。
	positive := `bankAccountNo := "1234567 連番ではない"`
	assertRules(t, d.ScanContent("account.go", positive), "jp-bank-account")

	// ラベル自体が負文脈語を伴う（bankAccountId）→ 正ラベル優先の例外対象外。
	// 旧方式・新方式のいずれでも棄却される（回帰確認）。
	negativeLabel := `bankAccountId := "1234567 連番ではない"`
	assertRules(t, d.ScanContent("account.go", negativeLabel))
}

// issue #68 段階1(a) の続き: ScanContent の隣接行負コンテキストフィルタ
// （hasCrossLineNegativeContext, negative_context.go）にも同じ正ラベル優先の
// 例外が効くことを確認する。クロスライン統語（ラベル行＋値行）で作られた
// 正ラベルは、値の行と同一文ではない「さらに次の行」にある一般負文脈語
// （連番）では棄却されない。detect.go 側の hasNegativeNear だけを直しても、
// ここが直っていないと ScanContent 経路では結局棄却されてしまう
// （フルツリー走査 internal/source が使う経路のため実運用上重要）。
func TestScanContentSourceContextPositiveLabelOverridesAdjacentLineNegativeContext(t *testing.T) {
	d := newDetector(t, "")
	content := "bankAccountNo:\n1234567\n連番"
	assertRules(t, d.ScanContent("account.yaml", content), "jp-bank-account")
}

// 構造化・複数行の氏名検出（person-name-structured）。値は埋め込み姓名辞書に
// 含まれる一般的な氏名（山田太郎 等）のリテラルを使い、外部フィクスチャ無しでも
// 実行できるようにしている（dict/names_test.go と同じ方針）。
const highRecallTOML = "[rules]\nhigh_recall = true\n"

func TestCrossLineNameLabelThenValue(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	fs := d.ScanContent("f.txt", "氏名:\n山田太郎")
	assertRules(t, fs, "person-name-structured")
	if fs[0].Line != 2 || fs[0].Column != 1 {
		t.Fatalf("location = %d:%d, want 2:1", fs[0].Line, fs[0].Column)
	}
	if fs[0].Match != "山田太郎" {
		t.Fatalf("match = %q, want 山田太郎", fs[0].Match)
	}
	if fs[0].Confidence != rule.Medium {
		t.Fatalf("confidence = %v, want medium", fs[0].Confidence)
	}
}

func TestCrossLineNameNormalizationAndQuotes(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	cases := []struct {
		name       string
		content    string
		wantLine   int
		wantColumn int
		wantMatch  string
	}{
		// 全角コロン・全角スペースのインデントは正規化で半角になり、列位置は元行基準。
		{"全角コロン + 全角スペース", "お名前：\n　鈴木花子", 2, 2, "鈴木花子"},
		// JSON 風キー引用符と値の引用符・インデント。
		{"引用符付きキーと値", "\"customer_name\":\n  \"田中一郎\"", 2, 4, "田中一郎"},
		// ASCII の強いラベル。
		{"full_name", "full_name:\n山田太郎", 2, 1, "山田太郎"},
		// 値が空白区切りの姓名。
		{"空白区切りの姓名", "氏名:\n山田 太郎", 2, 1, "山田 太郎"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := d.ScanContent("f.txt", tc.content)
			assertRules(t, fs, "person-name-structured")
			if fs[0].Line != tc.wantLine || fs[0].Column != tc.wantColumn {
				t.Fatalf("location = %d:%d, want %d:%d", fs[0].Line, fs[0].Column, tc.wantLine, tc.wantColumn)
			}
			if fs[0].Match != tc.wantMatch {
				t.Fatalf("match = %q, want %q", fs[0].Match, tc.wantMatch)
			}
		})
	}
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
		{"GitHub SSH URL は棄却", "repoURL: git@github.com:baneido/jp-pii-detecter.git", ""},
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

func TestCrossLineNameRejectsNonNames(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	// 組織名・プレースホルダ・辞書外の一般名詞は次行に来ても検出しない。
	for _, value := range []string{"株式会社", "未定", "プロジェクト", "該当なし"} {
		assertRules(t, d.ScanContent("f.txt", "氏名:\n"+value))
	}
}

func TestCrossLineNameExpandedDictionary(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	assertRules(t, d.ScanContent("f.txt", "氏名:\n越智凪沙"), "person-name-structured")
}

func TestCrossLineNameOnlyStrongLabels(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	// 弱いラベル（姓・名 の単一フィールド）のクロスライン結合は本スライスの対象外。
	// 姓:\n山田 は構造化ルールでは検出しない（姓名ペア結合は今後の拡張）。
	assertRules(t, d.ScanContent("f.txt", "姓:\n山田"))
}

func TestCrossLineNameDisabledByDefault(t *testing.T) {
	d := newDetector(t, "")
	// 高再現率モードでなければ構造化クロスライン検出は走らない（既定挙動を変えない）。
	assertRules(t, d.ScanContent("f.txt", "氏名:\n山田太郎"))
}

func TestCrossLineNameSameLineUnaffected(t *testing.T) {
	// 同一行に値があるラベルは従来どおり person-name（Low）で検出し、構造化ルールでは
	// 二重に拾わない（ラベル行は値を伴わない場合のみマッチするため）。Low を見るため
	// min_confidence=low と高再現率を併用する。
	d := newDetector(t, "min_confidence = \"low\"\n[rules]\nhigh_recall = true\n")
	fs := d.ScanContent("f.txt", "氏名: 山田太郎")
	assertRules(t, fs, "person-name")
}

func TestCrossLineNameSuppressedByTrailingContent(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	// 値行は「氏名だけ」をアンカー付きで要求するため、行末コメント（ignore マーカー
	// 含む）が付くと検出しない。利用者はこれで個別の偽陽性を抑制できる。
	assertRules(t, d.ScanContent("f.txt", "氏名:\n山田太郎 // "+IgnoreMarker))
	assertRules(t, d.ScanContent("f.txt", "氏名:\n山田太郎（備考）"))
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
		{"番直後の号", "住所: 大阪府大阪市北区梅田10番7号", "大阪府大阪市北区梅田10番7号"},
		{"丁目のみ", "住所: 東京都渋谷区道玄坂2丁目", "東京都渋谷区道玄坂2丁目"},
		// 号は終端。号の後ろの部屋番号・電話番号、丁目の後ろの「階」の数字など、
		// 単位もダッシュも伴わない裸の数字列は吸収しない。
		{"号の後の部屋番号は含めない", "住所: 東京都渋谷区道玄坂2丁目10番7号101", "東京都渋谷区道玄坂2丁目10番7号"},
		{"号の後の電話番号は含めない", "住所: 大阪府大阪市北区梅田1丁目2番3号09012345678", "大阪府大阪市北区梅田1丁目2番3号"},
		{"丁目の後の階数は含めない", "住所: 東京都渋谷区道玄坂2丁目10階", "東京都渋谷区道玄坂2丁目"},
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

// jp-birthdate の表記ゆれ（元号アルファベット略記・元年・区切りなし8桁・
// 英語ラベル・ラベル直後の注記）が検出されることを確認する（issue #45）。
func TestBirthdateNotationVariants(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
	}{
		{"元号の単字略記（ドット区切り）", "生年月日: S60.1.2"},
		{"元号の単字略記（スラッシュ区切り）", "誕生日: H5/4/1"},
		{"元年（漢字元号）", "生年月日: 令和元年5月1日"},
		{"元年（単字略記）", "生年月日: R元.5.1"},
		{"区切りなし8桁（YYYYMMDD）", "生年月日: 19850102"},
		{"区切りなし8桁（コロンなし直結）", "生年月日19850102"},
		{"英語ラベル birthday", "birthday: 1985-01-02"},
		{"英語ラベル birth date（スペース区切り）", "birth date: 1985-01-02"},
		{"英語ラベル date_of_birth", "date_of_birth: 1985-01-02"},
		{"英語ラベル DOB（大文字）", "DOB: 1985-01-02"},
		{"ラベル直後に注記が挟まる（西暦）", "生年月日(西暦): 1985-01-02"},
		{"ラベル直後に注記が挟まる（8桁形式）", "生年月日（西暦）: 19850102"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), "jp-birthdate")
		})
	}
}

// jp-birthdate は表記ゆれを拡充しても、以下は誤って拾わないことを確認する:
//   - ラベルの前方境界チェックで除外されるべき、英語ラベルが別の単語の一部
//     になっているケース（adobe: など）
//   - ラベルなしの裸 8 桁（処理日・有効期限などと同形のため、ラベル直結を
//     必須とする設計を維持）
//   - 月日のレンジ外の区切りなし8桁（生年月日: 20259999 等）
func TestBirthdateVariantsNegative(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
	}{
		{"dob が adobe の一部", "adobe: 1985-01-02"},
		{"dob が wardrobe_id の一部", "wardrobe_id: 19850102"},
		{"ラベルなしの裸8桁", "19850102"},
		{"無関係なラベルの8桁（有効期限）", "有効期限: 20250101"},
		{"区切りなし8桁で月がレンジ外", "生年月日: 20259999"},
		{"区切りなし8桁で日がレンジ外", "生年月日: 19850132"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line))
		})
	}
}

// jp-birthdate ラベル直結の8桁と jp-health-insurance の文脈依存8桁
// （保険者番号などのラベルが 40 ルーン以内にある）が同一行・同一箇所で
// 重なった場合の帰属を固定する。両ルールとも Base: Medium かつ検出値が
// 同じ長さのため resolveOverlaps は「先勝ち」で決着する。ラベル直結という
// より強いシグナルを持つ jp-birthdate 側を優先させるため、internal/rule
// の Builtin() では jp-birthdate を jp-health-insurance より前に登録している。
// 少なくとも検出漏れにならないことも合わせて確認する。
func TestBirthdateWinsOverHealthInsuranceOverlap(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanLine("f.txt", 1, "保険者番号 生年月日: 19850102")
	assertRules(t, fs, "jp-birthdate")
}

// --- ComputeOffsets（scan --stdin 用の文字オフセット付与）---

// TestComputeOffsets は行・列ベースの検出位置を、テキスト全体先頭からの
// ルーン単位の半開区間 [Offset, EndOffset) へ正しく変換することを確認する。
// マルチバイト文字・複数行・CRLF・先頭一致を網羅する。
func TestComputeOffsets(t *testing.T) {
	tests := []struct {
		name    string
		content string
		f       Finding
		want    string // content のルーン列を [Offset:EndOffset) で切り出した結果
	}{
		{
			name:    "マルチバイト＋複数行",
			content: "あいう\nname: 山田太郎!\n",
			f:       Finding{Line: 2, Column: 7, Match: "山田太郎"},
			want:    "山田太郎",
		},
		{
			name:    "先頭一致（offset 0）",
			content: "taro@kaisha.co.jp\n",
			f:       Finding{Line: 1, Column: 1, Match: "taro@kaisha.co.jp"},
			want:    "taro@kaisha.co.jp",
		},
		{
			name:    "CRLF 改行",
			content: "ヘッダ\r\nmail: a@kaisha.co\r\n",
			f:       Finding{Line: 2, Column: 7, Match: "a@kaisha.co"},
			want:    "a@kaisha.co",
		},
		{
			// 非BMP（サロゲートペア）。Go の rune と Python のコードポイントは
			// どちらも 1 文字＝1 とする。UTF-16 単位で数える回帰を弾く。
			// 𠮷(U+20BB7) と 😀(U+1F600) を前置し、Column はルーン基準。
			name:    "非BMP文字を含む行",
			content: "前置 𠮷😀\nname: a@kaisha.co\n",
			f:       Finding{Line: 1, Column: 4, Match: "𠮷😀"},
			want:    "𠮷😀",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeOffsets(tt.content, []Finding{tt.f})[0]
			if !got.HasOffset {
				t.Fatal("HasOffset = false, want true")
			}
			runes := []rune(tt.content)
			if got.Offset < 0 || got.EndOffset > len(runes) || got.Offset > got.EndOffset {
				t.Fatalf("offset 範囲外: [%d, %d) len=%d", got.Offset, got.EndOffset, len(runes))
			}
			if s := string(runes[got.Offset:got.EndOffset]); s != tt.want {
				t.Errorf("content[%d:%d] = %q, want %q", got.Offset, got.EndOffset, s, tt.want)
			}
		})
	}
}

// TestComputeOffsetsOutOfRange は範囲外の行・Column<1 では panic せず、HasOffset を
// 付けず、Offset/EndOffset も 0 のまま（ゴミ値が漏れない）ことを確認する。
func TestComputeOffsetsOutOfRange(t *testing.T) {
	cases := []struct {
		name string
		f    Finding
	}{
		{"行が範囲外", Finding{Line: 99, Column: 1, Match: "x"}},
		{"Column<1", Finding{Line: 1, Column: 0, Match: "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeOffsets("一行のみ\n", []Finding{tc.f})[0]
			if got.HasOffset {
				t.Errorf("無効な位置に HasOffset が付いた: %+v", got)
			}
			if got.Offset != 0 || got.EndOffset != 0 {
				t.Errorf("無効な位置で Offset/EndOffset が 0 でない: %d/%d", got.Offset, got.EndOffset)
			}
		})
	}
}

// --- パスをまたぐ finding の重複解決（issue #64）---
//
// resolveOverlaps は単行走査 1 回分の候補にしか適用されておらず、単行パス・
// 隣接行ペアパス・クロスライン氏名パスが独立に出す候補は findingKey
// （RuleID+行+範囲の完全一致）でしか dedup されなかった。異なるルールが同じ
// 値・重なる範囲に別々のパスからマッチすると、矛盾する複数 finding が
// 二重報告される。以下は resolveOverlapsPerLine 追加の回帰テスト。

// 12345678901 から検査用数字を計算した既知のマイナンバー値（internal/checksum の
// TestMyNumberKnownValue と同じ値）。運転免許証番号の Validate
// （先頭 2 桁が公安委員会コードで 0 以外・全桁同一でない）も満たすため、
// 「免許番号:」ラベルの次行に置くと jp-my-number（単行パス、Medium）と
// jp-drivers-license（隣接行ペアパス、High）の双方の候補になる。
const knownMyNumberDriversLicenseCollision = "123456789018"

// TestScanContentCrossPassDedupDriversLicenseVsMyNumber は本 issue で確認された
// 再現ケース: 前行「免許番号:」＋次行に MyNumber の検査用数字も満たす 12 桁。
// 単行パスが吐く jp-my-number（Medium）と隣接行ペアパスが吐く
// jp-drivers-license（High, RequireContext 充足）が同じ範囲に重なるが、
// ScanContent の結果は confidence の高い jp-drivers-license のみを含み、
// jp-my-number を含まないこと。
func TestScanContentCrossPassDedupDriversLicenseVsMyNumber(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", "免許番号:\n"+knownMyNumberDriversLicenseCollision)
	assertRules(t, fs, "jp-drivers-license")
	if fs[0].Confidence != rule.High {
		t.Fatalf("confidence = %v, want high", fs[0].Confidence)
	}
	if fs[0].Line != 2 || fs[0].Column != 1 {
		t.Fatalf("location = %d:%d, want 2:1", fs[0].Line, fs[0].Column)
	}
	if fs[0].Match != knownMyNumberDriversLicenseCollision {
		t.Fatalf("match = %q, want %q", fs[0].Match, knownMyNumberDriversLicenseCollision)
	}
}

// TestScanDiffHunkCrossPassDedupDriversLicenseVsMyNumber は同じ衝突ケースを
// ScanDiffHunk（単行パス＋隣接行ペアパスの 2 系統）でも確認する。
func TestScanDiffHunkCrossPassDedupDriversLicenseVsMyNumber(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanDiffHunk("f.txt", []DiffLine{
		{Text: "免許番号:", Added: false},
		{Text: knownMyNumberDriversLicenseCollision, Added: true},
	})
	assertRules(t, fs, "jp-drivers-license")
	if fs[0].Confidence != rule.High {
		t.Fatalf("confidence = %v, want high", fs[0].Confidence)
	}
}

// TestScanContentCrossPassDedupKeepsUnrelatedFindingsOnDifferentLines は
// resolveOverlapsPerLine が File+Line でグループ化せずグローバルに
// resolveOverlaps を適用してしまう回帰を防ぐ。Finding.start/end は行内
// オフセットのため、たまたま同じ列位置・同じ長さの無関係な finding が
// 別々の行にあると、行を無視した重複解決では誤って片方だけに間引かれて
// しまう。ここでは 2 行それぞれの電話番号が同じ列・同じ長さで検出される
// ケースを使い、両方とも残ることを確認する。
func TestScanContentCrossPassDedupKeepsUnrelatedFindingsOnDifferentLines(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", "TEL: 090-1234-5678\nTEL: 080-9876-5432")
	assertRules(t, fs, "jp-phone-number", "jp-phone-number")
	if fs[0].Line != 1 || fs[0].Column != 6 || fs[0].Match != "090-1234-5678" {
		t.Fatalf("finding[0] = %+v, want line 1 col 6 090-1234-5678", fs[0])
	}
	if fs[1].Line != 2 || fs[1].Column != 6 || fs[1].Match != "080-9876-5432" {
		t.Fatalf("finding[1] = %+v, want line 2 col 6 080-9876-5432", fs[1])
	}
}

// TestScanContentCrossPassDedupKeepsSinglePassFinding は、1 つのパスからしか
// 出ない finding（他パスと重ならない）が resolveOverlapsPerLine の追加後も
// 素通りで残ることを確認する（単行パスのみ・隣接行ペアパスのみ・
// クロスライン氏名パスのみのケースを 1 つずつ）。
func TestScanContentCrossPassDedupKeepsSinglePassFinding(t *testing.T) {
	t.Run("単行パスのみ", func(t *testing.T) {
		d := newDetector(t, "")
		fs := d.ScanContent("f.txt", "TEL: 090-1234-5678")
		assertRules(t, fs, "jp-phone-number")
	})
	t.Run("隣接行ペアパスのみ", func(t *testing.T) {
		d := newDetector(t, "")
		fs := d.ScanContent("f.txt", "口座番号:\n1234567")
		assertRules(t, fs, "jp-bank-account")
	})
	t.Run("クロスライン氏名パスのみ", func(t *testing.T) {
		d := newDetector(t, highRecallTOML)
		fs := d.ScanContent("f.txt", "氏名:\n山田太郎")
		assertRules(t, fs, "person-name-structured")
	})
}

// --- [[rules.custom]]（.jp-pii.toml の利用者定義ルール）---

// TestCustomRuleDetectsMatch は digit_boundary 付きカスタムルールが
// builtin ルールと同様に検出し、より長い数字列の一部は対象外になることを確認する。
func TestCustomRuleDetectsMatch(t *testing.T) {
	d := newDetector(t, `
[[rules.custom]]
id = "student-id"
description = "学籍番号"
pattern = 'S\d{8}'
digit_boundary = true
base_confidence = "high"
`)
	findings := d.ScanLine("f.go", 1, "学籍番号: S12345678")
	assertRules(t, findings, "student-id")
	if findings[0].Confidence != rule.High {
		t.Errorf("Confidence = %v, want High", findings[0].Confidence)
	}
	if findings[0].Match != "S12345678" {
		t.Errorf("Match = %q, want S12345678", findings[0].Match)
	}
	if findings[0].Description != "学籍番号" {
		t.Errorf("Description = %q, want 学籍番号", findings[0].Description)
	}

	// 8 桁ちょうどではなく、より長い数字列の一部は対象外（digit_boundary の境界ガード）。
	assertRules(t, d.ScanLine("f.go", 1, "S123456789"))
}

// TestCustomRuleWithoutDigitBoundaryUsesWholeMatch は digit_boundary を
// 指定しない場合、パターンにキャプチャグループが無ければマッチ全体を検出値とすることを確認する。
func TestCustomRuleWithoutDigitBoundaryUsesWholeMatch(t *testing.T) {
	d := newDetector(t, `
[[rules.custom]]
id = "custom-token"
description = "カスタムトークン"
pattern = 'TOKEN-[A-Z0-9]{8}'
base_confidence = "high"
`)
	findings := d.ScanLine("f.go", 1, "key=TOKEN-AB12CD34;")
	assertRules(t, findings, "custom-token")
	if findings[0].Match != "TOKEN-AB12CD34" {
		t.Errorf("Match = %q, want TOKEN-AB12CD34", findings[0].Match)
	}
}

// TestCustomRuleRequireContext は RequireContext がキーワード無しで検出を破棄し、
// キーワードがあっても（builtin と同じ規約で）Base の信頼度のまま昇格しないことを確認する。
func TestCustomRuleRequireContext(t *testing.T) {
	d := newDetector(t, `
[[rules.custom]]
id = "staff-id"
description = "社員番号"
pattern = 'E\d{6}'
digit_boundary = true
context = ["社員番号"]
require_context = true
base_confidence = "medium"
`)
	assertRules(t, d.ScanLine("f.go", 1, "E123456")) // キーワード無し: 破棄

	withCtx := d.ScanLine("f.go", 1, "社員番号: E123456")
	assertRules(t, withCtx, "staff-id")
	if withCtx[0].Confidence != rule.Medium {
		t.Errorf("Confidence = %v, want Medium（RequireContext は昇格しない）", withCtx[0].Confidence)
	}
}

// TestCustomRuleNegativeContext は近傍の否定文脈語が検出を棄却することを確認する。
func TestCustomRuleNegativeContext(t *testing.T) {
	d := newDetector(t, `
[[rules.custom]]
id = "ticket-id"
description = "チケット番号"
pattern = 'T\d{6}'
digit_boundary = true
negative_context = ["サンプル"]
base_confidence = "medium"
`)
	assertRules(t, d.ScanLine("f.go", 1, "サンプル: T123456")) // 否定文脈: 棄却
	assertRules(t, d.ScanLine("f.go", 1, "チケット番号: T123456"), "ticket-id")
}

// TestCustomRuleDisabledViaConfig は rules.disabled がカスタムルールにも
// builtin ルールと同様に効くことを確認する。
func TestCustomRuleDisabledViaConfig(t *testing.T) {
	d := newDetector(t, `
[rules]
disabled = ["staff-id"]

[[rules.custom]]
id = "staff-id"
description = "社員番号"
pattern = 'E\d{6}'
digit_boundary = true
base_confidence = "high"
`)
	assertRules(t, d.ScanLine("f.go", 1, "E123456"))
}

// TestCustomRuleInvalidRegexIsConfigError はコンパイル不能な正規表現が
// panic ではなく New() のエラーとして返ることを確認する（セキュリティ境界の回帰防止）。
func TestCustomRuleInvalidRegexIsConfigError(t *testing.T) {
	cfg, err := config.Parse(`
[[rules.custom]]
id = "bad"
pattern = "("
`)
	if err == nil {
		t.Fatal("config.Parse should reject an uncompilable custom rule pattern")
	}
	if cfg != nil {
		t.Errorf("cfg = %v, want nil on error", cfg)
	}
}
