package detect

import (
	"strings"
	"testing"
	"unicode/utf8"

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
		{"日付風prefixの検査用数字一致値", "個人番号: 199001230000", []string{"jp-my-number"}, rule.High},
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

// TestMyNumberSeparatorVariants は issue #46 で追加した空白区切り（4-4-4 /
// 6-6）のマイナンバー表記をカバーする。検査用数字は checksum_test.go の
// genMyNumber("12345678901") と同じ既知値（123456789018）を使う。
func TestMyNumberSeparatorVariants(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
		conf       rule.Confidence
	}{
		{"空白区切り4-4-4 コンテキストあり", "マイナンバー: 1234 5678 9018", []string{"jp-my-number"}, rule.High},
		{"空白区切り4-4-4 コンテキストなし", "value = 1234 5678 9018", []string{"jp-my-number"}, rule.Medium},
		{"空白区切り6-6 コンテキストあり", "個人番号: 123456 789018", []string{"jp-my-number"}, rule.High},
		{"空白区切り4-4-4 検査用数字不一致", "value = 1234 5678 9012", nil, 0},
		{"空白区切り4-4-4 の末尾に数字が続く場合は対象外", "マイナンバー: 1234 5678 90189", nil, 0},
		{"4-4-4 でない空白区切りは対象外（5-3-4）", "マイナンバー: 12345 678 9018", nil, 0},
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

func TestNumericSeparatorVariantsRejectLongTokenPrefixes(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
	}{
		{"空白区切りマイナンバーの直後にさらに空白数字が続く", "マイナンバー: 1234 5678 9018 0000"},
		{"空白区切り基礎年金番号の直後にさらに空白数字が続く", "基礎年金番号: 1234 567890 1"},
		{"空白区切りパスポート番号の直後にさらに空白数字が続く", "パスポート番号: AB 1234567 8"},
		{"ドット区切り電話番号の直後にさらにドット数字が続く", "電話番号: 090.1234.5678.9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line))
		})
	}
}

// TestNumericBoundariesAllowAdjacentIndependentValues は、区切り文字 1 個の外側に
// 別の数字があるだけで既存の数値ルールを棄却しないことを確認する。長い同一
// トークンの部分一致は上のテストで個別に防ぎつつ、ログ・CSV・フォームで普通に
// 現れる複数値の隣接を許容する。
func TestNumericBoundariesAllowAdjacentIndependentValues(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"電話番号の後ろに年", "TEL: 03-1234-5678 2024年度", []string{"jp-phone-number"}},
		{"年の後ろに電話番号", "更新日2024 03-1234-5678", []string{"jp-phone-number"}},
		{"電話番号2件", "TEL:03-1234-5678 03-1234-5679", []string{"jp-phone-number", "jp-phone-number"}},
		{"郵便番号と電話番号", "郵便番号: 100-0001 090-1234-5678", []string{"jp-postal-code", "jp-phone-number"}},
		{"口座番号と別数字", "口座番号: 1234567 8888", []string{"jp-bank-account"}},
		{"保険者番号と別数字", "保険者番号: 12345678 9999", []string{"jp-health-insurance"}},
		{"運転免許証番号と別数字", "免許証番号: 305012345678 8888", []string{"jp-drivers-license"}},
		{"基礎年金番号（ハイフン）と別数字", "基礎年金番号: 1234-567890 8888", []string{"jp-pension-number"}},
		{"基礎年金番号（連続）と別数字", "基礎年金番号: 1234567890 8888", []string{"jp-pension-number"}},
		{"パスポート番号と別数字", "パスポート番号: AB1234567 8888", []string{"jp-passport"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
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
	fixedNoSep := strings.ReplaceAll(piifixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"携帯区切りあり", "TEL: " + piifixtures.MustGet(t, "detect.phone_mobile_sep"), []string{"jp-phone-number"}},
		{"携帯区切りなしコンテキストあり", "携帯 " + piifixtures.MustGet(t, "detect.phone_mobile_nosep"), []string{"jp-phone-number"}},
		{"固定電話区切りあり", "本社: " + piifixtures.MustGet(t, "detect.phone_fixed_tokyo"), []string{"jp-phone-number"}},
		{"固定電話区切りあり seed 辞書未収録", "電話: 04992-2-1234", []string{"jp-phone-number"}},
		// P10（#56）: 固定電話・区切りなし 10 桁。市外局番辞書（dict.ValidAreaCode）による
		// validPhone 拡張と新パターンで新たに検出可能になった。RequireContext のため
		// コンテキストキーワードが必須。
		{"固定電話区切りなしコンテキストあり", "電話番号：" + fixedNoSep, []string{"jp-phone-number"}},
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

// P10（#56）: 固定電話・区切りなし 10 桁パターンは RequireContext のため、
// コンテキストキーワードがなければ市外局番として実在するプレフィックスでも
// 検出しない。新規 fixture キーは作らず、既存の区切りあり固定電話から同じ番号の
// 区切りなし表記を組み立てる。
func TestPhoneLandlineNoSepRequiresContext(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	fixedNoSep := strings.ReplaceAll(piifixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")
	assertRules(t, d.ScanLine("f.txt", 1, fixedNoSep))
	assertRules(t, d.ScanLine("f.txt", 1, "電話番号："+fixedNoSep), "jp-phone-number")
}

// P10（#56）: 新規の区切りなし固定電話だけに負文脈を適用し、既存の電話番号
// パターンは近傍に伝票番号等があっても従来どおり検出する。
func TestPhoneNegativeContextOnlyAppliesToLandlineNoSep(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	fixedSep := piifixtures.MustGet(t, "detect.phone_fixed_tokyo")
	fixedNoSep := strings.ReplaceAll(fixedSep, "-", "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"区切りあり携帯", "伝票番号:0001 " + piifixtures.MustGet(t, "detect.phone_mobile_sep"), []string{"jp-phone-number"}},
		{"区切りなし携帯", "伝票番号:0001 " + piifixtures.MustGet(t, "detect.phone_mobile_nosep"), []string{"jp-phone-number"}},
		{"区切りあり固定電話", "伝票番号:0001 " + fixedSep, []string{"jp-phone-number"}},
		{"IP 電話", "伝票番号:0001 " + piifixtures.MustGet(t, "detect.phone_ip"), []string{"jp-phone-number"}},
		{"国際表記", "伝票番号:0001 " + piifixtures.MustGet(t, "detect.phone_intl_mobile"), []string{"jp-phone-number"}},
		{"区切りなし固定電話", "電話番号: " + fixedNoSep + " 伝票番号", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// ScanContent の隣接行負文脈フィルタでも、既存パターンの除外指定が維持される。
func TestPhoneExistingPatternIgnoresAdjacentLineNegativeContext(t *testing.T) {
	piifixtures.Require(t)
	d := newDetector(t, "")
	content := piifixtures.MustGet(t, "detect.phone_mobile_sep") + "\n伝票番号"
	assertRules(t, d.ScanContent("f.txt", content), "jp-phone-number")
}

// P10（#56）: 区切りあり固定電話は area_codes.txt の seed 辞書が未完成でも
// 取りこぼさない。
func TestPhoneSepAllowsAreaCodeMissingFromSeedDictionary(t *testing.T) {
	d := newDetector(t, "")
	assertRules(t, d.ScanLine("f.txt", 1, "電話番号：04992-2-1234"), "jp-phone-number")
}

// TestPhoneNumberSeparatorVariants は issue #46 で追加した区切り表記ゆれ
// （区切りなし固定電話・空白/ドット区切り携帯・括弧市外局番・フリーダイヤル）を
// カバーする。既存 4 パターン（区切りあり携帯・区切りなし携帯・区切りあり固定・
// +81 国際表記）が壊れていないことも回帰として明記する。
func TestPhoneNumberSeparatorVariants(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
		conf       rule.Confidence
	}{
		// ---- 既存パターンの回帰（挙動が変わらないことの確認）----
		{"回帰: 区切りあり携帯", "TEL: 090-1234-5678", []string{"jp-phone-number"}, rule.High},
		{"回帰: 区切りなし携帯コンテキストなし", "09012345678", []string{"jp-phone-number"}, rule.Medium},
		{"回帰: 区切りあり固定電話（末尾4桁）", "TEL: 03-1234-5678", []string{"jp-phone-number"}, rule.High},
		{"回帰: 国際表記 +81", "+81-90-1234-5678", []string{"jp-phone-number"}, rule.High},
		// ---- 新規: 区切りなし固定電話（RequireContext 必須）----
		{"区切りなし固定電話 コンテキストあり", "電話番号: 0312345678", []string{"jp-phone-number"}, rule.Medium},
		{"区切りなし固定電話 コンテキストなし", "id: 0312345678", nil, 0},
		{"区切りなし固定電話 直後に数字が続く場合は対象外（11桁の先頭10桁部分ではない）", "電話番号: 03123456789", nil, 0},
		{"区切りなし固定電話 直前に数字が続く場合は対象外（11桁の末尾10桁部分ではない）", "電話番号: 10312345678", nil, 0},
		// ---- 新規: 空白・ドット区切り携帯 ----
		{"空白区切り携帯 コンテキストあり", "携帯 090 1234 5678", []string{"jp-phone-number"}, rule.High},
		{"ドット区切り携帯 コンテキストなし", "090.1234.5678", []string{"jp-phone-number"}, rule.Medium},
		{"携帯プレフィックスでない空白区切りは対象外", "030 1234 5678", nil, 0},
		// ---- 新規: 括弧市外局番 ----
		{"括弧書き市内局番", "電話: 03(1234)5678", []string{"jp-phone-number"}, rule.High},
		{"括弧書き市外局番全体", "電話: (03) 1234-5678", []string{"jp-phone-number"}, rule.High},
		// ---- 新規: フリーダイヤル等の末尾3桁 ----
		{"フリーダイヤル（末尾3桁）", "TEL: 0120-234-567", []string{"jp-phone-number"}, rule.High},
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

// TestDriversLicenseHyphenVariant は issue #46 で追加したハイフン区切り
// （4-4-4）の運転免許証番号をカバーする。プレースホルダ（全桁同一・先頭0）が
// 新パターンでも棄却されること、ハイフン区切りトークンの内部を切り出さない
// ことを回帰として明記する。
func TestDriversLicenseHyphenVariant(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
		conf       rule.Confidence
	}{
		{"ハイフン区切り コンテキストあり", "免許証番号: 3050-1234-5678", []string{"jp-drivers-license"}, rule.High},
		{"ハイフン区切り コンテキストなし", "id: 3050-1234-5678", nil, 0},
		{"回帰: 連続12桁は変わらない", "免許証番号: 305012345678", []string{"jp-drivers-license"}, rule.High},
		{"プレースホルダ（全桁同一）はハイフン区切りでも棄却", "免許証番号: 0000-0000-0000", nil, 0},
		{"プレースホルダ（全桁同一・非ゼロ）はハイフン区切りでも棄却", "免許証番号: 1111-1111-1111", nil, 0},
		{"先頭が0の場合はハイフン区切りでも棄却", "免許証番号: 0501-2345-6789", nil, 0},
		{"ハイフン区切りトークンの内部は対象外", "免許証番号: token-3050-1234-5678-suffix", nil, 0},
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

// TestPassportSpaceVariant は issue #46 で追加した英字・数字間の半角スペース
// 任意表記（AB 1234567）をカバーする。
func TestPassportSpaceVariant(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"空白区切り コンテキストあり", "パスポート番号: AB 1234567", []string{"jp-passport"}},
		{"回帰: 区切りなしは変わらない", "パスポート番号: AB1234567", []string{"jp-passport"}},
		{"空白区切り コンテキストなし", "AB 1234567", nil},
		{"英字トークンの内部は対象外", "パスポート番号: XAB 1234567", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// TestPensionNumberSpaceVariant は issue #46 で追加した半角スペース区切り
// （4-6）の基礎年金番号をカバーする。ハイフン区切り・区切りなしの既存挙動が
// 変わらないことも回帰として明記する。
func TestPensionNumberSpaceVariant(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"空白区切り", "基礎年金番号: 1234 567890", []string{"jp-pension-number"}},
		{"回帰: ハイフン区切りは変わらない", "基礎年金番号: 1234-567890", []string{"jp-pension-number"}},
		{"回帰: 区切りなしは変わらない", "基礎年金番号: 1234567890", []string{"jp-pension-number"}},
		{"コンテキストなし", "1234 567890", nil},
		{"より長い数字列の一部は対象外", "基礎年金番号: 12345678901", nil},
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

// mynumValid / mynumValid2 は検査用数字の合致するダミーのマイナンバー
// （piifixtures 無しでも実行できるよう、チェックディジットを手計算した値）。
// visaTestCard は Stripe 等が公開する Luhn 有効な Visa テスト番号。
// shibuyaPostal は実在する郵便番号（渋谷区道玄坂、internal/dict のテストと同じ値）。
const (
	mynumValid    = "123456789018"
	mynumValid2   = "100000000013"
	visaTestCard  = "4242424242424242"
	visaSepCard   = "4111-1111-1111-1111"
	shibuyaPostal = "150-0043"
)

// P05: jp-my-number / credit-card / jp-postal-code / jp-passport /
// jp-residence-card は、これまで NegativeContext が未設定で、値に隣接する
// 通貨・カウンタ単位（「売上は 4242... 円」等）でも抑制されなかった
// （issue #53 (a)）。単位隣接専用の語彙を適用し、値に直接隣接する場合のみ
// 抑制することを確認する。
func TestUnitAdjacentNegativeContextSuppressesFiveRules(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
	}{
		{"マイナンバーに直後の円", "マイナンバー: " + mynumValid + "円"},
		{"売上表記のカード番号（issue 実測例）", "売上は " + visaTestCard + " 円"},
		{"郵便番号に直後のカウンタ", "〒" + shibuyaPostal + "件"},
		{"パスポート番号に直後のカウンタ", "パスポート番号: TZ1234567件"},
		{"在留カード番号に直後のカウンタ", "在留カード番号: AB12345678CD件"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line))
		})
	}
}

// 単位隣接専用の語彙は、既存 4 ルールの汎用窓語（注文・伝票・管理番号 等）を
// 含まない。値と関係のない離れた位置に汎用語があるだけでは抑制せず、
// 「カード番号 … で注文」「マイナンバー … を伝票に転記」のような正当な
// 検出を取りこぼさないことを確認する（issue #53 (1) の FN 回避）。
func TestUnitAdjacentNegativeContextIgnoresDistantGenericWords(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"マイナンバーを伝票に転記", "マイナンバー: " + mynumValid + " を伝票に転記", []string{"jp-my-number"}},
		{"カード番号で注文", "カード番号: " + visaSepCard + " で注文", []string{"credit-card"}},
		{"郵便番号を伝票に転記", "郵便番号: " + shibuyaPostal + " を伝票に転記", []string{"jp-postal-code"}},
		{"パスポート番号を伝票に転記", "パスポート番号: TZ1234567 を伝票に転記", []string{"jp-passport"}},
		{"在留カード番号を伝票に転記", "在留カード番号: AB12345678CD を伝票に転記", []string{"jp-residence-card"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// 採番ラベル接頭クラス（伝票番号・受付番号・予約番号 等）は、値に直接
// 隣接する場合のみ抑制する（issue #53 (4)）。
func TestNumberingLabelPrefixSuppressesAdjacentValue(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
	}{
		{"伝票番号（issue 実測例）", "伝票番号 " + mynumValid2},
		{"受付番号直後のカード番号", "受付番号 " + visaSepCard},
		{"予約番号直後の郵便番号（肯定文脈も同一行に存在）", "郵便番号: 予約番号" + shibuyaPostal},
		{"シリアル番号直後の在留カード番号（肯定文脈も同一行に存在）", "在留カード番号: シリアル番号AB12345678CD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line))
		})
	}
}

// 採番ラベルが値から離れている場合は抑制しない（正ラベル + 離れた採番語）。
// hasUnitBefore は空白・タブ以外を挟むと不成立になるため、「伝票番号」の
// 語自体が行内にあっても値の直前でなければ通常どおり検出する。
func TestNumberingLabelPrefixIgnoresDistantLabel(t *testing.T) {
	d := newDetector(t, "")
	line := "マイナンバー: " + mynumValid + " を伝票番号に転記"
	assertRules(t, d.ScanLine("f.txt", 1, line), "jp-my-number")
}

// hasUnitAfter の requireBoundary（issue #53 (2)）: 修正前は単位直後が
// ひらがな（助詞）でも「日本語文字」とみなして境界不成立にしていたため、
// 「1234567件に到達した」のような助詞続きでカウンタ抑制が効かなかった
// （「1234567件。」は句点なので元々抑制されており非一貫性だった）。
// 直後が漢字（件名・名義等の複合語）の場合のみ境界不成立として抑制しない。
func TestHasUnitAfterKanjiBoundary(t *testing.T) {
	unit := []rune("件")
	tests := []struct {
		name string
		line string
		want bool
	}{
		{"助詞（ひらがな）続きは境界成立で抑制する", "1234567件に到達した", true},
		{"漢字複合語（件名）は境界不成立で抑制しない", "1234567件名は空欄", false},
		{"句点続きは境界成立で抑制する", "1234567件。", true},
		{"行末は境界成立で抑制する", "1234567件", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := []rune(tt.line)
			if got := hasUnitAfter(rs, 7, negativeContextWindowRunes, unit, true); got != tt.want {
				t.Errorf("hasUnitAfter(%q, ...) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}

// hasUnitAfter の境界修正を実際の検出パイプラインで確認する
// （直接の関数テストに加え、rule.Rule.NegativeContext 経由の統合確認）。
func TestCounterSuffixBoundaryFixIntegration(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"助詞続きのカウンタは抑制する（境界バグ修正）", "口座番号: 1234567件に到達した", nil},
		{"漢字複合語（件名）は引き続き抑制しない", "口座番号: 1234567件名は空欄", []string{"jp-bank-account"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// ScanDiffHunk はこれまで cross-line 負コンテキストを一切適用しておらず、
// 追加行同士（両方 Added）でも抑制されなかった。フルスキャン（ScanContent）
// では同じ内容が抑制されるため、pre-commit --staged とフルスキャンで結果が
// 非対称になっていた（issue #53 (5)）。追加行同士は抑制し、文脈行
// （未変更行）由来の抑制は引き続き適用しないことを確認する。
func TestScanDiffHunkNegativeContextBetweenAddedLines(t *testing.T) {
	d := newDetector(t, "")

	// 追加行同士が隣接する場合は、フルスキャンと同じく負コンテキストで抑制する。
	fs := d.ScanDiffHunk("f.txt", []DiffLine{
		{Text: "口座番号: 1234567", Added: true},
		{Text: "円", Added: true},
	})
	assertRules(t, fs)

	// 負コンテキストが文脈行（未変更行）にある場合は抑制しない
	// （追加した値の隣の既存行に「円」があっても、新規 PII を取りこぼさない設計）。
	fs = d.ScanDiffHunk("f.txt", []DiffLine{
		{Text: "口座番号: 1234567", Added: true},
		{Text: "円", Added: false},
	})
	assertRules(t, fs, "jp-bank-account")
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

// TestPersonNameWeakFieldTrailingParticleFallback は issue #59 段階0: 弱いラベル
// （姓・名・name 系）の値の直後に助詞・敬称が続き、通常の personNameValueShort が
// 貪欲に取り込んで辞書照合に失敗する見逃し（FN）を、末尾の助詞・敬称を 1 回だけ
// 剥がすフォールバックで拾うことを確認する。検出スパンは切り詰めた先頭セグメント。
// 値は埋め込み姓名辞書のリテラルを使い、外部フィクスチャ不要（オフライン実行可能）。
func TestPersonNameWeakFieldTrailingParticleFallback(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	tests := []struct {
		name, line, wantMatch string
	}{
		{"姓 + 助詞混入の地続き文", "姓: 山田さんへ連絡", "山田"},
		{"名 + です", "名: 花子です", "花子"},
		{"last_name + 敬称", "last_name: 山田様がいらっしゃいました", "山田"},
		{"user_name + 助詞", "user_name: 山田さんへ連絡", "山田"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanLine("f.txt", 1, tt.line)
			assertRules(t, fs, "person-name")
			if fs[0].Match != tt.wantMatch {
				t.Errorf("match = %q, want %q", fs[0].Match, tt.wantMatch)
			}
		})
	}
}

// TestPersonNameWeakFieldTrailingParticleFallbackUnaffected は上記フォールバックが
// 通常の完全一致（値の直後に助詞が続かない）を壊さないこと、および辞書に
// 一致しない一般名詞では引き続き検出しないことを確認する。
func TestPersonNameWeakFieldTrailingParticleFallbackUnaffected(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	tests := []struct {
		name, line string
		want       []string
	}{
		// 助詞が続かない通常の完全一致は、切り詰めずフルの値のまま検出する。
		{"姓 + 名（地続き文なし）", "姓: 山田太郎", []string{"person-name"}},
		// 1 文字の単独要素は助詞混入時でも棄却する（validGivenField の長さ制約）。
		{"first_name + 1文字 + 助詞", "first_name: 実さんへ連絡", nil},
		// 辞書に一致しない一般名詞は、助詞が続いても検出しない。
		{"名 + 一般名詞 + 助詞", "名: 一覧です", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// TestPersonNameChargeLabelConfidenceSplit は issue #59 段階1: 担当ラベル
// （person-name-high-recall）が判定根拠（dict.MatchPersonName）に応じて
// 信頼度を作り分けることを確認する。姓+名の分割（FullNameSplit）は Medium の
// まま、単独の姓一致（SurnameOnly、渋谷・大和・本田のような地名・企業名と
// 同形の姓を含む）は Low に降格し、Medium への一律昇格を避ける。
func TestPersonNameChargeLabelConfidenceSplit(t *testing.T) {
	d := newDetector(t, `
min_confidence = "low"
[rules]
high_recall = true
`)
	tests := []struct {
		name, line     string
		wantConfidence rule.Confidence
	}{
		{"担当 + 姓名分割", "担当: 山田太郎", rule.Medium},
		{"担当 + 地名同形の単独姓（渋谷）", "担当: 渋谷", rule.Low},
		{"担当 + 地名同形の単独姓（大和）", "担当: 大和", rule.Low},
		{"担当 + 企業名同形の単独姓（本田）", "担当: 本田", rule.Low},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanLine("f.txt", 1, tt.line)
			assertRules(t, fs, "person-name-high-recall")
			if fs[0].Confidence != tt.wantConfidence {
				t.Errorf("confidence = %v, want %v", fs[0].Confidence, tt.wantConfidence)
			}
		})
	}
}

// TestPersonNameChargeLabelRejectsCompoundHomographs は issue #59 段階1: 関心
// （関+心）・東大（東+大）・山田錦（山田+錦、denylist）のような、姓名分割は
// 辞書上成立してしまうが実際には人名ではない一般名詞・固有名詞を、担当ラベルが
// 検出しないことを確認する。
func TestPersonNameChargeLabelRejectsCompoundHomographs(t *testing.T) {
	d := newDetector(t, `
min_confidence = "low"
[rules]
high_recall = true
`)
	for _, line := range []string{
		"担当: 関心",
		"担当: 東大",
		"担当: 山田錦",
	} {
		t.Run(line, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, line))
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

// マーカー付き番地（丁目/番/号）パターンには Validate が無い。マーカーなし
// ダッシュ連結パターンには日付誤検出対策の Validate（notCalendarDateBanchi）が
// あるため、区別できるよう固定のマーカー付き住所を使う（#55 でパターンが
// 2 つに分かれたため、実在するフィクスチャの表記に依存しないようにした）。
func TestReasonNotValidatedWhenNoValidator(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanLine("f.txt", 1, "住所: 東京都渋谷区道玄坂2丁目10番7号")
	assertRules(t, fs, "jp-address")
	if fs[0].Reason.Validated {
		t.Fatalf("validated = true, want false (jp-address marker pattern has no validator)")
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

// High 昇格判定（RequireContext ではない Base<High パターン）は #54 以前は
// 行全体を無制限に探索していたため、minified JSON や長い 1 行ではラベルが
// 1 つあるだけで行内の全マッチが昇格してしまっていた（P12 #54 (a)）。
// 昇格は defaultPromotionContextWindow（既定 40 ルーン）の窓に限定される。
// 昇格対象は Base<High かつ RequireContext ではないパターンを持ち、かつ
// Context を設定している 3 ルール（jp-my-number・jp-phone-number・
// jp-address-high-recall）に限られる（他のルールは RequireContext か、
// Context 未設定のため昇格判定自体が働かない。#54 issue 記載の確認済み事項）。
func TestPromotionContextWindowBoundary(t *testing.T) {
	tests := []struct {
		name       string
		toml       string
		label      string
		value      string
		wantRuleID string
	}{
		{name: "jp-my-number", label: "個人番号", value: "123456789018", wantRuleID: "jp-my-number"},
		{name: "jp-phone-number", label: "電話", value: "09012345678", wantRuleID: "jp-phone-number"},
		{
			name: "jp-address-high-recall",
			toml: "[rules]\nhigh_recall = true\n",
			// 都道府県を含まない住所（jp-address ではなく high-recall 版のみが
			// マッチする。jp-address の方は常に Base: High で昇格判定を経由しない）。
			label:      "住所",
			value:      "渋谷区道玄坂1-2-3",
			wantRuleID: "jp-address-high-recall",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newDetector(t, tt.toml)
			labelRunes := utf8.RuneCountInString(tt.label)
			// inN: ラベル終端がちょうど窓の起点に来る境界（内側）。
			// outN: そのすぐ外側（1 ルーンだけ超える）。
			inN := defaultPromotionContextWindow - labelRunes
			outN := inN + 1
			mk := func(n int) string {
				return tt.label + strings.Repeat(" ", n) + tt.value
			}

			inFs := d.ScanLine("f.txt", 1, mk(inN))
			assertRules(t, inFs, tt.wantRuleID)
			if inFs[0].Confidence != rule.High || !inFs[0].Reason.ContextPromoted {
				t.Fatalf("filler=%d(窓内): confidence=%v promoted=%v, want high/promoted",
					inN, inFs[0].Confidence, inFs[0].Reason.ContextPromoted)
			}

			outFs := d.ScanLine("f.txt", 1, mk(outN))
			assertRules(t, outFs, tt.wantRuleID)
			if outFs[0].Confidence == rule.High || outFs[0].Reason.ContextPromoted {
				t.Fatalf("filler=%d(窓外): confidence=%v promoted=%v, want base confidence / not promoted",
					outN, outFs[0].Confidence, outFs[0].Reason.ContextPromoted)
			}
		})
	}
}

// jp-postal-code は #54 以前 RequireContextWindow 未設定（行全体探索）だったため、
// 「品番 150-0002 は廃番。郵便での返送は不可。」のように離れた場所の「郵便」の
// 部分一致だけで Medium 成立していた（P12 #54 (b)）。他の digit 系 RequireContext
// ルール（jp-bank-account 等）と同じ 40 ルーン窓を追加したことを確認する。
func TestPostalCodeRequireContextWindowBoundary(t *testing.T) {
	d := newDetector(t, "")
	postal := "150-0043" // 渋谷区道玄坂（実在の郵便番号）

	tests := []struct {
		name      string
		label     string
		wantFound bool
	}{
		{"近傍の郵便番号は検出する", "郵便番号", true},
		{"近傍の郵便だけでも検出する", "郵便", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labelRunes := utf8.RuneCountInString(tt.label)
			inN := digitRuleRequireContextWindowForTest - labelRunes
			line := tt.label + strings.Repeat(" ", inN) + postal
			fs := d.ScanLine("f.txt", 1, line)
			if tt.wantFound {
				assertRules(t, fs, "jp-postal-code")
			} else {
				assertRules(t, fs)
			}
		})
	}

	// 離れた場所（窓の外）の「郵便番号」「郵便」はどちらも検出しない
	// （#54 で報告された実例の一般形）。
	far := []struct {
		name  string
		label string
	}{
		{"離れた場所の郵便番号は検出しない", "郵便番号"},
		{"離れた場所の郵便だけでは検出しない", "郵便"},
	}
	for _, tt := range far {
		t.Run(tt.name, func(t *testing.T) {
			labelRunes := utf8.RuneCountInString(tt.label)
			outN := digitRuleRequireContextWindowForTest - labelRunes + 1
			line := tt.label + strings.Repeat(" ", outN) + postal
			assertRules(t, d.ScanLine("f.txt", 1, line))
		})
	}
}

// digitRuleRequireContextWindowForTest は jp-postal-code の RequireContextWindow
// （internal/rule 側の非公開定数 digitRuleRequireContextWindow）と同じ値。
// パッケージが異なり参照できないため、テスト側で値を複製する
// （internal/rule.digitRuleRequireContextWindow と乖離しないよう
// TestReasonRecordsRequiredNearbyContext が 40 を別途アサートしている）。
const digitRuleRequireContextWindowForTest = 40

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

// TestScanContentAdjacentLinesSkipBlankLines は issue #62 の「論理隣接」化を
// 検証する: ラベルと値の間に空行が 1〜2 行挟まっても相関が成立すること
// （j-i<=3。空行なしの物理隣接は既存テストで確認済み）。
func TestScanContentAdjacentLinesSkipBlankLines(t *testing.T) {
	d := newDetector(t, "")
	bankAccount := "1234567"

	// 空行 1 行（j-i=2）。
	fs := d.ScanContent("f.txt", "口座番号:\n\n"+bankAccount)
	assertRules(t, fs, "jp-bank-account")
	if fs[0].Line != 3 || fs[0].Column != 1 {
		t.Fatalf("location = %d:%d, want 3:1", fs[0].Line, fs[0].Column)
	}
	if fs[0].Match != bankAccount {
		t.Fatalf("match = %q, want %q", fs[0].Match, bankAccount)
	}

	// 空行 2 行（j-i=3、許容される上限）。
	fs = d.ScanContent("f.txt", "口座番号:\n\n\n"+bankAccount)
	assertRules(t, fs, "jp-bank-account")
	if fs[0].Line != 4 {
		t.Fatalf("line = %d, want 4", fs[0].Line)
	}
}

// TestScanContentAdjacentLinesTooFarNotDetected は j-i>3（空行 3 行以上）では
// 相関しないことを確認する負例。
func TestScanContentAdjacentLinesTooFarNotDetected(t *testing.T) {
	d := newDetector(t, "")
	bankAccount := "1234567"
	assertRules(t, d.ScanContent("f.txt", "口座番号:\n\n\n\n"+bankAccount))
}

// TestScanContentAdjacentLabelPromotesNonRequireContextRuleWithinWindow は、
// RequireContext ではないルール（電話番号）も隣接行のラベルで High に昇格する
// ことを確認する。従来は scanAdjacentLines が RequireContext finding 以外を
// 一律に捨てていたため、min_confidence=high 運用ではこのケースを原理的に
// 見逃していた（issue #62 の問題(2)）。空行を 1 行挟んでも成立することも兼ねて
// 確認する。
func TestScanContentAdjacentLabelPromotesNonRequireContextRuleWithinWindow(t *testing.T) {
	d := newDetector(t, `min_confidence = "high"`)
	phone := "090" + "1234" + "5678"

	fs := d.ScanContent("f.txt", "電話番号:\n\n"+phone)
	assertRules(t, fs, "jp-phone-number")
	if fs[0].Confidence != rule.High {
		t.Fatalf("confidence = %v, want high", fs[0].Confidence)
	}
	if !fs[0].Reason.ContextPromoted {
		t.Fatalf("reason.ContextPromoted = false, want true")
	}
}

// TestScanContentAdjacentBirthdateWithEmbeddedLabel は、ラベルを正規表現自体に
// 埋め込む非 RequireContext ルールも隣接行をまたいで検出できることを確認する。
// person-name の重複抑制用越境ガードを全ルールに適用すると、この正当なマッチまで
// 巻き添えで失われる。
func TestScanContentAdjacentBirthdateWithEmbeddedLabel(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", "生年月日:\n1990/01/01")
	assertRules(t, fs, "jp-birthdate")
	if fs[0].Line != 2 || fs[0].Column != 1 {
		t.Fatalf("location = %d:%d, want 2:1", fs[0].Line, fs[0].Column)
	}
	if fs[0].Match != "1990/01/01" {
		t.Fatalf("match = %q, want 1990/01/01", fs[0].Match)
	}
}

// TestScanContentDedupPrefersPromotedConfidenceOverUnpromoted は
// dedupAndSortFindings が同一 span の候補のうち信頼度の高い方を残すことを
// 確認する。単独行走査（ラベルなし・Medium）と隣接行相関（ラベルあり・High）が
// 同じ span を候補として生成するため、先勝ちのままだと min_confidence=medium
// 運用で昇格結果が捨てられてしまう（issue #62 の回帰項目）。
func TestScanContentDedupPrefersPromotedConfidenceOverUnpromoted(t *testing.T) {
	d := newDetector(t, "") // 既定の min_confidence = medium
	phone := "090" + "1234" + "5678"

	fs := d.ScanContent("f.txt", "電話番号:\n"+phone)
	assertRules(t, fs, "jp-phone-number")
	if fs[0].Confidence != rule.High {
		t.Fatalf("confidence = %v, want high（dedup は高信頼度を優先すべき）", fs[0].Confidence)
	}
}

// TestScanContentAdjacentLabelIgnoreMarkerDoesNotSuppressValueLine は
// ignore マーカーの抑制判定が値の乗る行ごとであることを確認する。従来は
// 結合文字列全体に対して ignoredLine を判定していたため、ラベル行だけの
// マーカーが隣の値行の検出まで消していた（非対称バグ、issue #62）。
func TestScanContentAdjacentLabelIgnoreMarkerDoesNotSuppressValueLine(t *testing.T) {
	d := newDetector(t, "")
	bankAccount := "1234567"
	fs := d.ScanContent("f.txt", "口座番号: // "+IgnoreMarker+"\n"+bankAccount)
	assertRules(t, fs, "jp-bank-account")
}

// TestScanContentAdjacentValueLineIgnoreMarkerStillSuppresses は、値行自体の
// マーカーは従来どおり抑制することを確認する（上のテストとの対称性）。
func TestScanContentAdjacentValueLineIgnoreMarkerStillSuppresses(t *testing.T) {
	d := newDetector(t, "")
	bankAccount := "1234567"
	fs := d.ScanContent("f.txt", "口座番号:\n"+bankAccount+" // "+IgnoreMarker)
	assertRules(t, fs)
}

// TestScanContentRejectsCrossLineNegativeContextAcrossBlankLine は
// hasCrossLineNegativeContext も論理隣接（空行スキップ）に統一されていることを
// 確認する。空行を挟んだ先に負コンテキスト（円）があるケースを抑制できないと、
// 隣接行相関の到達範囲拡大に伴い新規の誤検出が増える（issue #62 のリスク項目）。
func TestScanContentRejectsCrossLineNegativeContextAcrossBlankLine(t *testing.T) {
	d := newDetector(t, "")
	bankAccount := "1234567"
	assertRules(t, d.ScanContent("f.txt", "口座番号: "+bankAccount+"\n\n円"))
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

// TestScanDiffHunkAdjacentLinesSkipBlankLines は diff 走査経路でも論理隣接
// （空行スキップ）が効くことを確認する。git diff -U3 の文脈行に空行が
// 挟まっていても、追加行の値をラベルで正しく相関できる必要がある（issue #62）。
func TestScanDiffHunkAdjacentLinesSkipBlankLines(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanDiffHunk("f.txt", []DiffLine{
		{Text: "口座番号:", Added: false},
		{Text: "", Added: false},
		{Text: "1234567", Added: true},
	})
	assertRules(t, fs, "jp-bank-account")
	if fs[0].Line != 3 {
		t.Fatalf("line = %d, want 3", fs[0].Line)
	}
}

// TestScanDiffHunkAdjacentLinesTooFarNotDetected は diff 経路でも j-i>3 では
// 相関しないことを確認する負例。
func TestScanDiffHunkAdjacentLinesTooFarNotDetected(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanDiffHunk("f.txt", []DiffLine{
		{Text: "口座番号:", Added: false},
		{Text: "", Added: false},
		{Text: "", Added: false},
		{Text: "", Added: false},
		{Text: "1234567", Added: true},
	})
	assertRules(t, fs)
}

// TestScanDiffHunkAdjacentLabelPromotesNonRequireContextRule は diff 経路でも
// 非 RequireContext ルール（電話番号）が文脈行のラベルで昇格することを確認する
// （ScanContent 側の TestScanContentAdjacentLabelPromotesNonRequireContextRuleWithinWindow
// との full/diff 対称性）。
func TestScanDiffHunkAdjacentLabelPromotesNonRequireContextRule(t *testing.T) {
	d := newDetector(t, `min_confidence = "high"`)
	phone := "090" + "1234" + "5678"
	fs := d.ScanDiffHunk("f.txt", []DiffLine{
		{Text: "電話番号:", Added: false},
		{Text: phone, Added: true},
	})
	assertRules(t, fs, "jp-phone-number")
	if fs[0].Confidence != rule.High {
		t.Fatalf("confidence = %v, want high", fs[0].Confidence)
	}
}

// TestScanDiffHunkAdjacentBirthdateWithEmbeddedLabel は、未変更のラベル行と追加した
// 値行を結合する diff 経路でも jp-birthdate のラベル埋め込み正規表現を維持する
// ことを確認する。
func TestScanDiffHunkAdjacentBirthdateWithEmbeddedLabel(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanDiffHunk("f.txt", []DiffLine{
		{Text: "生年月日:", Added: false},
		{Text: "1990/01/01", Added: true},
	})
	assertRules(t, fs, "jp-birthdate")
	if fs[0].Line != 2 || fs[0].Column != 1 {
		t.Fatalf("location = %d:%d, want 2:1", fs[0].Line, fs[0].Column)
	}
	if fs[0].Match != "1990/01/01" {
		t.Fatalf("match = %q, want 1990/01/01", fs[0].Match)
	}
}

// TestScanDiffHunkAdjacentLabelIgnoreMarkerDoesNotSuppressAddedValue は、
// 文脈行（ラベル）だけの ignore マーカーが追加行の値を消さないことを確認する
// （diff 経路は元から scanLineNoIgnore + 値行ごとの判定だったため既存の挙動だが、
// ScanContent 側の対称性修正（issue #62）とセットで回帰確認する）。
func TestScanDiffHunkAdjacentLabelIgnoreMarkerDoesNotSuppressAddedValue(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanDiffHunk("f.txt", []DiffLine{
		{Text: "口座番号: // " + IgnoreMarker, Added: false},
		{Text: "1234567", Added: true},
	})
	assertRules(t, fs, "jp-bank-account")
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
		// マーカーなしダッシュ連結は市区町村との間に助詞（で・に・は・を）以外の
		// ひらがな・漢字を挟んでもよい（「霞が関」の「が」・「小島町」は町名自体が
		// マーカー、いずれも助詞を含まない）。#55: banchiDash + notCalendarDateBanchi。
		{"ダッシュ連結（助詞以外のひらがなを挟む）", "住所: 東京都千代田区霞が関3-2-1", "東京都千代田区霞が関3-2-1"},
		{"ダッシュ連結（町名がそのままマーカー）", "住所: 神奈川県川崎市川崎区小島町2-10-7", "神奈川県川崎市川崎区小島町2-10-7"},
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

// マーカー（丁目/番/号）のないダッシュ連結番地は、市区町村直後の助詞
// 「で・に・は・を」を挟んだスコア表記・ISO 日付を番地と誤認しない（#55）。
// 助詞が市区町村に直結していない（間に別の語がある）場合は本スライスの対象外。
func TestAddressDashOnlyExcludesParticleGap(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct{ name, line string }{
		{"スコア表記（で）", "東京都調布市で行われた試合に3-2で勝利"},
		{"ISO日付（で）", "東京都渋谷区で2025-07-02に開催"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line))
		})
	}
}

// 市区町村に助詞なしで直結する末尾ダッシュ番地は、3 成分かつ先頭が妥当な西暦
// （1900〜2100）で実在する暦日のときだけ棄却する（notCalendarDateBanchi）。
// 2 成分（大字直番地型）、存在しない日付、年として妥当でない先頭成分（実住所の
// 番地）は棄却しない（#55）。
func TestAddressDashOnlyValidateRejectsOnlyRealCalendarDates(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line, want string
	}{
		{"実在するISO日付（助詞なし直結）は棄却", "住所: 東京都渋谷区2025-07-02に開催", ""},
		{"2成分は棄却しない（大字直番地）", "住所: 東京都渋谷区大字直番地1993-1", "東京都渋谷区大字直番地1993-1"},
		{"存在しない日付（13月）は番地として許可", "住所: 東京都渋谷区2025-13-40に開催", "東京都渋谷区2025-13-40"},
		{"存在しない日付（2月30日）は番地として許可", "住所: 東京都渋谷区2025-02-30に開催", "東京都渋谷区2025-02-30"},
		{"年の範囲外（1900未満）は番地として許可", "住所: 東京都渋谷区1899-01-01に開催", "東京都渋谷区1899-01-01"},
		{"年として妥当でない先頭成分は許可（実住所）", "住所: 東京都千代田区霞が関3-2-1", "東京都千代田区霞が関3-2-1"},
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

// 高再現率住所ルールは、学区のように市区町村ではない語（通学区）を municipality
// と誤認した検出を辞書照合（dict.MunicipalitySuffixMatch）で棄却する。実在する
// 市区町村を含む住所は従来どおり検出する（#55）。
func TestHighRecallAddressRejectsUnknownMunicipality(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	assertRules(t, d.ScanLine("f.txt", 1, "通学区域は3丁目まで"))
	assertRules(t, d.ScanLine("f.txt", 1, "住所: 通学区域は3丁目まで"))
	assertRules(t, d.ScanLine("f.txt", 1, "勤務地: 渋谷区渋谷2-1-1"), "jp-address-high-recall")
}

// 漢数字番地（神南一丁目十九番十一号 等）。ASCII 数字を含まない行でも
// PrefilterCJK + 都道府県リテラルで検出する。ダッシュ形は持たない（#55）。
func TestAddressKanjiNumeralBanchi(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct{ name, line, want string }{
		{"丁目番号の連鎖（漢数字）", "住所: 東京都渋谷区神南一丁目十九番十一号", "東京都渋谷区神南一丁目十九番十一号"},
		{"丁目のみ（漢数字）", "住所: 東京都渋谷区神南三丁目", "東京都渋谷区神南三丁目"},
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

// 以下、issue #60（公的番号のカバレッジ拡充）で追加したルールのテスト。
// JP_PII_FIXTURES を要求する既存ルールと異なり、値はチェックディジット計算や
// 桁数・区切り文字だけで妥当性が決まる架空のダミー値のため、インラインの
// リテラルで完結させる（piifixtures 不要）。

// TestEmploymentInsuranceRule は雇用保険被保険者番号（4桁-6桁-1桁 / 11桁）を検証する。
func TestEmploymentInsuranceRule(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
		conf       rule.Confidence
	}{
		{"区切りあり（4-6-1）はコンテキストなしでも high", "value = 1234-567890-1", []string{"jp-employment-insurance"}, rule.High},
		{"区切りなし 11 桁はコンテキストが必要", "雇用保険被保険者番号: 12345678901", []string{"jp-employment-insurance"}, rule.Medium},
		{"区切りなし 11 桁はコンテキストなしでは不成立", "value = 12345678901", nil, 0},
		{"英語コンテキスト", "employment insurance no: 12345678901", []string{"jp-employment-insurance"}, rule.Medium},
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

// ---- issue #58: 半角カナ折り畳み・カタカナ/ひらがな氏名・4 文字姓・ローマ字氏名 ----
//
// 以下のテストは JP_PII_FIXTURES に依存しない（値は internal/dict/gen-names で
// 生成した辞書エントリ、または人手追加のダミー氏名を直接使う）。

// TestPersonNameHalfwidthKatakana は半角カナのフリガナラベル・値
// （振込明細・レガシー CSV に頻出）を検出することを確認する。normalize.Line が
// 半角カナを未合成の結合文字つき全角カナへ折り畳み、katakana 文字クラス
// （internal/rule）が結合文字 \x{3099}\x{309A} を許容することで検出できる。
func TestPersonNameHalfwidthKatakana(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	tests := []struct {
		name, line string
		want       []string
	}{
		{"半角カナ フリガナラベル・値（濁点あり）", "ﾌﾘｶﾞﾅ: ﾔﾏﾀﾞ ﾀﾛｳ", []string{"person-name"}},
		{"半角カナ フリガナラベル 全角＝区切り", "ﾌﾘｶﾞﾅ＝ﾔﾏﾀﾞ ﾀﾛｳ", []string{"person-name"}},
		{"全角フリガナラベル・半角カナ値", "フリガナ: ﾔﾏﾀﾞ ﾀﾛｳ", []string{"person-name"}},
		{"半角カナラベル・全角カナ値", "ﾌﾘｶﾞﾅ: ヤマダ タロウ", []string{"person-name"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// TestPersonNameHalfwidthKatakanaPreservesOriginalMatchText は、検出値が
// 正規化前の元の半角カナ表記のまま報告される（マスク・報告は生テキスト基準）
// ことを確認する。internal/normalize の 1 ルーン = 1 ルーン不変条件の直接的な帰結。
func TestPersonNameHalfwidthKatakanaPreservesOriginalMatchText(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	fs := d.ScanLine("f.txt", 1, "ﾌﾘｶﾞﾅ: ﾔﾏﾀﾞ ﾀﾛｳ")
	assertRules(t, fs, "person-name")
	if fs[0].Match != "ﾔﾏﾀﾞ ﾀﾛｳ" {
		t.Errorf("Match = %q, want original half-width text %q", fs[0].Match, "ﾔﾏﾀﾞ ﾀﾛｳ")
	}
}

// TestPersonNameKatakanaDictionaryWeakFields はカタカナ読みの姓・名
// （internal/dict/gen-names で生成）が弱いラベル（姓・名）で検出されることを
// 確認する。辞書拡充前はカタカナ単独の値がすべて false になっていた
// （issue #58 の問題 (2)）。
func TestPersonNameKatakanaDictionaryWeakFields(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	tests := []struct {
		name, line string
		want       []string
	}{
		{"姓（カタカナ）", "姓: サトウ", []string{"person-name"}},
		{"名（カタカナ）", "名: サクラ", []string{"person-name"}},
		{"フリガナ（姓+名 空白区切り）", "フリガナ: サトウ サクラ", []string{"person-name"}},
		{"フリガナ（姓+名 区切りなし）", "フリガナ: サトウサクラ", []string{"person-name"}},
		// 辞書外のカタカナ語は弱いラベルでは棄却する。
		{"名 + 辞書外カタカナ", "名: サービス", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// TestPersonNameFourCharacterSurname は 4 文字姓（issue #58 で人手追加。従来の
// 辞書は最長 3 文字だった）が弱いラベルで検出されることを確認する。
func TestPersonNameFourCharacterSurname(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	tests := []struct {
		name, line string
	}{
		{"4文字姓（漢字）", "姓: 勅使河原"},
		{"4文字姓（カタカナ読み）", "姓: テシガハラ"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), "person-name")
		})
	}
}

// TestPersonNameRomajiHighRecall は person-name-romaji ルール（issue #58 段階
// 3）の検出を確認する。ASCII の強いラベル・裸の name ラベルの両方で、姓名
// ローマ字辞書の共起（語順不問）を必須にする。既定では無効（高再現率モード限定）。
func TestPersonNameRomajiHighRecall(t *testing.T) {
	d := newDetector(t, `
min_confidence = "low"
[rules]
high_recall = true
`)
	tests := []struct {
		name, line string
		want       []string
	}{
		{"name ラベル 姓→名の順", "name: Yamada Tarou", []string{"person-name-romaji"}},
		{"name ラベル 名→姓の順（語順不問）", "name: Tarou Yamada", []string{"person-name-romaji"}},
		{"full_name ラベル", "full_name: Yamada Tarou", []string{"person-name-romaji"}},
		{"JSON 風キー引用符", `{"full_name": "Yamada Tarou"}`, []string{"person-name-romaji"}},
		{"name ラベル 3 語は先頭 2 語だけ検出しない", "name: Yamada Tarou Extra", nil},
		{"full_name ラベル 3 語は先頭 2 語だけ検出しない", "full_name: Yamada Tarou Extra", nil},
		{"2 語目に数字が直結する場合は検出しない", "name: Yamada Tarou2023", nil},
		{"2 語目に underscore が直結する場合は検出しない", "name: Yamada Tarou_id", nil},
		// 辞書外の英単語は棄却する。
		{"辞書外の英単語 2 語", "name: Hello World", nil},
		// 裸の name ラベルの前方境界（kebab-case・dotted key）は除外する。
		{"project-name（非人物キー）", "project-name: Yamada Tarou", nil},
		{"filename（複合識別子）", "filename: Yamada Tarou", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// TestPersonNameRomajiDisabledByDefault は person-name-romaji が高再現率
// モード限定（既定オフ）であることを確認する。
func TestPersonNameRomajiDisabledByDefault(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	assertRules(t, d.ScanLine("f.txt", 1, "name: Yamada Tarou"))
}

// TestAddressStillDetectedAfterKatakanaClassExpansion は、katakana 文字クラス
// （internal/rule）へ結合濁点・半濁点を追加した変更（issue #58）が、通常の
// 全角住所検出を壊していないことを確認する回帰テスト。
func TestAddressStillDetectedAfterKatakanaClassExpansion(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct{ name, line string }{
		{"都道府県+市区+番地", "住所: 東京都千代田区丸の内1-1-1"},
		{"府+市+区+番地", "勤務地: 大阪府大阪市北区梅田2-2-2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), "jp-address")
		})
	}
}

// --- P23: 複数エンティティ共起ブースト（[rules] cooccurrence_boost）---
//
// piifixtures を使わず inline literal のみでテストする（外部データセットが
// 無い CI/開発機でも走る）。氏名は「架空太郎」（人名らしい形だが姓名辞書には
// 無く dict.IsPersonName は false になるため、person-name の twin のうち
// Base:Low 側だけがヒットする。notPlaceholderName は通るので Reason.Validated
// は true になる）、電話番号は区切りあり携帯（0[5-9]0-\d{4}-\d{4}）で
// Base:High・Validated（validPhone）な高信頼アンカーに使う。min_confidence は
// 既定の "medium" を明示して氏名（Base:Low）が昇格なしでは報告されないことを
// 前提にする。

func TestCooccurrenceBoostPromotesNearbyPersonName(t *testing.T) {
	d := newDetector(t, `
min_confidence = "medium"

[rules]
cooccurrence_boost = true
`)
	content := "氏名: 架空太郎\n電話: 090-1234-5678"
	fs := d.ScanContent("f.txt", content)
	assertRules(t, fs, "person-name", "jp-phone-number")
	for _, f := range fs {
		if f.RuleID != "person-name" {
			continue
		}
		if f.Confidence != rule.Medium {
			t.Errorf("person-name confidence = %v, want %v（Low→Medium の 1 段昇格）", f.Confidence, rule.Medium)
		}
		if !f.Reason.CooccurrenceBoosted {
			t.Error("Reason.CooccurrenceBoosted = false, want true")
		}
	}
}

func TestCooccurrenceBoostIgnoresCrossLineNegativeAnchor(t *testing.T) {
	d := newDetector(t, `
min_confidence = "medium"

[rules]
cooccurrence_boost = true
`)
	content := "氏名: 架空太郎\n免許証番号: 123456789012\n円"
	assertRules(t, d.ScanContent("f.txt", content))
}

// TestCooccurrenceBoostDisabledByDefault は opt-in していない既定設定では、
// 辞書不一致の氏名+電話が近接していても氏名が既定どおり非表示のままであることを
// 確認する。
func TestCooccurrenceBoostDisabledByDefault(t *testing.T) {
	d := newDetector(t, "") // 既定 min_confidence=medium, cooccurrence_boost=false
	content := "氏名: 架空太郎\n電話: 090-1234-5678"
	assertRules(t, d.ScanContent("f.txt", content), "jp-phone-number")
}

// TestCooccurrenceBoostIsolatedNameNotPromoted は近傍に異なるカテゴリの高信頼
// PII が無い単発の氏名は昇格しないことを確認する（負例）。
func TestCooccurrenceBoostIsolatedNameNotPromoted(t *testing.T) {
	d := newDetector(t, `
min_confidence = "medium"

[rules]
cooccurrence_boost = true
`)
	content := "氏名: 架空太郎\n備考: 特になし\n備考: 特になし"
	assertRules(t, d.ScanContent("f.txt", content))
}

// TestCooccurrenceBoostFarApartEntitiesNotPromoted は大きなファイルで氏名と
// 電話番号がウィンドウ（±cooccurrenceWindowLines 行）を大きく超えて離れている
// 場合、無関係な PII 同士を誤って共起昇格させないことを確認する（負例）。
func TestCooccurrenceBoostFarApartEntitiesNotPromoted(t *testing.T) {
	d := newDetector(t, `
min_confidence = "medium"

[rules]
cooccurrence_boost = true
`)
	content := "氏名: 架空太郎\n" + strings.Repeat("filler line\n", 50) + "電話: 090-1234-5678"
	assertRules(t, d.ScanContent("f.txt", content), "jp-phone-number")
}

// TestCooccurrenceBoostWindowBoundary は cooccurrenceWindowLines（±5 行）の
// 境界ちょうどで昇格する/しないが切り替わることを確認する。
func TestCooccurrenceBoostWindowBoundary(t *testing.T) {
	tests := []struct {
		name  string
		gap   int // 氏名行と電話番号行の間に挟む空行数
		boost bool
	}{
		{"ウィンドウ内（5行差）", 4, true},
		{"ウィンドウ外（6行差）", 5, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newDetector(t, `
min_confidence = "medium"

[rules]
cooccurrence_boost = true
`)
			content := "氏名: 架空太郎\n" + strings.Repeat("\n", tt.gap) + "電話: 090-1234-5678"
			fs := d.ScanContent("f.txt", content)
			hasName := false
			for _, f := range fs {
				if f.RuleID == "person-name" {
					hasName = true
				}
			}
			if hasName != tt.boost {
				t.Errorf("person-name present = %v, want %v (findings=%v)", hasName, tt.boost, ruleIDs(fs))
			}
		})
	}
}

// TestEmploymentInsuranceBoundaryAndNegativeContext は、より長い数字列の一部を
// 誤検出しないこと、および金額・件数文脈で抑制されることを確認する。
func TestEmploymentInsuranceBoundaryAndNegativeContext(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
	}{
		{"区切りありの一部は対象外（前後に数字が連結）", "id = 91234-567890-12"},
		{"区切りなし 11 桁がより長い数字列の一部は対象外", "雇用保険 id=912345678901 番"},
		// NegativeContext（件）が直後にあれば、コンテキスト語（雇用保険）が
		// 同一行にあっても検出を棄却する。
		{"件数文脈は NegativeContext で棄却される", "雇用保険の加入者数は 12345678901 件"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line))
		})
	}
}

// TestKaigoInsuranceRule は介護保険被保険者番号（10桁）を検証する。
// 桁数は基礎年金番号（4桁-6桁、区切りなしでも同じ10桁形状）と衝突するが、
// 両ルールとも RequireContext:true のため、コンテキスト語が異なる限り
// 同一の10桁値に対してどちらか一方だけが成立する（同時発火しない）。
func TestKaigoInsuranceRule(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"介護保険コンテキストで成立", "介護保険 被保険者証番号: 9876543210", []string{"jp-kaigo-insurance"}},
		{"年金コンテキストでは基礎年金番号側が成立", "年金番号: 9876543210", []string{"jp-pension-number"}},
		{"コンテキストなしでは不成立", "value = 9876543210", nil},
		{"より長い数字列の一部は対象外", "介護保険 被保険者証番号: 912345678901", nil},
		{"要介護コンテキスト", "要介護認定 被保険者番号 9876543210", []string{"jp-kaigo-insurance"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// TestJuminhyoCodeRule は住民票コード（無作為な10桁 + 検査数字1桁）を検証する。
// 検査数字の公式算式を一次資料から独立検証できていないため、未検証の算式による
// false negative を避け、11桁の形状・周辺語・全桁同一でないことだけを判定する。
func TestJuminhyoCodeRule(t *testing.T) {
	d := newDetector(t, "")
	const value = "55512345670"
	tests := []struct {
		name, line string
		want       []string
	}{
		{"住民票コードコンテキストで成立", "住民票コード: " + value, []string{"jp-juminhyo-code"}},
		{"住民票コンテキストでも成立", "住民票の写しに記載のコード " + value, []string{"jp-juminhyo-code"}},
		{"末尾桁の値にかかわらず形状とコンテキストで成立", "住民票コード: 55512345679", []string{"jp-juminhyo-code"}},
		{"コンテキストなしでは不成立", "value = " + value, nil},
		{"全桁同一は無効", "住民票コード: 11111111111", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// TestInvoiceNumberRule は適格請求書発行事業者登録番号（T + 13桁）を検証する。
func TestInvoiceNumberRule(t *testing.T) {
	d := newDetector(t, "")
	const valid = "T1234567890123"
	tests := []struct {
		name, line string
		want       []string
	}{
		{"登録番号コンテキスト", "登録番号: " + valid, []string{"jp-invoice-number"}},
		{"インボイスコンテキスト", "インボイス登録番号 " + valid, []string{"jp-invoice-number"}},
		{"英語コンテキスト", "invoice number: " + valid, []string{"jp-invoice-number"}},
		{"コンテキストなしでは不成立", "value = " + valid, nil},
		{"桁数不足（12桁）は対象外", "登録番号: T123456789012", nil},
		{"より長い数字列の一部は対象外", "登録番号: " + valid + "4", nil},
		{"英数字トークンに埋め込まれた場合は対象外", "登録番号: aT1234567890123b", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// TestResidenceCardSpecialPermanentContext は特別永住者証明書番号
// （在留カードと同一形式）を、追加したコンテキスト語で検出できることを確認する。
func TestResidenceCardSpecialPermanentContext(t *testing.T) {
	d := newDetector(t, "")
	const value = "AB12345678CD"
	tests := []struct {
		name, line string
		want       []string
	}{
		{"特別永住", "特別永住の在留資格に係る番号: " + value, []string{"jp-residence-card"}},
		{"特別永住者証明書", "特別永住者証明書番号: " + value, []string{"jp-residence-card"}},
		{"永住者証明書", "永住者証明書 " + value, []string{"jp-residence-card"}},
		{"special permanent", "special permanent resident certificate: " + value, []string{"jp-residence-card"}},
		{"コンテキストなしでは不成立", value, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

// TestCooccurrenceBoostRejectsPlaceholderName はプレースホルダ値（未定 等）が
// notPlaceholderName で最初から候補にすらならないため、近傍に高信頼 PII が
// あっても昇格・報告されないことを確認する（Validated でない候補は昇格しない）。
func TestCooccurrenceBoostRejectsPlaceholderName(t *testing.T) {
	d := newDetector(t, `
min_confidence = "medium"

[rules]
cooccurrence_boost = true
`)
	content := "氏名: 未定\n電話: 090-1234-5678"
	assertRules(t, d.ScanContent("f.txt", content), "jp-phone-number")
}

// TestCooccurrenceBoostExcludesAddressAnchor は jp-address がチェックサム検証も
// RequireContext によるラベル必須化も無いため、現時点では昇格の根拠（アンカー）
// に含めないことを確認する（試合スコア・日付住所等のボーダー FP を道連れに
// 昇格させるリスクを避けるための意図的なスコープ限定。P11 の住所誤検出対策が
// 先行してから再検討する）。
func TestCooccurrenceBoostExcludesAddressAnchor(t *testing.T) {
	d := newDetector(t, `
min_confidence = "medium"

[rules]
cooccurrence_boost = true
`)
	content := "氏名: 架空太郎\n住所: 東京都渋谷区道玄坂2丁目10番7号"
	assertRules(t, d.ScanContent("f.txt", content), "jp-address")
}

// TestCooccurrenceBoostHighRecallMediumToHigh は person-name-high-recall
// （Base:Medium）が近傍アンカーで Medium→High まで昇格しうることを確認する
// （「まれに Medium→High」の 1 段昇格。high_recall と cooccurrence_boost の
// 両方が opt-in されて初めて効く）。
func TestCooccurrenceBoostHighRecallMediumToHigh(t *testing.T) {
	d := newDetector(t, `
min_confidence = "high"

[rules]
high_recall = true
cooccurrence_boost = true
`)
	content := "担当: 田中太郎\n電話: 090-1234-5678"
	fs := d.ScanContent("f.txt", content)
	assertRules(t, fs, "person-name-high-recall", "jp-phone-number")
	for _, f := range fs {
		if f.RuleID == "person-name-high-recall" && f.Confidence != rule.High {
			t.Errorf("person-name-high-recall confidence = %v, want %v", f.Confidence, rule.High)
		}
	}
}

// TestScanDiffHunkDoesNotApplyCooccurrenceBoost は ScanDiffHunk（git diff 走査）が
// cooccurrence_boost の対象外であることを確認する。ScanDiffHunk は文脈行を
// 昇格の根拠にしない設計を維持するため、フルスキャン専用の ScanContent とは
// 意図的に別経路のまま扱う。
func TestScanDiffHunkDoesNotApplyCooccurrenceBoost(t *testing.T) {
	d := newDetector(t, `
min_confidence = "medium"

[rules]
cooccurrence_boost = true
`)
	fs := d.ScanDiffHunk("f.txt", []DiffLine{
		{Text: "氏名: 架空太郎", Added: true},
		{Text: "電話: 090-1234-5678", Added: true},
	})
	assertRules(t, fs, "jp-phone-number")
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
