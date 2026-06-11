package detect

import (
	"testing"

	"github.com/baneido/jp-pii-detecter/internal/config"
	"github.com/baneido/jp-pii-detecter/internal/rule"
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

// 123456789018 はテスト用に検査用数字を計算したダミーのマイナンバー。
func TestMyNumberRule(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
		conf       rule.Confidence
	}{
		{"コンテキストあり区切りあり", "マイナンバー: 1234-5678-9018", []string{"jp-my-number"}, rule.High},
		{"コンテキストなし", "value = 123456789018", []string{"jp-my-number"}, rule.Medium},
		{"全角数字", "個人番号：１２３４５６７８９０１８", []string{"jp-my-number"}, rule.High},
		{"検査用数字不一致", "value = 123456789012", nil, 0},
		{"より長い数字列の一部は対象外", "id = 9123456789018", nil, 0},
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
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"携帯区切りあり", "TEL: 090-1234-5678", []string{"jp-phone-number"}},
		{"携帯区切りなしコンテキストあり", "携帯 09012345678", []string{"jp-phone-number"}},
		{"固定電話区切りあり", "本社: 03-1234-5678", []string{"jp-phone-number"}},
		{"国際表記", "+81-90-1234-5678", []string{"jp-phone-number"}},
		{"IP電話", "050-1234-5678", []string{"jp-phone-number"}},
		{"全角と長音記号", "電話番号：０９０ー１２３４ー５６７８", []string{"jp-phone-number"}},
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
	d := newDetector(t, "")
	fs := d.ScanLine("f.txt", 1, "09012345678")
	assertRules(t, fs, "jp-phone-number")
	if fs[0].Confidence != rule.Medium {
		t.Errorf("confidence = %v, want medium", fs[0].Confidence)
	}
}

func TestPostalAndAddress(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"郵便マークと住所", "〒530-0001 大阪府大阪市北区梅田3丁目", []string{"jp-postal-code", "jp-address"}},
		{"コンテキスト付き郵便番号", "郵便番号: 150-0043", []string{"jp-postal-code"}},
		{"コンテキストなし NNN-NNNN は対象外", "version 150-0043", nil},
		{"番地つき住所", "東京都渋谷区道玄坂2-10-7", []string{"jp-address"}},
		{"番地なしの地名のみは対象外", "東京都渋谷区では雨が降った", nil},
		{"号まで", "住所: 大阪府大阪市北区梅田3丁目1番3号", []string{"jp-address"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestEmailRule(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"通常", "contact: taro.yamada@gmail.com", []string{"email-address"}},
		{"全角アット", "taro＠gmail.com", []string{"email-address"}},
		{"予約ドメイン example は除外", "user@example.com / user@sub.example.co.jp", nil},
		{"予約 TLD test は除外", "user@foo.test", nil},
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
		{"Luhn 不正", "4111-1111-1111-1112", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestContextRequiredRules(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"運転免許", "免許証番号: 305012345678", []string{"jp-drivers-license"}},
		{"運転免許コンテキストなし", "id: 305012345678", nil},
		{"パスポート", "パスポート番号: TK1234567", []string{"jp-passport"}},
		{"パスポートコンテキストなし", "TK1234567", nil},
		{"基礎年金番号", "基礎年金番号: 1234-567890", []string{"jp-pension-number"}},
		{"在留カード", "在留カード番号 AB12345678CD", []string{"jp-residence-card"}},
		{"銀行口座", "口座番号: 1234567", []string{"jp-bank-account"}},
		{"保険者番号", "保険者番号: 12345678", []string{"jp-health-insurance"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestLabeledRules(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	tests := []struct {
		name, line string
		want       []string
	}{
		{"氏名", "氏名: 山田 太郎", []string{"person-name"}},
		{"フリガナ", "フリガナ＝ヤマダ　タロウ", []string{"person-name"}},
		{"生年月日 西暦", "生年月日: 1990年1月23日", []string{"jp-birthdate"}},
		{"生年月日 和暦", "生年月日：平成2年1月23日", []string{"jp-birthdate"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestPersonNameHiddenByDefault(t *testing.T) {
	d := newDetector(t, "") // 既定 min_confidence = medium
	assertRules(t, d.ScanLine("f.txt", 1, "氏名: 山田 太郎"))
}

func TestAllowlist(t *testing.T) {
	d := newDetector(t, `
[allowlist]
stopwords = ["090-0000-0001"]
regexes = ["@baneido\\.com$"]
`)
	tests := []struct {
		name, line string
		want       []string
	}{
		{"stopword", "TEL: 090-0000-0001", nil},
		{"regex 除外", "nakamura@baneido.com", nil},
		{"インラインマーカー", "TEL: 090-1234-5678 // pii-allow ダミー", nil},
		{"除外対象外は検出", "TEL: 090-1234-5678", []string{"jp-phone-number"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestDisabledRule(t *testing.T) {
	d := newDetector(t, `
[rules]
disabled = ["jp-phone-number"]
`)
	assertRules(t, d.ScanLine("f.txt", 1, "TEL: 090-1234-5678"))
}

func TestOverlapResolution(t *testing.T) {
	d := newDetector(t, "")
	// クレジットカード 16 桁の先頭 12 桁にマイナンバーのパターンが重なるケース。
	fs := d.ScanLine("f.txt", 1, "4111-1111-1111-1111")
	assertRules(t, fs, "credit-card")
}

func TestPositionReporting(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanLine("f.txt", 7, "電話：０９０－１２３４－５６７８")
	assertRules(t, fs, "jp-phone-number")
	f := fs[0]
	if f.Line != 7 {
		t.Errorf("line = %d, want 7", f.Line)
	}
	if f.Column != 4 {
		t.Errorf("column = %d, want 4", f.Column)
	}
	if f.Match != "０９０－１２３４－５６７８" {
		t.Errorf("match = %q (元テキストを保持すべき)", f.Match)
	}
}

func TestScanContent(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", "line1\nTEL: 090-1234-5678\r\nline3")
	assertRules(t, fs, "jp-phone-number")
	if fs[0].Line != 2 {
		t.Errorf("line = %d, want 2", fs[0].Line)
	}
}
