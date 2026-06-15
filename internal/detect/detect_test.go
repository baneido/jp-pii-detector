package detect

import (
	"strings"
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
		{"実在しない地域コードの郵便番号", "郵便番号: 000-0000", nil},
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
		{"ドットとプラスとサブドメイン", "contact: user.name+tag@sub-domain.company.co.jp", []string{"email-address"}},
		{"予約ドメイン example は除外", "user@example.com / user@sub.example.co.jp", nil},
		{"予約 TLD test は除外", "user@foo.test", nil},
		{"実在しない TLD は除外", "user@service.notatld", nil},
		{"IANA 登録済み TLD は検出", "contact: user@service.dev", []string{"email-address"}},
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

func TestASCIIContextRequiresWordBoundary(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
		conf       rule.Confidence
	}{
		{"tel は hotel の一部では成立しない", "hotel 03-1234-5678", []string{"jp-phone-number"}, rule.Medium},
		{"license no は sublicense no の一部では成立しない", "sublicense no 305012345678", nil, 0},
		{"ASCII 語が独立していれば成立する", "license no 305012345678", []string{"jp-drivers-license"}, rule.High},
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
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"口座番号と名義", "口座番号: 1234567 名義: 山田太郎", []string{"jp-bank-account"}},
		{"保険者番号と本人確認", "保険者番号: 12345678 本人確認済み", []string{"jp-health-insurance"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}

func TestDigitRulesRequireNearbyPositiveContext(t *testing.T) {
	d := newDetector(t, "")
	assertRules(t, d.ScanLine("f.txt", 1, "口座番号: 1234567"), "jp-bank-account")

	line := "口座番号は別紙に記載しています。" + strings.Repeat("あ", 40) + "1234567"
	assertRules(t, d.ScanLine("f.txt", 1, line))
}

func TestDigitRulesIgnoreDistantNegativeContext(t *testing.T) {
	d := newDetector(t, "")
	line := "口座番号: 1234567" + strings.Repeat("あ", 25) + "円"
	assertRules(t, d.ScanLine("f.txt", 1, line), "jp-bank-account")
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

func TestHighRecallRulesDisabledByDefault(t *testing.T) {
	d := newDetector(t, "")
	assertRules(t, d.ScanLine("f.txt", 1, "勤務地: 渋谷区道玄坂2-10-7"))
	assertRules(t, d.ScanLine("f.txt", 1, "担当: 山田太郎"))
}

func TestHighRecallRulesOptIn(t *testing.T) {
	d := newDetector(t, `
[rules]
high_recall = true
`)
	assertRules(t, d.ScanLine("f.txt", 1, "勤務地: 渋谷区道玄坂2-10-7"), "jp-address-high-recall")
	assertRules(t, d.ScanLine("f.txt", 1, "担当: 山田太郎"), "person-name-high-recall")
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
		{"ignore コメント", "TEL: 090-1234-5678 # jp-pii-detector:ignore", nil},
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
	// 「住所」コンテキスト下では郵便番号パターン \d{3}-\d{4} が電話番号
	// "090-1234" の部分にもマッチし、範囲が重なる。長い方（電話番号）だけが
	// 残ることを確認する（重複解決ロジックを実際に通るケース）。
	fs := d.ScanLine("f.txt", 1, "住所・電話: 090-1234-5678")
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
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"カンマ区切りの電話番号 2 件", "090-1111-2222,090-3333-4444",
			[]string{"jp-phone-number", "jp-phone-number"}},
		{"CSV 行の電話番号 3 件", "山田,090-1111-2222,090-3333-4444,090-5555-6666",
			[]string{"jp-phone-number", "jp-phone-number", "jp-phone-number"}},
		{"区切りなし携帯の隣接", "tel: 09011112222,09033334444",
			[]string{"jp-phone-number", "jp-phone-number"}},
		{"メールアドレス 2 件", "a.yamada@gmail.com,b.suzuki@gmail.com",
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
	d := newDetector(t, "")
	// 1234-5678-9018 は検査用数字を通過するが、後ろに -3456 が続く。
	assertRules(t, d.ScanLine("f.txt", 1, "code: 1234-5678-9018-3456"))
}

// RequireContext のパターンはキーワードの存在が検出の前提のため High に
// 昇格せず、Base の信頼度のまま報告される（docs/detection-methods.md 4.3）。
// 旧実装は常に High へ昇格し、min_confidence = "high" で△ルールを
// 絞り込めなかった。
func TestContextRequiredConfidenceNotPromoted(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       string
		conf       rule.Confidence
	}{
		{"銀行口座は base の medium のまま", "口座番号: 1234567", "jp-bank-account", rule.Medium},
		{"保険者番号は base の medium のまま", "保険者番号: 12345678", "jp-health-insurance", rule.Medium},
		{"運転免許は base が high", "免許証番号: 305012345678", "jp-drivers-license", rule.High},
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
	assertRules(t, dh.ScanLine("f.txt", 1, "口座番号: 1234567"))
	assertRules(t, dh.ScanLine("f.txt", 1, "免許証番号: 305012345678"), "jp-drivers-license")
}

func TestReasonRecordsPromotionAndContext(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanLine("f.txt", 1, "tel: 09012345678")
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
	d := newDetector(t, "")
	fs := d.ScanLine("f.txt", 1, "住所: 東京都渋谷区道玄坂2-10-7")
	assertRules(t, fs, "jp-address")
	if fs[0].Reason.Validated {
		t.Fatalf("validated = true, want false (jp-address has no validator)")
	}
}

func TestReasonRecordsRequiredNearbyContext(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanLine("f.txt", 1, "口座番号: 1234567")
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
	d := newDetector(t, `min_confidence = "high"`)
	// 区切りなし携帯（コンテキストなし）は medium なので報告されない。
	assertRules(t, d.ScanLine("f.txt", 1, "09012345678"))
	// 区切りあり携帯は high なので報告される。
	assertRules(t, d.ScanLine("f.txt", 1, "090-1234-5678"), "jp-phone-number")
}

// stopword は全角表記とも正規化済みで照合される。
func TestStopwordNormalized(t *testing.T) {
	d := newDetector(t, `
[allowlist]
stopwords = ["090-0000-0001"]
`)
	assertRules(t, d.ScanLine("f.txt", 1, "TEL: ０９０－００００－０００１"))
}

// 固定電話は 10 桁のみ。11 桁は携帯・IP（0[5-9]0）に限る。
func TestPhoneDigitCountStrict(t *testing.T) {
	d := newDetector(t, "")
	assertRules(t, d.ScanLine("f.txt", 1, "0123-456-7890"))                       // 11 桁の固定様式は実在しない
	assertRules(t, d.ScanLine("f.txt", 1, "+81-1-2345-6789"), "jp-phone-number")  // +81 + 9 桁 = 固定 OK
	assertRules(t, d.ScanLine("f.txt", 1, "+81-12-3456-7890"))                    // +81 + 10 桁で携帯以外は不正
	assertRules(t, d.ScanLine("f.txt", 1, "+81-90-1234-5678"), "jp-phone-number") // +81 携帯
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

func TestScanContentSplitLabelAndValue(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", "口座番号:\n1234567")
	assertRules(t, fs, "jp-bank-account")
	if fs[0].Line != 2 || fs[0].Column != 1 {
		t.Fatalf("location = %d:%d, want 2:1", fs[0].Line, fs[0].Column)
	}
	if fs[0].Match != "1234567" {
		t.Fatalf("match = %q, want 1234567", fs[0].Match)
	}
}

func TestScanContentSplitValueAndLabel(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", "1234567\n口座番号:")
	assertRules(t, fs, "jp-bank-account")
	if fs[0].Line != 1 || fs[0].Column != 1 {
		t.Fatalf("location = %d:%d, want 1:1", fs[0].Line, fs[0].Column)
	}
}

func TestScanContentDoesNotDuplicateInlineContext(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", "口座番号: 1234567\n備考")
	assertRules(t, fs, "jp-bank-account")
}

func TestScanContentPreservesDocumentOrderWithAdjacentLineFindings(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", "口座番号:\n1234567\nTEL: 090-1234-5678")
	assertRules(t, fs, "jp-bank-account", "jp-phone-number")

	if fs[0].RuleID != "jp-bank-account" || fs[0].Line != 2 {
		t.Fatalf("first finding = %s at line %d, want jp-bank-account at line 2", fs[0].RuleID, fs[0].Line)
	}
	if fs[1].RuleID != "jp-phone-number" || fs[1].Line != 3 {
		t.Fatalf("second finding = %s at line %d, want jp-phone-number at line 3", fs[1].RuleID, fs[1].Line)
	}
}

func TestScanContentRejectsCrossLineNegativeContext(t *testing.T) {
	d := newDetector(t, "")
	// 口座番号に見えるが、次の行に金額マーカーがある場合は検出しない。
	assertRules(t, d.ScanContent("f.txt", "口座番号: 1234567\n円"))
	// 3 行にまたがるケースも、隣接行のネガティブコンテキストを抑制する。
	assertRules(t, d.ScanContent("f.txt", "口座番号:\n1234567\n円"))
	// ネガティブコンテキストが遠い場合は検出する。
	assertRules(t, d.ScanContent("f.txt", "口座番号: 1234567"+strings.Repeat("あ", 25)+"\n円"), "jp-bank-account")
}
