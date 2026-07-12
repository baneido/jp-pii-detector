package detect

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/rule"
)

const healthInsurance6DigitContextWindowForTest = 12

// TestHealthInsuranceSixDigitInsurerNumber は国民健康保険の 6 桁保険者番号を
// 強ラベル「保険者番号」へほぼ直結した場合だけ Medium で検出することを確認する。
// 6 桁は金額・件数・郵便番号の一部などと衝突しやすいため、既存 8 桁向けの
// 「保険証」「被保険者」等の広い文脈だけでは成立させない。
func TestHealthInsuranceSixDigitInsurerNumber(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       bool
	}{
		{"強ラベルとコロン", "保険者番号: 138057", true},
		{"国保の説明と等号", "国民健康保険 保険者番号 = 138057", true},
		{"全角数字と全角コロン", "保険者番号：１３８０５７", true},
		{"値から強ラベルの順", "138057 : 保険者番号", true},
		{"ラベルなし", "138057", false},
		{"健康保険だけでは弱い", "健康保険 138057", false},
		{"保険証だけでは弱い", "保険証 138057", false},
		{"被保険者番号は別種の番号", "被保険者番号: 138057", false},
		{"強ラベルとの間に受付ID説明", "保険者番号の問い合わせ受付ID: 138057", false},
		{"金額", "保険者番号: 138057円", false},
		{"件数", "保険者番号: 138057件", false},
		{"郵便番号上位風", "郵便番号: 138057", false},
		{"7桁の末尾部分", "保険者番号: 9138057", false},
		{"7桁の先頭部分", "保険者番号: 1380579", false},
		{"英数字トークンの内部", "保険者番号: A138057Z", false},
		{"ハイフン区切り", "保険者番号: 138-057", false},
		{"検証番号不一致", "保険者番号: 138058", false},
		{"全桁同一ダミー", "保険者番号: 111111", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanLine("f.txt", 1, tt.line)
			if !tt.want {
				assertRules(t, fs)
				return
			}
			assertRules(t, fs, "jp-health-insurance")
			if fs[0].Confidence != rule.Medium {
				t.Fatalf("confidence = %v, want medium", fs[0].Confidence)
			}
			if fs[0].Reason.ContextWindow != healthInsurance6DigitContextWindowForTest {
				t.Fatalf("context window = %d, want %d", fs[0].Reason.ContextWindow, healthInsurance6DigitContextWindowForTest)
			}
		})
	}
}

// TestHealthInsuranceSixDigitContextWindowBoundary は 6 桁パターン固有の 12
// ルーン窓の境界を検証する。既存の 8 桁パターンはルール既定の 40 ルーンを
// 継承し続け、6 桁だけが狭い窓へ限定される。
func TestHealthInsuranceSixDigitContextWindowBoundary(t *testing.T) {
	d := newDetector(t, "")
	label := "保険者番号"
	inN := healthInsurance6DigitContextWindowForTest - utf8.RuneCountInString(label)

	in := d.ScanLine("f.txt", 1, label+strings.Repeat(" ", inN)+"138057")
	assertRules(t, in, "jp-health-insurance")
	if in[0].Reason.ContextWindow != healthInsurance6DigitContextWindowForTest {
		t.Fatalf("6桁 context window = %d, want %d", in[0].Reason.ContextWindow, healthInsurance6DigitContextWindowForTest)
	}
	assertRules(t, d.ScanLine("f.txt", 1, label+strings.Repeat(" ", inN+1)+"138057"))

	eight := d.ScanLine("f.txt", 1, "保険者番号: 12345678")
	assertRules(t, eight, "jp-health-insurance")
	if eight[0].Reason.ContextWindow != digitRuleRequireContextWindowForTest {
		t.Fatalf("8桁 context window = %d, want %d", eight[0].Reason.ContextWindow, digitRuleRequireContextWindowForTest)
	}
}

// TestHealthInsuranceSixDigitAdjacentLines は、強ラベルと 6 桁値が論理隣接行へ
// 分かれた帳票形式を両方向で検出し、値の行・列へ正しく再マップする。
func TestHealthInsuranceSixDigitAdjacentLines(t *testing.T) {
	d := newDetector(t, "")

	fs := d.ScanContent("f.txt", "保険者番号:\n\n138057")
	assertRules(t, fs, "jp-health-insurance")
	if fs[0].Line != 3 || fs[0].Column != 1 || fs[0].Match != "138057" {
		t.Fatalf("finding = %+v, want 3:1 match 138057", fs[0])
	}

	fs = d.ScanContent("f.txt", "138057\n保険者番号:")
	assertRules(t, fs, "jp-health-insurance")
	if fs[0].Line != 1 || fs[0].Column != 1 || fs[0].Match != "138057" {
		t.Fatalf("finding = %+v, want 1:1 match 138057", fs[0])
	}

	assertRules(t, d.ScanContent("f.txt", "被保険者番号:\n138057"))
}

// TestHealthInsuranceSixDigitAdjacentDiff は未変更の強ラベル行を文脈として、
// 追加した 6 桁値だけを diff 走査でも報告することを確認する。
func TestHealthInsuranceSixDigitAdjacentDiff(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanDiffHunk("f.txt", []DiffLine{
		{Text: "保険者番号:", Added: false},
		{Text: "138057", Added: true},
	})
	assertRules(t, fs, "jp-health-insurance")
	if fs[0].Line != 2 || fs[0].Column != 1 || fs[0].Match != "138057" {
		t.Fatalf("finding = %+v, want 2:1 match 138057", fs[0])
	}

	assertRules(t, d.ScanDiffHunk("f.txt", []DiffLine{
		{Text: "被保険者番号:", Added: false},
		{Text: "138057", Added: true},
	}))
}
