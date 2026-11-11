package detect

import (
	"testing"

	"github.com/baneido/jp-pii-detector/internal/rule"
)

// TestHealthInsuranceSymbolNumberLabeled は被保険者証の記号・番号を、ラベル
// （被保険者証／被保険者／保険証 + 記号・番号）が値に直結する場合だけ Medium で
// 検出することを確認する。値はすべて架空。記号・番号の形（英数字-数字）は社内
// コード・型番と区別できないため、ラベルの無い値や記号・番号だけのラベルでは拾わない。
func TestHealthInsuranceSymbolNumberLabeled(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line, want string
	}{
		{"コロン区切り", "被保険者証記号・番号: QX7RZ-48213906", "QX7RZ-48213906"},
		{"文中の助詞は", "保険者番号は31234567、被保険者証記号・番号は MK-5821、公費負担者番号は12345678です。", "MK-5821"},
		{"の・空白区切り", "被保険者証の記号・番号 123 4567", "123 4567"},
		{"全角英数字とハイフン", "保険証記号番号：ＡＢ１２－３４５６７", "ＡＢ１２－３４５６７"},
		{"枝番つき", "被保険者証記号・番号（枝番）: 7Q-48213-00", "7Q-48213-00"},
		{"鉤括弧", "被保険者証記号・番号「Z8-30417」", "Z8-30417"},
		{"記号と番号に別々のラベル", "保険証 記号: 4521 番号: 37", "4521 番号: 37"},
		{"記号と番号の間に読点", "被保険者証の記号 ABC12、番号 3481", "ABC12、番号 3481"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []Finding
			for _, f := range d.ScanLine("f.txt", 1, tt.line) {
				if f.RuleID == "jp-health-insurance" && f.Match == tt.want {
					got = append(got, f)
				}
			}
			if len(got) != 1 {
				t.Fatalf("%q: want one jp-health-insurance finding %q, got %+v", tt.line, tt.want, d.ScanLine("f.txt", 1, tt.line))
			}
			if got[0].Confidence != rule.Medium {
				t.Fatalf("confidence = %v, want medium", got[0].Confidence)
			}
		})
	}
}

func TestHealthInsuranceSymbolNumberRejects(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct{ name, line string }{
		{"番号が全桁同一の記入例", "被保険者証記号・番号: AB-0000"},
		{"値が記入の案内", "被保険者証記号・番号: 記入してください"},
		{"被保険者証のラベルがない", "記号・番号: QX7RZ-48213906"},
		{"ラベルなしの型番", "型番 QX7RZ-48213906"},
		{"より長いコードの一部", "被保険者証記号・番号: QX7RZ-48213906X"},
		{"年度の記述", "被保険者証の記号・番号 2024 年度から変更"},
		{"区切りが多すぎるコード", "被保険者証記号・番号: AB-1234-5678-9012"},
		{"欄の説明", "被保険者証記号・番号欄は空欄"},
		{"番号が数字でない", "被保険者証の記号 ABC 番号 なし"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line))
		})
	}
}

// TestHealthInsuranceSymbolNumberWinsOverEightDigitTail は、記号・番号の番号側が
// 8 桁のとき、既存の 8 桁パターンが番号部分だけを拾うのではなく、記号から番号
// までの全体を 1 件として報告することを確認する。
func TestHealthInsuranceSymbolNumberWinsOverEightDigitTail(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanLine("f.txt", 1, "被保険者証記号・番号: 5KQ2-37150482")
	assertRules(t, fs, "jp-health-insurance")
	if fs[0].Match != "5KQ2-37150482" {
		t.Fatalf("match = %q, want whole symbol-number", fs[0].Match)
	}
}
