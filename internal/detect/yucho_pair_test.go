package detect

import (
	"testing"

	"github.com/baneido/jp-pii-detector/internal/rule"
)

// ゆうちょ銀行の記号・番号がフォームで別行のラベル付きフィールドに分かれる
// ケース（記号: …\n番号: … 等）のテスト。internal/rule/structured.go の
// CrossLineYuchoSymbolRe / CrossLineYuchoNumberRe / ValidCrossLineYuchoPair と、
// internal/detect/yucho_pair.go の scanCrossLineYuchoPairs が対象。
// jp-yucho-account の同一行形式（TestYuchoAccountRule・TestYuchoLabeledAccountRule、
// internal/detect/detect_test.go）と違い、この別行ペア検出は高再現率モードに
// 依存せず既定で有効なため、全テストで newDetector(t, "") を使う。

// TestCrossLineYuchoPairAdjacent は記号行・番号行が論理隣接する基本ケース
// （直接隣接、および間に空行を 1 つ挟むケース）を確認する。高再現率モードでは
// なく既定設定（newDetector(t, "")）で検出できることも合わせて確認する。
func TestCrossLineYuchoPairAdjacent(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name      string
		content   string
		wantLine2 int
	}{
		{"直接隣接", "記号: 14030\n番号: 12345671\n", 2},     // jp-pii-detector:ignore
		{"空行1つ挟み", "記号: 14030\n\n番号: 12345671\n", 3}, // jp-pii-detector:ignore
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanContent("f.txt", tt.content)
			if len(fs) != 2 {
				t.Fatalf("len(fs) = %d, want 2 (findings=%v)", len(fs), ruleIDs(fs))
			}
			for _, f := range fs {
				if f.RuleID != "jp-yucho-account" || f.Confidence != rule.High {
					t.Fatalf("finding: rule=%s confidence=%s, want jp-yucho-account/high", f.RuleID, f.Confidence)
				}
				if !f.Reason.Validated {
					t.Fatalf("finding: Reason.Validated = false, want true")
				}
			}
			if fs[0].Line != 1 || fs[0].Column != 5 || fs[0].Match != "14030" {
				t.Fatalf("fs[0] = line=%d col=%d match=%q, want 1/5/14030", fs[0].Line, fs[0].Column, fs[0].Match)
			}
			if fs[1].Line != tt.wantLine2 || fs[1].Column != 5 || fs[1].Match != "12345671" {
				t.Fatalf("fs[1] = line=%d col=%d match=%q, want %d/5/12345671", fs[1].Line, fs[1].Column, fs[1].Match, tt.wantLine2)
			}
		})
	}
}

// TestCrossLineYuchoPairWithPrefixLabel は記号行に「ゆうちょ」前置語が付いても
// ペア検出が機能することを確認する。
func TestCrossLineYuchoPairWithPrefixLabel(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", "ゆうちょ 記号: 14030\n番号: 12345671\n") // jp-pii-detector:ignore
	if len(fs) != 2 {
		t.Fatalf("len(fs) = %d, want 2 (findings=%v)", len(fs), ruleIDs(fs))
	}
	if fs[0].RuleID != "jp-yucho-account" || fs[0].Line != 1 || fs[0].Match != "14030" {
		t.Fatalf("fs[0] = rule=%s line=%d match=%q", fs[0].RuleID, fs[0].Line, fs[0].Match)
	}
	if fs[1].RuleID != "jp-yucho-account" || fs[1].Line != 2 || fs[1].Match != "12345671" {
		t.Fatalf("fs[1] = rule=%s line=%d match=%q", fs[1].RuleID, fs[1].Line, fs[1].Match)
	}
}

// TestCrossLineYuchoPairQuotedAndPrefixed は、JSON/YAML のフィールド行
// （ラベル・値が引用符で囲まれ、行末に区切りカンマが付く形）と、
// 「通帳」「貯金」前置ラベルの別行ペアを確認する（CrossLineYuchoSymbolRe /
// CrossLineYuchoNumberRe の引用符・行末カンマ・前置語対応）。
func TestCrossLineYuchoPairQuotedAndPrefixed(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name    string
		content string
	}{
		{"JSONフィールド行", "\"記号\": \"14030\",\n\"番号\": \"12345671\"\n"}, // jp-pii-detector:ignore
		{"YAML引用符付き", "記号: \"14030\"\n番号: \"12345671\"\n"},           // jp-pii-detector:ignore
		{"通帳前置ラベル", "通帳記号: 14030\n通帳番号: 12345671\n"},                 // jp-pii-detector:ignore
		{"貯金前置ラベル", "貯金記号: 14030\n貯金番号: 12345671\n"},                 // jp-pii-detector:ignore
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanContent("f.txt", tt.content)
			if len(fs) != 2 {
				t.Fatalf("len(fs) = %d, want 2 (findings=%v)", len(fs), ruleIDs(fs))
			}
			if fs[0].RuleID != "jp-yucho-account" || fs[0].Line != 1 || fs[0].Match != "14030" {
				t.Fatalf("fs[0] = rule=%s line=%d match=%q", fs[0].RuleID, fs[0].Line, fs[0].Match)
			}
			if fs[1].RuleID != "jp-yucho-account" || fs[1].Line != 2 || fs[1].Match != "12345671" {
				t.Fatalf("fs[1] = rule=%s line=%d match=%q", fs[1].RuleID, fs[1].Line, fs[1].Match)
			}
		})
	}
}

// TestCrossLineYuchoPairNegativeCases はペア検出が対象外とすべきケースを
// まとめて確認する。want が nil のケースは jp-yucho-account の検出ゼロを意味する
// （他ルールの単独行検出まで含めた完全一致は assertRules が行う）。
func TestCrossLineYuchoPairNegativeCases(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		// 記号のみ（隣接する番号行が無い）。
		{"記号のみ", "記号: 14030\n", nil}, // jp-pii-detector:ignore
		// 番号のみ（隣接する記号行が無い）。
		{"番号のみ", "番号: 12345671\n", nil}, // jp-pii-detector:ignore
		// 番号→記号の逆順は対象外（記号ラベル行を起点に、その直後の非空白行だけを
		// 番号ラベル行として調べるため、逆順ペアは走査対象に入らない）。
		{"順序逆", "番号: 12345671\n記号: 14030\n", nil}, // jp-pii-detector:ignore
		// 記号が "1" 始まりでない。CrossLineYuchoSymbolRe 自体が `1\d{3}0` を
		// 要求するためマッチしない。
		{"先頭1でない記号", "記号: 24040\n番号: 12345671\n", nil}, // jp-pii-detector:ignore
		// 形状は成立するが、記号 4 桁目が公式検査式と一致しない。
		{"検査数字不一致", "記号: 14040\n番号: 12345671\n", nil}, // jp-pii-detector:ignore
		// 番号が "1" 終わりでない。CrossLineYuchoNumberRe 自体が末尾 `1` を
		// 要求するためマッチしない。
		{"末尾1でない番号", "記号: 14030\n番号: 12345670\n", nil}, // jp-pii-detector:ignore
		// 番号が全桁同一のダミー値。記号の形状と検査数字は成立するが、
		// ValidCrossLineYuchoPair が AllSame を棄却する。
		{"AllSame", "記号: 12360\n番号: 1111111\n", nil}, // jp-pii-detector:ignore
		// 4 行以上離れたペア（間に空行 3 つ）は maxAdjacentLineGap（j-i<=3）を
		// 超えるため論理隣接とみなさない。
		{"4行以上離れたペア", "記号: 14030\n\n\n\n番号: 12345671\n", nil}, // jp-pii-detector:ignore
		// 値行（番号側）に ignore マーカー。CrossLineYuchoNumberRe は行全体を
		// アンカーするため、行末の何か（ignore マーカーを含む）でマッチしなく
		// なり、ペアとして成立しない。
		{"値行にignoreマーカー", "記号: 14030\n番号: 12345671 // jp-pii-detector:ignore\n", nil},
		// 「記号: 14030」の次行が「番号: 12345671 円」。CrossLineYuchoNumberRe は
		// 行全体をアンカーするため、値の後に何か（単位等）が付くとマッチしない
		// （円建て金額等との混同を避ける）。
		{"番号行に単位が付く", "記号: 14030\n番号: 12345671 円\n", nil}, // jp-pii-detector:ignore
		// 行末に許容するのはカンマ・読点 1 つまで。その後にさらに何かが
		// 続く行はフィールド行とみなさない。
		{"行末カンマの後に文字列", "\"記号\": \"14030\", x\n\"番号\": \"12345671\"\n", nil}, // jp-pii-detector:ignore
		// 「お客様番号」のような複合ラベルは、ゆうちょの番号ラベルとして
		// 扱わない（許容する前置語は ゆうちょ/通帳/貯金 のみ）。
		{"お客様番号ラベルは対象外", "記号: 14030\nお客様番号: 12345671\n", nil}, // jp-pii-detector:ignore
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanContent("f.txt", tt.content)
			assertRules(t, fs, tt.want...)
		})
	}
}
