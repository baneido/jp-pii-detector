package detect

import "testing"

// uuidGuardDetector は insideUUIDToken の判定だけを切り出して観測するための
// 検出器を返す。custom ルールは digit_boundary=false（既定）なので builtin の
// dg()/ag() 系境界ガードを経由せず、UUID ガードが効いたかどうかがそのまま
// 検出結果に現れる。
func uuidGuardDetector(t *testing.T) *Detector {
	t.Helper()
	return newDetector(t, `
[[rules.custom]]
id = "any-7-digits"
description = "UUID ガード判定テスト"
pattern = '\d{7}'
base_confidence = "high"
`)
}

// TestInsideUUIDTokenAcceptsRFC9562Versions は RFC 9562 が定義する
// バージョン 1〜8 の UUID（ハイフン形・コンパクト形）と、特別扱いの
// Nil/Max UUID が UUID トークンと判定されることを確認する。
// 以前はバージョン桁 '4' 固定だったため、DB 主キーとして普及した v7 などが
// 抑制されず誤検出の原因になっていた。
func TestInsideUUIDTokenAcceptsRFC9562Versions(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"v1 ハイフン形", "12345678-1234-1000-8000-123456789012"},
		{"v2 ハイフン形", "12345678-1234-2000-9000-123456789012"},
		{"v3 ハイフン形", "12345678-1234-3000-a000-123456789012"},
		{"v4 ハイフン形", "12345678-1234-4000-b000-123456789012"},
		{"v5 ハイフン形", "12345678-1234-5000-8000-123456789012"},
		{"v6 ハイフン形", "12345678-1234-6000-9000-123456789012"},
		{"v7 ハイフン形", "12345678-1234-7000-8000-123456789012"},
		{"v8 ハイフン形", "12345678-1234-8000-a000-123456789012"},
		{"v7 大文字", "12345678-1234-7ABC-8DEF-123456789012"},
		{"v1 コンパクト形", "12345678123410008000123456789012"},
		{"v7 コンパクト形", "12345678123470008000123456789012"},
		{"v8 コンパクト形", "1234567812348000a000123456789012"},
		{"Nil UUID", "00000000-0000-0000-0000-000000000000"},
		{"Nil UUID コンパクト形", "00000000000000000000000000000000"},
		{"Max UUID", "ffffffff-ffff-ffff-ffff-ffffffffffff"},
		{"Max UUID 大文字", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// トークン全体および内部の任意区間が UUID 内部と判定されること。
			if !insideUUIDToken(tt.token, 0, len(tt.token)) {
				t.Fatalf("insideUUIDToken(%q, 全体) = false, want true", tt.token)
			}
			if !insideUUIDToken(tt.token, 1, 5) {
				t.Fatalf("insideUUIDToken(%q, 内部区間) = false, want true", tt.token)
			}
		})
	}
}

// TestInsideUUIDTokenRejectsNonUUIDShapes は UUID の形状（長さ・ハイフン位置・
// バージョン桁・バリアント桁）を満たさない hex 列を UUID とみなさないことを
// 確認する。バージョン許容範囲を広げても形状チェックの選択性は維持する、という
// 方針の回帰テスト。緩めすぎると「UUID に似ただけの hex 列」に埋まった本物の
// PII を取りこぼす。
func TestInsideUUIDTokenRejectsNonUUIDShapes(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"バージョン桁 0（Nil ではない）", "12345678-1234-0000-8000-123456789012"},
		{"バージョン桁 9（未定義）", "12345678-1234-9000-8000-123456789012"},
		{"バージョン桁 e（未定義）", "12345678-1234-e000-8000-123456789012"},
		{"バージョン桁 f（Max ではない）", "12345678-1234-f000-8000-123456789012"},
		{"バリアント桁が RFC 変種でない（0）", "12345678-1234-7000-0000-123456789012"},
		{"バリアント桁が RFC 変種でない（c）", "12345678-1234-7000-c000-123456789012"},
		{"ハイフン位置が違う", "1234567-81234-7000-8000-1234567890123"},
		{"ハイフンが足りない", "123456781234-7000-8000-1234567890129999"},
		{"長さが 35", "12345678-1234-7000-8000-12345678901"},
		{"長さが 37", "12345678-1234-7000-8000-1234567890123"},
		{"コンパクト形で 31 桁", "1234567812347000800012345678901"},
		{"コンパクト形で 33 桁", "123456781234700080001234567890123"},
		{"単なる数字列", "1234567"},
		{"Nil に 1 桁だけ非 0 が混じる", "00000000-0000-0000-0000-000000000001"},
		{"Max に 1 桁だけ非 f が混じる", "ffffffff-ffff-ffff-ffff-fffffffffff0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if insideUUIDToken(tt.token, 0, len(tt.token)) {
				t.Fatalf("insideUUIDToken(%q) = true, want false", tt.token)
			}
		})
	}
}

// TestUUIDVersionsWithPIIContextSuppressed は PII 文脈語（口座番号: 等）の
// 直後に置かれた各バージョンの UUID でも、内部の数字列が検出されず
// uuid-token として棄却されることを確認する。
func TestUUIDVersionsWithPIIContextSuppressed(t *testing.T) {
	tests := []struct {
		name, line string
	}{
		{"v1 口座番号文脈", "口座番号: 12345678-1234-1000-8000-123456789012"},
		{"v4 口座番号文脈", "口座番号: 12345678-1234-4000-8000-123456789012"},
		{"v7 口座番号文脈", "口座番号: 12345678-1234-7000-8000-123456789012"},
		{"v8 口座番号文脈", "口座番号: 12345678-1234-8000-8000-123456789012"},
		{"v7 マイナンバー文脈", "マイナンバー: 12345678-1234-7000-b000-123456789012"},
		{"v7 郵便番号文脈", "郵便番号: 12345678-1234-7000-9000-123456789012"},
		{"v7 コンパクト形の口座番号文脈", "口座番号: 12345678123470008000123456789012"},
		{"Nil UUID の口座番号文脈", "口座番号: 00000000-0000-0000-0000-000000000000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := uuidGuardDetector(t)
			d.CollectDropped(true)
			assertRules(t, d.ScanLine("f.txt", 1, tt.line))
			dropped := d.TakeDropped()
			if _, ok := findDropped(dropped, "any-7-digits", DropReasonUUIDToken); !ok {
				t.Fatalf("uuid-token が記録されていない: %+v", dropped)
			}
		})
	}
}

// TestNonUUIDShapedTokensStillDetected は UUID 形状でないトークン内部の
// 数字列は従来どおり検出されることを確認する（ガードの緩めすぎ検知）。
func TestNonUUIDShapedTokensStillDetected(t *testing.T) {
	tests := []struct {
		name, line string
	}{
		{"バージョン桁が未定義（9）", "口座番号: 12345678-1234-9000-8000-123456789012"},
		{"バリアント桁が RFC 変種でない", "口座番号: 12345678-1234-7000-0000-123456789012"},
		{"ハイフン位置が違う", "口座番号: 1234567-81234-7000-8000-1234567890123"}, // jp-pii-detector:ignore
		{"単なる数字列", "口座番号: 1234567"},                                  // jp-pii-detector:ignore
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := uuidGuardDetector(t)
			// 1 行に複数の数字列が含まれる場合は件数が可変なので、
			// 「1 件以上検出される」ことだけを確認する。
			fs := d.ScanLine("f.txt", 1, tt.line)
			if len(fs) == 0 {
				t.Fatalf("findings = %v, want any-7-digits を 1 件以上", ruleIDs(fs))
			}
			for _, f := range fs {
				if f.RuleID != "any-7-digits" {
					t.Fatalf("findings = %v, want any-7-digits のみ", ruleIDs(fs))
				}
			}
		})
	}
}

// TestBuiltinRulesSuppressUUIDv7BankAccountShape は報告された誤検出
// （UUIDv7 の第 1 グループが口座番号として jp-bank-account 判定される）が
// builtin ルール一式でも再発しないことを確認する。v4 形（既存挙動）も
// あわせて 0 件のままであることを確認する。
func TestBuiltinRulesSuppressUUIDv7BankAccountShape(t *testing.T) {
	d := newDetector(t, "")
	lines := []string{
		"口座番号: a1234567-bbbb-7abc-8def-123456789abc",
		"口座番号: a1234567-bbbb-4abc-8def-123456789abc",
		"口座番号: a1234567-bbbb-1abc-8def-123456789abc",
		"口座番号: a1234567-bbbb-8abc-8def-123456789abc",
		"口座番号: a1234567bbbb7abc8def123456789abc",
	}
	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, line))
		})
	}
}
