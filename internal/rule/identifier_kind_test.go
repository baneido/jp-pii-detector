package rule

import "testing"

// このファイルは適格請求書発行事業者登録番号ルール（jp-invoice-number）の検出値を
// 下位種別に分類する PublicBusinessKind（identifier_kind.go）のテスト。
// PublicBusinessKind は match の中身を見ずに常に "public-business" を返す定数分類のため、
// 実在の登録番号らしい検査用数字である必要はない。"T0000000000000" は形は T+13桁だが
// 全桁同一のため checksum.CorporateNumber（internal/checksum）の AllSame 判定で必ず
// 棄却される、明らかなダミー値（他の rule テストと同じ方針）。
func TestPublicBusinessKind(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"T+13桁の形をした値", "T0000000000000"},
		{"空文字列", ""},
		{"登録番号の形をしていない任意の値", "not-an-invoice-number"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PublicBusinessKind(tt.in); got != "public-business" {
				t.Errorf("PublicBusinessKind(%q) = %q, want %q", tt.in, got, "public-business")
			}
		})
	}
}
