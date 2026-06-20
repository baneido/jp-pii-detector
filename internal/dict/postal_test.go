package dict

import "testing"

// ValidPostalCode は 7 桁完全一致で判定する（上位 3 桁の一致では通さない）。
func TestValidPostalCode(t *testing.T) {
	tests := []struct {
		code string
		want bool
	}{
		{"150-0043", true},  // 渋谷区道玄坂（実在）
		{"〒530-0001", true}, // 大阪市北区梅田（〒・ハイフンを除去して 7 桁判定）
		{"5300001", true},
		{"000-0000", false}, // 非実在
		{"150-004", false},  // 6 桁は対象外
		{"12345678", false}, // 8 桁は対象外
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			if got := ValidPostalCode(tt.code); got != tt.want {
				t.Errorf("ValidPostalCode(%q) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

// 埋め込みビットセットが規定サイズ（1,250,000 バイト）であること。サイズが狂うと
// インデックス計算と整合せず検出が崩れるため回帰ガードする（gen の出力検証も同じ定数）。
func TestEmbeddedBitsetSize(t *testing.T) {
	if len(postalBitset) != PostalBitsetSize {
		t.Fatalf("postalBitset size = %d, want %d（internal/dict/gen で再生成してください）",
			len(postalBitset), PostalBitsetSize)
	}
}

func TestPostalCodeIndex(t *testing.T) {
	tests := []struct {
		digits string
		want   uint32
	}{
		{"0000000", 0},
		{"1000001", 1000001},
		{"5300001", 5300001},
		{"9999999", 9999999},
	}
	for _, tt := range tests {
		if got := PostalCodeIndex(tt.digits); got != tt.want {
			t.Errorf("PostalCodeIndex(%q) = %d, want %d", tt.digits, got, tt.want)
		}
	}
}

// 7 桁完全一致のビット照合ロジック（埋め込みデータから独立）。同じ上位 3 桁でも
// 7 桁が異なれば一致しないこと（prefix 一致では通さない）を手作りのビットセットで確認する。
func TestPostalInBitset(t *testing.T) {
	bitset := make([]byte, PostalBitsetSize)
	for _, d := range []string{"1500043", "5300001"} {
		n := PostalCodeIndex(d)
		bitset[n>>3] |= 1 << (n & 7)
	}
	if !postalInBitset(bitset, "1500043") {
		t.Error("1500043 should be present")
	}
	// 上位 3 桁 150 は登録済みだが 1509999 は別の 7 桁なので一致しない。
	if postalInBitset(bitset, "1509999") {
		t.Error("1509999 should not match (only prefix 150 is shared)")
	}
	if postalInBitset(bitset, "0000000") {
		t.Error("0000000 should not match")
	}
}
