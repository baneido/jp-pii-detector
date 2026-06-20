package dict

import "testing"

func TestValidPostalCodePrefix(t *testing.T) {
	tests := []struct {
		code string
		want bool
	}{
		{"150-0043", true},
		{"〒530-0001", true},
		{"000-0000", false},
		{"150-004", false},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			if got := ValidPostalCodePrefix(tt.code); got != tt.want {
				t.Errorf("ValidPostalCodePrefix(%q) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

// ValidPostalCode は埋め込みビットセットが未生成（プレースホルダ）のときは
// 上位 3 桁実在チェックへフォールバックする。生成済みなら 7 桁完全一致になる。
func TestValidPostalCode(t *testing.T) {
	tests := []struct {
		code string
		want bool
	}{
		{"150-0043", true},  // 上位 3 桁 150 は実在
		{"〒530-0001", true}, // 〒・ハイフンを除去して 7 桁判定
		{"5300001", true},
		{"000-0000", false}, // 上位 3 桁 000 は不在
		{"150-004", false},  // 6 桁は対象外
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			if got := ValidPostalCode(tt.code); got != tt.want {
				t.Errorf("ValidPostalCode(%q) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

// postalToIndex は 7 桁数字をビットセットのインデックスへ変換する。
func TestPostalToIndex(t *testing.T) {
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
		if got := postalToIndex(tt.digits); got != tt.want {
			t.Errorf("postalToIndex(%q) = %d, want %d", tt.digits, got, tt.want)
		}
	}
}

// postalInBitset は 7 桁完全一致のビット照合ロジック（埋め込みデータから独立）。
// 手作りのビットセットで、存在する番号だけが一致することを確認する。
func TestPostalInBitset(t *testing.T) {
	bitset := make([]byte, postalBitsetSize)
	present := []string{"1000001", "5300001", "9999999"}
	for _, d := range present {
		n := postalToIndex(d)
		bitset[n>>3] |= 1 << (n & 7)
	}
	for _, d := range present {
		if !postalInBitset(bitset, d) {
			t.Errorf("postalInBitset(%q) = false, want true", d)
		}
	}
	for _, d := range []string{"1000002", "5300000", "0000000", "1500043"} {
		if postalInBitset(bitset, d) {
			t.Errorf("postalInBitset(%q) = true, want false", d)
		}
	}
}
