package dict

import "testing"

func TestMunicipalitySuffixMatch(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		// 実在する市区町村（都道府県プレフィックスあり・なし両方）。
		{"東京都渋谷区渋谷2-1-1", true},
		{"渋谷区渋谷2-1-1", true},
		// 政令指定都市の区（市＋区連結）と、市単独形の両方を照合できる。
		{"神奈川県川崎市川崎区小島町2-10-7", true},
		{"さいたま市大宮区", true},
		{"さいたま市で開催", true}, // 市単独形も併録されている
		// 郡付きの正式表記と、郡を省いた省略形の両方を照合できる。
		{"北海道石狩郡当別町１番地", true},
		{"当別町１番地", true},
		// 郡の字を含むが郡区分ではない市名（小郡市・郡山市等）を郡と誤認しない。
		{"福岡県小郡市", true},
		{"福島県郡山市", true},
		// ヶ/ケ の表記ゆれはどちらでも一致する。
		{"神奈川県鎌ケ谷市", true},
		{"神奈川県鎌ヶ谷市", true},
		// 実在しない市区町村名は棄却する（「通学区」は一般語で辞書に存在しない）。
		{"通学区域は3丁目まで", false},
		{"架空区にある建物", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := MunicipalitySuffixMatch(tt.in); got != tt.want {
				t.Errorf("MunicipalitySuffixMatch(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeMunicipalityKa(t *testing.T) {
	tests := []struct{ in, want string }{
		{"鎌ヶ谷市", "鎌ケ谷市"},
		{"鎌ケ谷市", "鎌ケ谷市"},
		{"渋谷区", "渋谷区"},
	}
	for _, tt := range tests {
		if got := NormalizeMunicipalityKa(tt.in); got != tt.want {
			t.Errorf("NormalizeMunicipalityKa(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestMunicipalitiesDictSanity は municipalities.txt の件数が現実的な範囲にあり、
// 空行・重複がないことを保証する（生成物の破損・切り詰めの検知）。
func TestMunicipalitiesDictSanity(t *testing.T) {
	if len(municipalities) < 1800 {
		t.Errorf("municipalities count = %d, want >= 1800 (municipalities.txt が壊れているか切り詰められている可能性)", len(municipalities))
	}
	if len(municipalities) > 4000 {
		t.Errorf("municipalities count = %d, want <= 4000", len(municipalities))
	}
	for m := range municipalities {
		if m == "" {
			t.Error("municipalities に空文字列のエントリがある")
		}
	}
}
