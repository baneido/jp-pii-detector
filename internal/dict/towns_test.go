package dict

import "testing"

// TestTownPrefixMatch は、実在する町字名（ABR 町字マスター由来）との前方一致、
// 最長一致優先、ヶ/ケ表記ゆれの正規化、非実在語の不一致を確認する。
func TestTownPrefixMatch(t *testing.T) {
	tests := []struct {
		in        string
		wantMatch string // "" なら ok=false を期待
	}{
		// スポットチェック 4 件（実在する著名な町字名）。
		{"神南1丁目2番3号", "神南"},
		{"丸の内2-1-5", "丸の内"},
		{"霞が関3-2-1", "霞が関"},
		{"大手町タワー", "大手町"},
		// 最長一致優先: 「美しが丘」「美しが丘西」がともに実在するとき、
		// より長い方を採用する。
		{"美しが丘西1-2-3", "美しが丘西"},
		{"美しが丘1-2-3", "美しが丘"},
		// ヶ/ケ の表記ゆれはどちらでも一致する（辞書は正規化済みの「ケ」で
		// 収録、入力側は「ヶ」でも NormalizeMunicipalityKa で揃う）。切り出す
		// 部分文字列は正規化前の元テキストからなので、入力が「ヶ」であれば
		// 「ヶ」のまま返る（ヶ→ケ は 1 ルーン = 1 ルーンでバイト長を変えない
		// ため、長さの計算だけ「ケ」表記のバイト長と一致する）。
		{"桜ケ丘1-2-3", "桜ケ丘"},
		{"桜ヶ丘1-2-3", "桜ヶ丘"},
		// 非実在語は不一致（通学区域のような一般語、辞書外の集合住宅名等）。
		{"通学区域は3丁目まで", ""},
		{"ニュータウン1-1-1", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			gotLen, ok := TownPrefixMatch(tt.in)
			if tt.wantMatch == "" {
				if ok {
					t.Errorf("TownPrefixMatch(%q) = (%d, true), want ok=false", tt.in, gotLen)
				}
				return
			}
			if !ok {
				t.Fatalf("TownPrefixMatch(%q) = (_, false), want match %q", tt.in, tt.wantMatch)
			}
			if gotLen != len(tt.wantMatch) {
				t.Errorf("TownPrefixMatch(%q) matchLen = %d, want %d (%q)", tt.in, gotLen, len(tt.wantMatch), tt.wantMatch)
			}
			if got := tt.in[:gotLen]; got != tt.wantMatch {
				t.Errorf("TownPrefixMatch(%q) matched substring = %q, want %q", tt.in, got, tt.wantMatch)
			}
		})
	}
}

// TestTownPrefixMatchSingleCharacterExcluded は、北海道の開拓地割由来の
// 1 文字だけの町字名（"上" "新" 等、内部データには実在する）が
// TownPrefixMatch では対象外になっていることを確認する。1 文字の町字名は
// ありふれた書き出しの語（「新製品」「上司」等）へ偶然前方一致しやすく、
// 昇格専用エビデンスとしての精度を損なうため internal/dict/gen/towns.go の
// 生成時に除外している（isCleanTownName の townMinRuneLen）。
func TestTownPrefixMatchSingleCharacterExcluded(t *testing.T) {
	tests := []string{"新製品について", "上長に相談", "中身を確認"}
	for _, in := range tests {
		if _, ok := TownPrefixMatch(in); ok {
			t.Errorf("TownPrefixMatch(%q) = true, want false（1 文字町字名への偶然一致は除外されているはず）", in)
		}
	}
}

// TestMunicipalityThenTownMatch は、市区町村マッチ直後のギャップが実在町字名で
// 始まる場合だけ true を返すことを確認する（jp-address-high-recall の昇格専用
// Validate、MunicipalityThenTownMatch が使う判定基準そのもの）。
func TestMunicipalityThenTownMatch(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		// 実在する市区町村 + 実在する町字名。
		{"渋谷区神南1丁目2番3号", true}, // jp-pii-detector:ignore
		{"渋谷区渋谷2-1-1", true},   // jp-pii-detector:ignore
		{"千代田区大手町1-1-1", true}, // jp-pii-detector:ignore
		{"千代田区霞が関3-2-1", true}, // jp-pii-detector:ignore
		// 都道府県プレフィックスがあっても同様に判定できる。
		{"東京都渋谷区神南1丁目2番3号", true}, // jp-pii-detector:ignore
		// 実在する市区町村だが、続く語が実在町字名でない
		// （MunicipalitySuffixMatch 単体なら true になる状況でも false）。
		{"渋谷区ニュータウン1-1-1", false}, // jp-pii-detector:ignore
		// 市区町村自体が実在しない。
		{"通学区域は3丁目まで", false},
		{"架空区にある建物", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := MunicipalityThenTownMatch(tt.in); got != tt.want {
				t.Errorf("MunicipalityThenTownMatch(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestTownsDictSanity は towns.txt の件数が現実的な範囲にあり、空エントリ・
// 1 文字エントリ・許可されていない文字種のエントリがないことを保証する
// （生成物の破損・切り詰め・フィルタ漏れの検知。TestMunicipalitiesDictSanity と
// 同じ方針）。
func TestTownsDictSanity(t *testing.T) {
	if len(towns) < 50000 {
		t.Errorf("towns count = %d, want >= 50000（towns.txt が壊れているか切り詰められている可能性）", len(towns))
	}
	if len(towns) > 300000 {
		t.Errorf("towns count = %d, want <= 300000", len(towns))
	}
	for name := range towns {
		if name == "" {
			t.Fatal("towns に空文字列のエントリがある")
		}
		rs := []rune(name)
		if len(rs) < 2 {
			t.Errorf("towns に 1 文字のエントリがある（除外されているはず）: %q", name)
		}
		for _, r := range rs {
			switch {
			case r >= 0x4E00 && r <= 0x9FFF, r == 0x3005: // 漢字 + 々
			case r >= 0x3041 && r <= 0x3096: // ひらがな
			case r >= 0x30A1 && r <= 0x30FA, r == 0x30FC, r == 0x3099, r == 0x309A: // カタカナ + ー + 濁点半濁点
			case r >= '0' && r <= '9', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z': // 半角英数字
			default:
				t.Errorf("towns のエントリ %q に許可されていない文字 %q (%U) が含まれる", name, r, r)
			}
		}
		if name != NormalizeMunicipalityKa(name) {
			t.Errorf("towns のエントリ %q が ヶ→ケ 正規化済みでない", name)
		}
	}
}
