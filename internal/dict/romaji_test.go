package dict

import "testing"

// TestRomajiOriginalFormsStillMatch は、辞書に実在するワープロ式ローマ字表記
// （長音符を "u" のまま綴る表記）が、派生形の追加後も引き続き一致することを
// 確認する。tarou は romaji_given_names.txt、saitou / yamada は
// romaji_surnames.txt に実在する（grep 確認済み）。
func TestRomajiOriginalFormsStillMatch(t *testing.T) {
	if !IsRomajiGivenName("tarou") {
		t.Error(`IsRomajiGivenName("tarou") = false, want true`)
	}
	if !IsRomajiSurname("saitou") {
		t.Error(`IsRomajiSurname("saitou") = false, want true`)
	}
	if !IsRomajiSurname("yamada") {
		t.Error(`IsRomajiSurname("yamada") = false, want true`)
	}
}

// TestRomajiLongVowelDropVariants は、長音省略ヘボン式（パスポート・
// クレジットカード・メール署名等で標準の表記）の派生形が読み込み時に
// 機械生成され、辞書に併録されていることを確認する。元エントリ
// tarou・saitou・itou・yuuki・oono はいずれも辞書に実在する（grep 確認済み）。
func TestRomajiLongVowelDropVariants(t *testing.T) {
	tests := []struct {
		name  string
		check func(string) bool
		value string
		from  string // 参考: 元になった実在エントリ
	}{
		{"taro from tarou (given)", IsRomajiGivenName, "taro", "tarou"},
		{"saito from saitou (surname)", IsRomajiSurname, "saito", "saitou"},
		{"ito from itou (surname)", IsRomajiSurname, "ito", "itou"},
		{"yuki from yuuki (surname)", IsRomajiSurname, "yuki", "yuuki"},
		{"ono from oono (surname)", IsRomajiSurname, "ono", "oono"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.check(tt.value) {
				t.Errorf("%q (derived from %q) not found in dictionary, want true", tt.value, tt.from)
			}
		})
	}
}

// TestRomajiOhFormVariants は OH 表記（大野→Ohno、佐藤→Satoh、伊藤→Itoh の
// ような、直後が子音または語末の場合の "ou"/"oo"→"oh" 置換）の派生形が
// 辞書に併録されていることを確認する。元エントリ oono・satou・itou は
// いずれも romaji_surnames.txt に実在する（grep 確認済み）。
func TestRomajiOhFormVariants(t *testing.T) {
	tests := []struct {
		value string
		from  string
	}{
		{"ohno", "oono"},
		{"satoh", "satou"},
		{"itoh", "itou"},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if !IsRomajiSurname(tt.value) {
				t.Errorf("IsRomajiSurname(%q) (derived from %q) = false, want true", tt.value, tt.from)
			}
		})
	}
}

// TestRomajiUnknownSpellingNotMatched は、辞書に実在しない綴りが派生形生成の
// 副作用で誤って true にならないことを確認する。
func TestRomajiUnknownSpellingNotMatched(t *testing.T) {
	if IsRomajiSurname("tarot") {
		t.Error(`IsRomajiSurname("tarot") = true, want false`)
	}
	if IsRomajiGivenName("tarot") {
		t.Error(`IsRomajiGivenName("tarot") = true, want false`)
	}
}

// TestRomajiIiNotShortened は、"ii" を含む語が長音省略の対象にならない
// （"ii"→"i" への誤短縮が起きない）ことを確認する。fujii は
// romaji_surnames.txt に実在する（grep 確認済み）。派生生成の対象は
// "ou"/"oo"/"uu" のみで "ii" は含まないため、fujii 自体は変化せず、
// 誤短縮形の "fuji" が新たに派生することもない。
func TestRomajiIiNotShortened(t *testing.T) {
	if !IsRomajiSurname("fujii") {
		t.Error(`IsRomajiSurname("fujii") = false, want true (original form must survive)`)
	}
	if got := romajiDropLongVowel("fujii"); got != "fujii" {
		t.Errorf(`romajiDropLongVowel("fujii") = %q, want "fujii" (unchanged; "ii" is not a drop pattern)`, got)
	}
	if _, ok := romajiOhForm("fujii"); ok {
		t.Error(`romajiOhForm("fujii") returned ok=true, want false (no "ou"/"oo" present)`)
	}
}

// TestRomajiEiNotShortened は "ei" を含む語も長音省略の対象にならないことを
// 確認する。eiko は romaji_given_names.txt に実在する（grep 確認済み）。
func TestRomajiEiNotShortened(t *testing.T) {
	if !IsRomajiGivenName("eiko") {
		t.Error(`IsRomajiGivenName("eiko") = false, want true (original form must survive)`)
	}
	if got := romajiDropLongVowel("eiko"); got != "eiko" {
		t.Errorf(`romajiDropLongVowel("eiko") = %q, want "eiko" (unchanged; "ei" is not a drop pattern)`, got)
	}
}

// TestRomajiDropLongVowel は romajiDropLongVowel の変換規則を直接検証する
// （単一箇所・複数箇所・非該当のケース）。
func TestRomajiDropLongVowel(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"tarou", "taro"},
		{"saitou", "saito"},
		{"itou", "ito"},
		{"yuuki", "yuki"},
		{"oono", "ono"},
		{"koutarou", "kotaro"}, // 複数箇所含む語は一括で全置換した1形になる
		{"yamada", "yamada"},   // 該当パターンなしは無変化
		{"keiichi", "keiichi"}, // "ei"・"ii" は対象外
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := romajiDropLongVowel(tt.in); got != tt.want {
				t.Errorf("romajiDropLongVowel(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestRomajiOhFormRule は romajiOhForm の変換規則を直接検証する。直後が母音の
// 場合は誤読形になるため生成しないこと、"uu" は対象外であることを含む。
func TestRomajiOhFormRule(t *testing.T) {
	tests := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"oono", "ohno", true},
		{"satou", "satoh", true},
		{"itou", "itoh", true},
		{"yuuki", "", false},   // "uu" は OH 表記の対象外
		{"yamada", "", false},  // 該当パターンなし
		{"kouichi", "", false}, // "ou" の直後が母音（i）なので生成しない
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, ok := romajiOhForm(tt.in)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("romajiOhForm(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
