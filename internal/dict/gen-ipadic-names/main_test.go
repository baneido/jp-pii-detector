package main

import (
	"reflect"
	"testing"
)

func TestSelectFiltersHomographsAndShapes(t *testing.T) {
	baseSurnames := map[string]bool{"山田": true}
	baseGiven := map[string]bool{"太郎": true, "夏樹": true}
	surnames, given := Select(baseSurnames, baseGiven,
		[]string{"山田", "足立", "上", "夏樹", "あらき", "勅使河原", "足立"},
		[]string{"太郎", "とき江", "みな", "マコト", "尊", "足立", "康弘"})
	if want := []string{"勅使河原", "足立"}; !reflect.DeepEqual(surnames, want) {
		t.Errorf("surnames = %q, want %q", surnames, want)
	}
	if want := []string{"とき江", "康弘"}; !reflect.DeepEqual(given, want) {
		t.Errorf("given = %q, want %q", given, want)
	}
}

func TestSelectAcceptsConnectorSurnames(t *testing.T) {
	surnames, _ := Select(map[string]bool{}, map[string]bool{},
		[]string{"松ヶ崎", "松ケ崎", "一ノ関", "ケ田", "田ノ", "一ノ瀬ノ", "あ木"}, nil)
	if want := []string{"一ノ関", "松ケ崎"}; !reflect.DeepEqual(surnames, want) {
		t.Errorf("surnames = %q, want %q", surnames, want)
	}
}

func TestCommonWordShape(t *testing.T) {
	for w, want := range map[string]bool{"別紙": true, "参照": true, "です": true, "カナ": true, "未入力": true,
		"あいうえお": false, "AB": false, "東京都庁舎": false, "": false, "一ノ関": true} {
		if got := CommonWordShape(w); got != want {
			t.Errorf("CommonWordShape(%q) = %v, want %v", w, got, want)
		}
	}
}

func TestPlaceStemsAndWithoutCommon(t *testing.T) {
	stems := PlaceStems(map[string]bool{"横浜市神奈川区": true, "八王子市": true, "石狩郡当別町": true, "北区": true})
	for _, w := range []string{"横浜", "神奈川", "八王子", "石狩", "当別", "東京", "北海"} {
		if !stems[w] {
			t.Errorf("PlaceStems に %q が無い", w)
		}
	}
	if stems["北"] {
		t.Error("1 文字の語幹は含めない")
	}
	stems["別紙"] = true
	// 千葉は「千葉県」として都道府県名に当たるので、語幹の一覧に無くても除く。
	got := withoutCommon([]string{"上増田", "八王子", "千葉", "別紙", "伊佐山"}, stems)
	if want := []string{"上増田", "伊佐山"}; !reflect.DeepEqual(got, want) {
		t.Errorf("withoutCommon = %q, want %q", got, want)
	}
}
