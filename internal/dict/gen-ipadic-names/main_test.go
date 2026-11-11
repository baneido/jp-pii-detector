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
