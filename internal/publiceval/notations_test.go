package publiceval

import (
	"strings"
	"testing"
)

// 表記の分類ごとに陽性・陰性が揃い、未定義の分類を使っていないことを確かめる。
// form-word は誤検出型なので陰性だけでよい。
func TestNotationCasesCoverCategories(t *testing.T) {
	known := map[string]bool{}
	for _, c := range notationCategories {
		known[c] = true
	}
	pos, neg := map[string]int{}, map[string]int{}
	for _, c := range NotationCases() {
		cat := notationCategoryOf(c)
		if !known[cat] {
			t.Fatalf("%s: 未定義の分類 %q", c.ID, cat)
		}
		if !strings.HasPrefix(c.ID, "public-notation-"+cat+"-") {
			t.Fatalf("%s: ID と分類 %q が一致しない", c.ID, cat)
		}
		if len(c.Want) > 0 {
			pos[cat]++
		} else {
			neg[cat]++
		}
	}
	for _, cat := range notationCategories {
		if neg[cat] == 0 {
			t.Errorf("%s: 陰性ケースがない", cat)
		}
		if cat != "form-word" && pos[cat] == 0 {
			t.Errorf("%s: 陽性ケースがない", cat)
		}
	}
}
