//go:build cgo && ort

package model

import "testing"

// TestOpenRecognizesWithRealModel は実モデル（JP_PII_MODEL_DIR）で、自由文中の
// 氏名・電話番号・住所がマーカーなしで候補になることを確かめる。
func TestOpenRecognizesWithRealModel(t *testing.T) {
	r, err := Open(modelDirForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	text := "昨日佐藤花子から連絡があり、来週の打ち合わせは延期になった。\n" +
		"折り返しは070-4412-9903までお願いします。\n" + // jp-pii-detector:ignore
		// 都道府県のない「渋谷区神南1-2-3」は、この 3 行の文脈では確率 0.499 で
		// 閾値 0.5 を下回る（Python 版の Sumi でも同じ値）。閾値の校正は未実施。
		"荷物は福岡県福岡市博多区博多駅前2-1-1宛てに送ってください。\n" // jp-pii-detector:ignore
	got, err := r.Recognize(text)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got {
		t.Logf("%+v %q", c, string([]rune(splitLine(text, c.Line))[c.Column-1:c.Column-1+c.Length]))
	}
	want := map[string]int{"person-name": 1, "jp-phone-number": 2, "jp-address": 3}
	for id, line := range want {
		found := false
		for _, c := range got {
			found = found || (c.RuleID == id && c.Line == line)
		}
		if !found {
			t.Errorf("%s（%d 行目）が候補にない", id, line)
		}
	}
}

func splitLine(text string, line int) string {
	n := 1
	start := 0
	for i, r := range text {
		if r == '\n' {
			if n == line {
				return text[start:i]
			}
			n++
			start = i + 1
		}
	}
	return text[start:]
}
