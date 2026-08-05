package detect

import "testing"

// クロスライン氏名検出（person-name-structured）は、ラベル行とその直下 1 行の
// ペアしか見ていなかったため、
//
//	氏名:
//	山田太郎
//	佐藤花子
//	鈴木一郎
//
// のような名簿で先頭 1 件しか拾えず、かつ区切り記号（:/=）を伴わない
// 見出し行（`氏名` だけの行）はラベルとして認識できなかった。
// ここでは伝播（crossLineNameValues）と見出し行（CrossLineNameHeaderRe）を
// 確認する。

// TestCrossLineNameLabelPropagatesToAllValues は、ラベル直下から連続する
// 氏名行すべてが検出されることを確認する。
func TestCrossLineNameLabelPropagatesToAllValues(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	content := "氏名:\n山田太郎\n佐藤花子\n鈴木一郎\n"
	fs := d.ScanContent("form.txt", content)
	assertRules(t, fs, "person-name-structured", "person-name-structured", "person-name-structured")
	for i, want := range []int{2, 3, 4} {
		if fs[i].Line != want {
			t.Errorf("findings[%d].Line = %d, want %d", i, fs[i].Line, want)
		}
	}
}

// TestCrossLineNamePropagationStopsAtNonNameShape は、氏名の形をしていない行で
// 伝播が打ち切られることを確認する。ラベルの効果が無関係な後続セクションまで
// 伸びると、遠く離れた値が氏名として昇格してしまう。
func TestCrossLineNamePropagationStopsAtNonNameShape(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	content := "氏名:\n山田太郎\n\n備考: なし\n佐藤花子\n"
	fs := d.ScanContent("form.txt", content)
	assertRules(t, fs, "person-name-structured")
	if fs[0].Line != 2 {
		t.Errorf("line = %d, want 2", fs[0].Line)
	}
}

// TestCrossLineNamePropagationSkipsNonDictionaryLines は、氏名の形は満たすが
// 姓名辞書を通らない行（他のラベル語など）でも伝播が止まらないことを確認する。
// 辞書未収録の値が 1 行挟まっただけで名簿の残り全部を落とさないための挙動。
func TestCrossLineNamePropagationSkipsNonDictionaryLines(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	content := "氏名:\n山田太郎\n住所\n佐藤花子\n"
	fs := d.ScanContent("form.txt", content)
	assertRules(t, fs, "person-name-structured", "person-name-structured")
	for i, want := range []int{2, 4} {
		if fs[i].Line != want {
			t.Errorf("findings[%d].Line = %d, want %d", i, fs[i].Line, want)
		}
	}
}

// TestCrossLineNameHeaderWithoutSeparator は、区切り記号を伴わない見出し行
// （`氏名` だけの行）をラベルとして扱えることを確認する。CSV のヘッダセルが
// 区切りを持たないのと同じ構造が、プレーンテキストの名簿でも使われる。
func TestCrossLineNameHeaderWithoutSeparator(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	content := "氏名\n山田太郎\n佐藤花子\n"
	assertRules(t, d.ScanContent("roster.txt", content),
		"person-name-structured", "person-name-structured")
}

// TestCrossLineNameHeaderNeedsValidValue は、見出し行だけがあっても続く行が
// 氏名として妥当でなければ何も報告しないことを確認する。区切りを持たない
// 見出しは手がかりが弱いため、値側の辞書照合が唯一の歯止めになる。
func TestCrossLineNameHeaderNeedsValidValue(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	content := "氏名\n未定\n該当なし\n"
	assertRules(t, d.ScanContent("form.txt", content))
}

// TestCrossLineNameHeaderNotMatchedInsideMarkup は、Markdown の見出しや
// 表のセルが見出し行として誤認されないことを確認する（行全体アンカーのため
// 行頭の `#` やパイプがあると一致しない）。
func TestCrossLineNameHeaderNotMatchedInsideMarkup(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	for _, tt := range []struct{ name, content string }{
		{"Markdown 見出し", "## 氏名\n山田太郎\n"},
		{"箇条書き", "- 氏名\n山田太郎\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanContent("doc.md", tt.content))
		})
	}
}

// TestCrossLineNamePropagationRequiresHighRecall は、伝播・見出し行の両方が
// person-name-structured（高再現率限定）に帰属し、既定では出ないことを
// 確認する。
func TestCrossLineNamePropagationRequiresHighRecall(t *testing.T) {
	d := newDetector(t, "")
	assertRules(t, d.ScanContent("form.txt", "氏名:\n山田太郎\n佐藤花子\n"))
	assertRules(t, d.ScanContent("roster.txt", "氏名\n山田太郎\n佐藤花子\n"))
}

// TestHonorificWithSpaceBeforeSuffix は、氏名と敬称の間に空白が入る形
// （宛名書き・フォームで一般的）を敬称アンカーが拾えることを確認する。
// 空白入りは「対応 様」のようなテンプレート断片とも衝突するため、
// 姓+名の分割が成立する値だけを許可する。
func TestHonorificWithSpaceBeforeSuffix(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	tests := []struct {
		name, line string
		want       []string
	}{
		{"敬称前の空白", "鈴木一郎 様", []string{"person-name-high-recall"}},
		{"姓名間の空白", "山田 太郎様", []string{"person-name-high-recall"}},
		{"両方の空白", "山田 太郎 様", []string{"person-name-high-recall"}},
		// 辞書照合を必須にしたことで、空白を挟む日常語・テンプレート断片は
		// 従来どおり棄却される。
		{"テンプレート断片（対応 様）", "対応 様", nil},
		{"テンプレート断片（納品 殿）", "納品 殿", nil},
		{"分かち書き（新しい 仕様）", "新しい 仕様", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want...)
		})
	}
}
