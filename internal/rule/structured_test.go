package rule

import "testing"

// 値は埋め込み姓名辞書に含まれる一般的な氏名のリテラルを使う（外部フィクスチャ
// 不要・オフライン実行可能。dict/names_test.go と同じ方針）。
//
// ValidCrossLineName は姓+名の分割（FullNameSplit）かつ名成分 2 文字以上を
// 必須にする（issue #59 段階1）。単独の姓・名一致（渋谷・大和・本田のような
// 地名・企業名と同形の姓を含む）は、クロスライン検出の「次行＝値」前提が
// 同一行ほど強くないことを踏まえて許可しない。
func TestValidCrossLineName(t *testing.T) {
	valid := []string{"山田太郎", "山田 太郎"}
	for _, v := range valid {
		if !ValidCrossLineName(v) {
			t.Errorf("ValidCrossLineName(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"山田",       // 単独の姓一致（FullNameSplit ではない）
		"太郎",       // 単独の名一致（FullNameSplit ではない）
		"渋谷",       // 地名・企業名と同形の姓（単独一致）
		"株式会社",     // 組織名
		"山田商事株式会社", // 組織語尾
		"未定",       // プレースホルダ
		"該当なし",     // プレースホルダ（接尾辞付き）
		"プロジェクト",   // 辞書外の一般名詞
		"",         // 空
	}
	for _, v := range invalid {
		if ValidCrossLineName(v) {
			t.Errorf("ValidCrossLineName(%q) = true, want false", v)
		}
	}
}

func TestCrossLineNameRegexes(t *testing.T) {
	// 正規表現は正規化済みの行（全角コロン等は半角化済み）を前提とする。
	// 全角コロンの end-to-end は detect の統合テストで確認する。
	labelMatch := []string{"氏名:", "お名前:", "  full_name:  ", `"氏名":`, "氏名: 「"}
	for _, s := range labelMatch {
		if !CrossLineNameLabelRe.MatchString(s) {
			t.Errorf("CrossLineNameLabelRe should match %q", s)
		}
	}
	labelNoMatch := []string{
		"氏名: 山田太郎", // 値が同一行にある（クロスライン対象外）
		"姓:",       // 弱いラベルは対象外
		"備考:",      // 氏名ラベルではない
	}
	for _, s := range labelNoMatch {
		if CrossLineNameLabelRe.MatchString(s) {
			t.Errorf("CrossLineNameLabelRe should NOT match %q", s)
		}
	}

	valueMatch := map[string]string{
		"山田太郎":   "山田太郎",
		"  鈴木花子": "鈴木花子",
		`"田中一郎"`: "田中一郎",
		"山田 太郎":  "山田 太郎",
	}
	for in, want := range valueMatch {
		m := CrossLineNameValueRe.FindStringSubmatch(in)
		if m == nil || m[1] != want {
			t.Errorf("CrossLineNameValueRe(%q) group1 = %v, want %q", in, m, want)
		}
	}
	valueNoMatch := []string{"名: 山田", "山田太郎（備考）", ""}
	for _, s := range valueNoMatch {
		if CrossLineNameValueRe.MatchString(s) {
			t.Errorf("CrossLineNameValueRe should NOT match %q", s)
		}
	}
}
