package rule

import "testing"

// 値は埋め込み姓名辞書に含まれる一般的な氏名のリテラルを使う（外部フィクスチャ
// 不要・オフライン実行可能。dict/names_test.go と同じ方針）。
func TestValidCrossLineName(t *testing.T) {
	valid := []string{"山田太郎", "山田 太郎", "山田", "太郎"}
	for _, v := range valid {
		if !ValidCrossLineName(v) {
			t.Errorf("ValidCrossLineName(%q) = false, want true", v)
		}
	}
	invalid := []string{
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

// CSVNameHeaderRe / CSVNameValueRe は CSV/TSV のヘッダ・データ行の 1 フィールド
// 本文全体をアンカーする（CrossLineNameLabelRe/ValueRe と違い区切り記号
// `:`/`=` や引用符・括弧は伴わない。フィールド分割は internal/detect の
// splitCSVLine が既に引用符を剥がした本文を渡す前提）。
func TestCSVNameRegexes(t *testing.T) {
	headerMatch := []string{"氏名", "お名前", "姓名", "フリガナ", "full_name", "customer_name"}
	for _, s := range headerMatch {
		if !CSVNameHeaderRe.MatchString(s) {
			t.Errorf("CSVNameHeaderRe should match %q", s)
		}
	}
	headerNoMatch := []string{
		"郵便番号", // 氏名系ラベルではない
		"口座番号",
		"氏名:",  // 区切り記号は伴わない（ヘッダセルはラベル語そのもの）
		"氏名メモ", // 複合語の一部は列全体アンカーで除外
		"",
	}
	for _, s := range headerNoMatch {
		if CSVNameHeaderRe.MatchString(s) {
			t.Errorf("CSVNameHeaderRe should NOT match %q", s)
		}
	}

	valueMatch := map[string]string{
		"山田太郎":   "山田太郎",
		"山田 太郎":  "山田 太郎",
		" 鈴木花子 ": "鈴木花子",
	}
	for in, want := range valueMatch {
		m := CSVNameValueRe.FindStringSubmatch(in)
		if m == nil || m[1] != want {
			t.Errorf("CSVNameValueRe(%q) group1 = %v, want %q", in, m, want)
		}
	}
	valueNoMatch := []string{"100-0001", "1234567", ""}
	for _, s := range valueNoMatch {
		if CSVNameValueRe.MatchString(s) {
			t.Errorf("CSVNameValueRe should NOT match %q", s)
		}
	}
}
