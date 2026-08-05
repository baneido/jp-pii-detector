package detect

import "testing"

// Markdown のパイプテーブルは日本語ドキュメントで名簿・連絡先一覧を書く
// 最頻の形のひとつだが、csv_context.go の列コンテキストが .csv/.tsv 限定
// だったため、ヘッダ直下の 1 行すら検出できていなかった。ここでは
// markdown_table.go が CSV と同じ「ヘッダセルのラベルを同じ列の全データ行へ
// 配る」機構を提供することを確認する。

const markdownHighRecallTOML = `
[rules]
high_recall = true
`

// TestMarkdownTableNameColumnAllRows は氏名列の全データ行が検出されることを
// 確認する。隣接行ペア（±1 行）だけではヘッダ直下の 1 行しか救えないため、
// 3 行目以降が拾えるかどうかが列コンテキストの有無をそのまま表す。
func TestMarkdownTableNameColumnAllRows(t *testing.T) {
	d := newDetector(t, markdownHighRecallTOML)
	content := "# 参加者\n\n| 氏名 | 部署 |\n|---|---|\n| 山田太郎 | 営業部 |\n| 佐藤花子 | 開発部 |\n| 鈴木一郎 | 総務部 |\n"
	fs := d.ScanContent("roster.md", content)
	assertRules(t, fs, "person-name-structured", "person-name-structured", "person-name-structured")
	wantLines := []int{5, 6, 7}
	for i, f := range fs {
		if f.Line != wantLines[i] {
			t.Errorf("findings[%d].Line = %d, want %d", i, f.Line, wantLines[i])
		}
	}
}

// TestMarkdownTableColumnContextForOtherRules は、氏名以外のルールにも
// 列コンテキストが効くことを確認する（既定で有効）。口座番号は
// RequireContext のため、列ラベルが届かなければ検出されない。
func TestMarkdownTableColumnContextForOtherRules(t *testing.T) {
	d := newDetector(t, "")
	content := "| 会社名 | 口座番号 |\n|---|---|\n| A商事 | 1234567 |\n| B工業 | 7654321 |\n"
	fs := d.ScanContent("accounts.md", content)
	assertRules(t, fs, "jp-bank-account", "jp-bank-account")
}

// TestMarkdownTableNegativeColumnContext は、列名が金額・件数系のときに
// 負のコンテキストが効いて抑制されることを確認する（csvNegativeContextWordsJP を
// Markdown でも同じように使う）。
func TestMarkdownTableNegativeColumnContext(t *testing.T) {
	d := newDetector(t, "")
	content := "| 数量 | 個数 |\n|---|---|\n| 1234567 | 7654321 |\n"
	assertRules(t, d.ScanContent("stats.md", content))
}

// TestMarkdownTableRequiresDelimiterRow は、区切り行が無いパイプ入りの行を
// テーブルとみなさないことを確認する。散文やシェルのパイプを列として
// 解釈すると、任意の行に無関係なラベルが付いてしまう。
func TestMarkdownTableRequiresDelimiterRow(t *testing.T) {
	d := newDetector(t, markdownHighRecallTOML)
	content := "| 氏名 | 部署 |\n| 山田太郎 | 営業部 |\n"
	assertRules(t, d.ScanContent("notatable.md", content))
}

// TestMarkdownTableHeaderShapeGuard は、ヘッダらしくない先頭行（空セル・
// 数値主体セル）のテーブルに列コンテキストを付けないことを確認する
// （looksLikeCSVHeader と同じ安全側の既定）。
func TestMarkdownTableHeaderShapeGuard(t *testing.T) {
	d := newDetector(t, markdownHighRecallTOML)
	tests := []struct {
		name, content string
	}{
		{"数値主体のヘッダ", "| 2024 | 2025 |\n|---|---|\n| 山田太郎 | 佐藤花子 |\n"},
		{"空セルのヘッダ", "| 氏名 |  |\n|---|---|\n| 山田太郎 | 営業部 |\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanContent("t.md", tt.content))
		})
	}
}

// TestMarkdownTableDelimiterCellCountMismatch は、ヘッダと区切り行のセル数が
// 食い違うテーブルを対象外にすることを確認する（列の対応が取れないため）。
func TestMarkdownTableDelimiterCellCountMismatch(t *testing.T) {
	d := newDetector(t, markdownHighRecallTOML)
	content := "| 氏名 | 部署 |\n|---|\n| 山田太郎 | 営業部 |\n"
	assertRules(t, d.ScanContent("t.md", content))
}

// TestMarkdownTableWithoutOuterPipes は、行頭・行末のパイプを省略した
// GFM の表記でも列が正しく対応することを確認する。
func TestMarkdownTableWithoutOuterPipes(t *testing.T) {
	d := newDetector(t, markdownHighRecallTOML)
	content := "氏名 | 部署\n---|---\n山田太郎 | 営業部\n佐藤花子 | 開発部\n"
	assertRules(t, d.ScanContent("t.md", content), "person-name-structured", "person-name-structured")
}

// TestMarkdownTableEscapedPipeKeepsColumns は、セル本文中のエスケープされた
// パイプ（`\|`）で列がずれないことを確認する。ずれると氏名列の値として
// 別の列が検査され、検出・誤検出の両方がおかしくなる。
func TestMarkdownTableEscapedPipeKeepsColumns(t *testing.T) {
	d := newDetector(t, markdownHighRecallTOML)
	content := "| 備考 | 氏名 |\n|---|---|\n| a \\| b | 山田太郎 |\n"
	fs := d.ScanContent("t.md", content)
	assertRules(t, fs, "person-name-structured")
	if fs[0].Match != "山田太郎" {
		t.Errorf("match = %q, want 山田太郎", fs[0].Match)
	}
}

// TestMarkdownTableSecondTableInSameFile は、1 ファイルに複数のテーブルが
// あるとき、2 つ目以降のヘッダも解釈されることを確認する（CSV と違い
// テーブルがファイル先頭にあるとは限らない）。
func TestMarkdownTableSecondTableInSameFile(t *testing.T) {
	d := newDetector(t, markdownHighRecallTOML)
	content := "| 項目 | 値 |\n|---|---|\n| a | b |\n\n## 名簿\n\n| 氏名 | 部署 |\n|---|---|\n| 山田太郎 | 営業部 |\n"
	fs := d.ScanContent("t.md", content)
	assertRules(t, fs, "person-name-structured")
	if fs[0].Line != 9 {
		t.Errorf("line = %d, want 9", fs[0].Line)
	}
}

// TestMarkdownTableNameColumnRequiresHighRecall は、氏名列の検出が
// person-name-structured（高再現率限定）に帰属し、既定では出ないことを
// 確認する。列コンテキスト自体は既定で有効なため、両者が別々に効くことを
// 固定しておく（TestMarkdownTableColumnContextForOtherRules と対）。
func TestMarkdownTableNameColumnRequiresHighRecall(t *testing.T) {
	d := newDetector(t, "")
	content := "| 氏名 | 部署 |\n|---|---|\n| 山田太郎 | 営業部 |\n"
	assertRules(t, d.ScanContent("t.md", content))
}

// TestMarkdownTableIgnoreMarker は、行末の ignore マーカーでテーブル行の
// 検出を抑制できることを確認する。
func TestMarkdownTableIgnoreMarker(t *testing.T) {
	d := newDetector(t, markdownHighRecallTOML)
	content := "| 氏名 | 部署 |\n|---|---|\n| 山田太郎 | 営業部 | <!-- jp-pii-detector:ignore -->\n"
	assertRules(t, d.ScanContent("t.md", content))
}

// TestSplitMarkdownRowFieldOffsets は、セル本文の byte offset が前後の空白を
// 含まない範囲になることを確認する（列コンテキストの Start/End はこの範囲を
// そのまま statementContext に使うため、ずれると値の帰属が壊れる）。
func TestSplitMarkdownRowFieldOffsets(t *testing.T) {
	line := "| 山田太郎 | 営業部 |"
	fields, ok := splitMarkdownRow(line)
	if !ok {
		t.Fatal("splitMarkdownRow failed")
	}
	if len(fields) != 2 {
		t.Fatalf("fields = %d, want 2", len(fields))
	}
	if got := line[fields[0].start:fields[0].end]; got != "山田太郎" {
		t.Errorf("field[0] = %q, want 山田太郎", got)
	}
	if got := line[fields[1].start:fields[1].end]; got != "営業部" {
		t.Errorf("field[1] = %q, want 営業部", got)
	}
}
