package detect

import (
	"strings"

	"github.com/baneido/jp-pii-detector/internal/normalize"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// Markdown のパイプテーブルは、日本語の業務ドキュメントで名簿・連絡先一覧を
// 書くときに CSV と同じかそれ以上によく使われる形だが、csv_context.go の
// 列コンテキストは拡張子 .csv/.tsv に限定されており、かつ `| 氏名 | 部署 |`
// という行は rule.CrossLineNameLabelRe の行全体アンカーにも一致しないため、
// 両方の機構から漏れてヘッダ直下の 1 行すら検出できなかった。ここでは CSV と
// 同じ「ヘッダ行のラベルを同じ列の全データ行へ配る」機構を Markdown テーブルへ
// 広げる。
//
// CSV との構造的な違いは 2 点で、どちらも markdownTables が吸収する:
//   - テーブルがファイル先頭にあるとは限らない（見出しや本文が先行する）
//   - 1 ファイルに複数のテーブルが現れうる
//
// フル走査限定で、diff 走査では使わない（csvLineContexts と同じ理由。hunk は
// ヘッダ行を含まないことが多く、CSV のように `git show` でヘッダだけを
// 取り直す経路も持たないため、列のずれた誤帰属を避けて安全側に倒す）。

// markdownTable は 1 つのパイプテーブルが占める行範囲。header は
// ヘッダ行、dataStart:dataEnd はデータ行の半開区間（区切り行 `|---|---|` は
// どちらにも含めない）。
type markdownTable struct {
	header    int
	dataStart int
	dataEnd   int
}

// splitMarkdownRow は正規化済みの 1 行を Markdown テーブルの行とみなして
// セルに分割し、各セル本文（前後の空白を除いた範囲）の byte offset を返す。
// GFM のエスケープ `\|` はセル区切りとして扱わない（直前の連続する
// バックスラッシュが奇数個ならエスケープされている）。
//
// 行に区切りとなるパイプが 1 つも無い場合は ok=false を返す。テーブルの成立
// 判定自体は markdownTables が区切り行の存在で行うため、この関数は
// 「パイプで区切られた行か」だけを見る（散文中の `grep foo | wc` のような行も
// ここでは 2 セルに分割されるが、区切り行を伴わないためテーブルにはならない）。
func splitMarkdownRow(line string) ([]csvField, bool) {
	var bounds []int
	for i := 0; i < len(line); i++ {
		if line[i] != '|' {
			continue
		}
		backslashes := 0
		for j := i - 1; j >= 0 && line[j] == '\\'; j-- {
			backslashes++
		}
		if backslashes%2 == 1 {
			continue
		}
		bounds = append(bounds, i)
	}
	if len(bounds) == 0 {
		return nil, false
	}
	var fields []csvField
	// 先頭パイプの前（`| a | b |` の左端）は空なら行頭パイプとして読み飛ばし、
	// 空でなければ（`a | b` の形）1 つ目のセルとして扱う。
	if f, ok := trimmedField(line, 0, bounds[0]); ok {
		fields = append(fields, f)
	}
	for k := 0; k+1 < len(bounds); k++ {
		f, ok := trimmedField(line, bounds[k]+1, bounds[k+1])
		if !ok {
			// 空セルも列の位置合わせには必要なので、範囲を潰した空フィールドを
			// 入れて列番号をずらさない。
			f = csvField{start: bounds[k] + 1, end: bounds[k] + 1}
		}
		fields = append(fields, f)
	}
	// 末尾パイプの後（`| a | b |` の右端）も同様に、空なら行末パイプとみなす。
	if f, ok := trimmedField(line, bounds[len(bounds)-1]+1, len(line)); ok {
		fields = append(fields, f)
	}
	if len(fields) == 0 {
		return nil, false
	}
	return fields, true
}

// trimmedField は line[start:end] の前後の空白を除いた範囲を返す。中身が
// 空白のみなら ok=false。
func trimmedField(line string, start, end int) (csvField, bool) {
	for start < end && (line[start] == ' ' || line[start] == '\t') {
		start++
	}
	for end > start && (line[end-1] == ' ' || line[end-1] == '\t') {
		end--
	}
	if start >= end {
		return csvField{}, false
	}
	return csvField{start: start, end: end}, true
}

// isMarkdownDelimiterRow は fields が GFM の区切り行（`---` / `:---` /
// `---:` / `:---:`）のセルだけで構成されるかを返す。この行の存在が
// 「散文中のパイプ」と「テーブル」を分ける唯一の手がかりになる。
func isMarkdownDelimiterRow(line string, fields []csvField) bool {
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		cell := line[f.start:f.end]
		cell = strings.TrimPrefix(cell, ":")
		cell = strings.TrimSuffix(cell, ":")
		if cell == "" || strings.Trim(cell, "-") != "" {
			return false
		}
	}
	return true
}

// looksLikeMarkdownHeader はヘッダ行らしさの判定。looksLikeCSVHeader と同じ
// 「空でなく、数値主体でもないセルだけからなる」条件を使うが、列数 2 以上の
// 要求は課さない。CSV では 1 列だけの行を「ヘッダ無しデータ」と区別できない
// のに対し、Markdown では区切り行の存在が既にテーブルであることを保証して
// いるため、1 列の名簿（`| 氏名 |`）も安全に扱えるため。
func looksLikeMarkdownHeader(line string, fields []csvField) bool {
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		text := strings.TrimSpace(line[f.start:f.end])
		if text == "" || isNumericMajorityText(text) {
			return false
		}
	}
	return true
}

// markdownTables は lines 中のパイプテーブルを先頭から順に列挙する。
// ヘッダ行と、その直後の区切り行（セル数が一致すること）が揃った場合のみ
// テーブルとみなし、以降パイプを含む行が続く限りをデータ行とする。
func markdownTables(lines []string) []markdownTable {
	var out []markdownTable
	for i := 0; i+1 < len(lines); i++ {
		headerNorm := normalize.Line(lines[i])
		headerFields, ok := splitMarkdownRow(headerNorm)
		if !ok {
			continue
		}
		delimNorm := normalize.Line(lines[i+1])
		delimFields, ok := splitMarkdownRow(delimNorm)
		if !ok || !isMarkdownDelimiterRow(delimNorm, delimFields) {
			continue
		}
		// セル数が食い違う区切り行は GFM のテーブルとして不正。列の対応が
		// 取れないため、列コンテキストを付けずに読み飛ばす（安全側）。
		if len(delimFields) != len(headerFields) {
			continue
		}
		start := i + 2
		end := start
		for end < len(lines) {
			if _, ok := splitMarkdownRow(normalize.Line(lines[end])); !ok {
				break
			}
			end++
		}
		out = append(out, markdownTable{header: i, dataStart: start, dataEnd: end})
		// 見つかったテーブルの内部を再度ヘッダ候補として走査しない。
		i = end - 1
	}
	return out
}

// parseMarkdownHeader はテーブルのヘッダ行から列ごとの文脈を組み立てる。
// ヘッダ行らしくない場合は ok=false（列コンテキストを一切付与しない）。
func parseMarkdownHeader(headerLine string) (csvHeader, []csvField, bool) {
	norm := normalize.Line(headerLine)
	fields, ok := splitMarkdownRow(norm)
	if !ok || !looksLikeMarkdownHeader(norm, fields) {
		return csvHeader{}, nil, false
	}
	return columnHeaderFromFields(norm, fields), fields, true
}

// markdownLineContexts は Markdown テーブルのヘッダセルから、同じテーブルの
// 全データ行の該当セルへ statementContext を付与する（sourceLineContexts から
// のみ呼ばれる。フル走査限定）。
//
// この列コンテキスト自体は氏名専用ではなく、電話番号・郵便番号・口座番号など
// 既定で有効な全ルールの文脈判定に効く（`| 電話番号 |` 列の値が
// RequireContext ルールの文脈を得る、など）。氏名列の検出だけは
// scanMarkdownTableNameColumns が別途行う。
func markdownLineContexts(lines []string) []lineContext {
	out := make([]lineContext, len(lines))
	for _, t := range markdownTables(lines) {
		header, _, ok := parseMarkdownHeader(lines[t.header])
		if !ok {
			continue
		}
		for i := t.dataStart; i < t.dataEnd; i++ {
			norm := normalize.Line(lines[i])
			fields, ok := splitMarkdownRow(norm)
			if !ok {
				continue
			}
			var stmts []statementContext
			for fi, f := range fields {
				if fi >= len(header.text) || header.text[fi] == "" || f.start >= f.end {
					continue
				}
				if header.positive[fi] == "" && header.negative[fi] == "" {
					continue
				}
				stmts = append(stmts, statementContext{
					Start:        f.start,
					End:          f.end,
					PositiveText: header.positive[fi],
					NegativeText: header.negative[fi],
				})
			}
			out[i].Statements = stmts
		}
	}
	return out
}

// scanMarkdownTableNameColumns は Markdown テーブルのヘッダセルが氏名系の
// 強いラベル（rule.CSVNameHeaderRe と完全一致）である列について、各データ行の
// セル値が氏名として妥当かを検証し person-name-structured として報告する。
// scanCSVNameColumns の Markdown 版で、値の検証・スパン算出は
// columnNameFinding を共有する。person-name-structured は高再現率限定の
// ルールのため、crossLineName が有効なときだけ呼ばれる。
func (d *Detector) scanMarkdownTableNameColumns(file string, lines []string) []Finding {
	if rule.Medium < d.scanMinConf {
		return nil
	}
	if d.crossLineName == nil {
		return nil
	}
	var out []Finding
	for _, t := range markdownTables(lines) {
		header, headerFields, ok := parseMarkdownHeader(lines[t.header])
		if !ok {
			continue
		}
		nameCols := map[int]bool{}
		for i := range headerFields {
			if header.text[i] != "" && rule.CSVNameHeaderRe.MatchString(header.text[i]) {
				nameCols[i] = true
			}
		}
		if len(nameCols) == 0 {
			continue
		}
		for li := t.dataStart; li < t.dataEnd; li++ {
			norm := normalize.Line(lines[li])
			fields, ok := splitMarkdownRow(norm)
			if !ok {
				continue
			}
			for fi, f := range fields {
				if !nameCols[fi] {
					continue
				}
				if finding, ok := d.columnNameFinding(file, li+1, lines[li], norm, f); ok {
					out = append(out, finding)
				}
			}
		}
	}
	return out
}
