package detect

import (
	"regexp"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/normalize"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// SQL ダンプ（.sql）の INSERT 文に対する列コンテキスト（csv_context.go の
// SQL 版・レコードスコープ第一歩）。CSV/TSV はヘッダ行の列名を以降の全データ行の
// 同じ列へ配るが、SQL の INSERT 文は 1 行（1 タプル、または複数タプル）の中に
// 列名（列リスト）と値（VALUES 句）の両方が同居する:
//
//	INSERT INTO users (name, phone, order_id) VALUES ('山田太郎', '090-...', 1234567);
//
// この行を解析し、name 列の値には氏名系ラベルの文脈を、order_id 列の値には
// 「注文 ID」を意味する負の文脈を、csv_context.go とまったく同じ
// statementContext の仕組み（source_context.go の PositiveText / NegativeText）で
// 割り当てる。csv_context.go のヘッダラベルと同様、ここでも列名テキストを
// csvColumnSignal（ASCII は識別子トークン化、非 ASCII はテキストそのもの）に
// 渡すだけで、正負の実際の判定は各ルールの Context / NegativeContext 語彙照合
// （internal/detect/detect.go の ctxForMatch / hasNegativeNear）にすべて委ねる。
// 行内の離れた位置にある列名由来の文脈は、前後 40 ルーン窓のテキスト近接だけに
// 頼るより遥かに強い、構造（列位置）に基づく証拠になる。
//
// スコープは意図的に狭い（「レコードスコープ第一歩」）:
//   - フル走査（sourceLineContexts）・diff 走査（sourceLineContextsForDiff）の
//     両方から呼ばれる。CSV は diff hunk がヘッダ行を含まないことが多いため
//     diff 走査を対象外にしている（csv_context.go 先頭のコメント参照）が、
//     対象の単一行 INSERT は列リストと値が同一物理行で自己完結するため、その
//     事情は当てはまらない。値を含む行には常にその行自身の列リストが一緒に
//     含まれるので、diff 走査でも外部からのヘッダ取得なしに安全に列
//     コンテキストを割り当てられる。
//   - 単一物理行に完結する
//     `INSERT INTO <table> (<col1>, ...) VALUES (<v1>, ...)[, (<v2>, ...)]*`
//     （大文字小文字不問）だけを対象にする。
//   - 列リストのない INSERT（`INSERT INTO t VALUES (...)`）は対象外。
//     ヘッダ用の正規表現がそもそもマッチしないため、自然に何も付与されない。
//   - 複数の物理行にまたがる INSERT（値がフィールド内改行を含む、または文
//     自体が改行を挟む）も対象外。csv_context.go の csvUnterminatedRecordEnd
//     のような複数物理行への復帰処理は持たない。あるタプルの引用符が行末までに
//     閉じない場合、その行のそれ以降の解析を打ち切る（すでに正しく解析できた
//     手前のタプルの文脈は保持する。安全側 = 疑わしい部分から先だけを捨てる）。
//   - 列数と値数が一致しないタプルには何も付与しない（安全側。タプル単位の
//     判定なので、同じ行の他のタプルが正しい形なら、そちらは通常どおり処理する）。
//
// 座標系の注意（csv_context.go と同じ）: すべての範囲は normalize.Line が返す
// 正規化済み行に対するバイトオフセットの半開区間で、statementContext.Start/End・
// lineContext.statementFor と同じ基準を使う。normalize.Line は全角英数字・
// ハイフン類・数字隣接の長音記号を半角へ畳み込むだけのルーン単位で厳密に 1:1 の
// 変換（文字数・出現順序を変えない）なので、正規化済み行上のバイト位置は
// 逆変換なしにそのまま元行の対応位置を指す（CLAUDE.md の normalize パッケージの
// 不変条件を参照）。

// sqlInsertHeaderRe は「INSERT INTO <table> (<col1>, <col2>, ...) VALUES」の
// 形（大文字小文字不問）を行頭からアンカーし、列リストの中身をグループ 1 で
// 捕捉する。マッチの終端（列リストの後の空白を含む）が、VALUES 句のタプル
// 列挙が始まる位置になる。列リストの丸括弧が 1 つも無い INSERT（列リストなし）
// は、"values" キーワードがこの位置に出現しないためマッチ自体が成立しない
// （結果として安全側で対象外になる。テーブル名部分に丸括弧を含む識別子は
// 現実的に存在しないため `[^(]+?` で十分）。
var sqlInsertHeaderRe = regexp.MustCompile(
	`(?i)^\s*insert\s+into\s+[^(]+?\(([^)]*)\)\s*values\s*`,
)

// sqlLineLooksLikeInsert は正規化済みの行が（前後の空白を除いて）大文字小文字
// 不問で "insert" から始まるかどうかを安価に判定する。sqlInsertHeaderRe の
// 正規表現評価は、大きな SQL ダンプの大半を占める非 INSERT 行（CREATE TABLE・
// コメント・空行等）に対しては無駄なコストになるため、正規表現に到達する前の
// 安価な事前判定として使う（internal/rule の Prefilter と同じ考え方）。
func sqlLineLooksLikeInsert(norm string) bool {
	trimmed := strings.TrimLeft(norm, " \t")
	const prefix = "insert"
	return len(trimmed) >= len(prefix) && strings.EqualFold(trimmed[:len(prefix)], prefix)
}

// sqlValue は VALUES タプル内の 1 値の正規化済み行上のバイト範囲（半開区間）。
// 引用符付きの値は csv_context.go の csvField と同じ規約で、開き引用符の
// 直後から閉じ引用符の直前まで（引用符自体は範囲に含まない）。
type sqlValue struct {
	start, end int
}

// sqlSplitTupleValues は 1 タプルの開き丸括弧の直後（start）から走査し、
// 対応する閉じ丸括弧までをカンマ区切りで値へ分割する。呼び出し側は
// line[start-1] が '(' である前提で呼ぶ。
//
// 値が引用符（' または "）で始まる場合は csv_context.go の splitCSVLine と
// 同じ規約（同じ引用符を 2 個連続で書くと 1 個のリテラル引用符にエスケープ
// され、値を終端しない）で引用符を除いた範囲を返す。引用符なしの値
// （数値・NULL・関数呼び出し等）は、ネストした丸括弧（NOW() 等）をカンマ分割の
// 対象から除外しつつ、トップレベルのカンマ、またはタプルを閉じる丸括弧の
// 直前までの生の範囲を返す（前後の空白は値の一部として範囲に含める。
// splitCSVLine の非引用フィールドと同じ扱いで、statementFor は部分区間の
// 包含判定なので余白があっても問題にならない）。引用符なしの値の内部に
// 引用符が現れた場合は構文エラーとみなす（splitCSVLine が非引用フィールド内の
// 引用符を拒否するのと同じ理由: 引用符内の区切り文字を見誤って値がずれる
// 可能性があるため）。
//
// 行末までに対応する閉じ丸括弧が見つからない場合（値がフィールド内改行を
// 含む、すなわち INSERT 文が複数の物理行にまたがる場合等）は ok=false を
// 返す。csv_context.go の csvUnterminatedRecordEnd のような複数物理行への
// 復帰処理は持たない（呼び出し側はこのタプル以降の解析を打ち切る安全側の
// 割り切り。パッケージ先頭のコメント参照）。
func sqlSplitTupleValues(line string, start int) (values []sqlValue, next int, ok bool) {
	i, n := start, len(line)
	for {
		i = skipSpaces(line, i, n)
		if i >= n {
			return nil, 0, false
		}
		var v sqlValue
		if line[i] == '\'' || line[i] == '"' {
			q := line[i]
			i++
			v.start = i
			for i < n {
				if line[i] == q {
					if i+1 < n && line[i+1] == q {
						i += 2 // エスケープされた引用符（値を終端しない）
						continue
					}
					break
				}
				i++
			}
			if i >= n {
				return nil, 0, false // 行末までに閉じ引用符が見つからない
			}
			v.end = i
			i++ // 閉じ引用符
			i = skipSpaces(line, i, n)
		} else {
			v.start = i
			depth := 0
		scanValue:
			for i < n {
				switch line[i] {
				case '\'', '"':
					// 引用符なしの値の内部に引用符は許さない（構文エラー）。
					return nil, 0, false
				case '(':
					depth++
				case ')':
					if depth == 0 {
						break scanValue
					}
					depth--
				case ',':
					if depth == 0 {
						break scanValue
					}
				}
				i++
			}
			if i >= n {
				return nil, 0, false // 対応する区切りが見つからないまま行末に到達
			}
			v.end = i
		}
		values = append(values, v)
		if i >= n {
			return nil, 0, false
		}
		switch line[i] {
		case ',':
			i++
			continue
		case ')':
			return values, i + 1, true
		default:
			// 引用符直後に区切り文字以外が続く等、想定外の構文。
			return nil, 0, false
		}
	}
}

// sqlTuples は VALUES 句（norm[valuesStart:] の位置から開始）に含まれる
// タプルを先頭から順にパースし、各タプルの値スライスを返す。あるタプルの
// 構文が壊れている（引用符が行末までに閉じない等）ものに行き当たった時点で
// 走査を打ち切り、それまでに正しくパースできたタプルだけを返す（同じ行の
// 手前のタプルは曖昧さなく確定しているため、後続タプルの構文エラーで
// 巻き添えにしない）。1 つもタプルが無い・最初のタプルの前に想定外の文字が
// ある場合は空スライス。
func sqlTuples(norm string, valuesStart int) [][]sqlValue {
	var tuples [][]sqlValue
	pos, n := valuesStart, len(norm)
	for {
		pos = skipSpaces(norm, pos, n)
		if pos >= n || norm[pos] != '(' {
			return tuples
		}
		values, next, ok := sqlSplitTupleValues(norm, pos+1)
		if !ok {
			return tuples
		}
		tuples = append(tuples, values)
		pos = skipSpaces(norm, next, n)
		if pos >= n || norm[pos] != ',' {
			return tuples
		}
		pos++ // カンマを読み飛ばして次のタプルへ
	}
}

// sqlSplitColumnList は INSERT の列リストの中身（丸括弧を除いたテキスト）を
// カンマ区切りで分割し、各列名の前後の空白と、対応する引用（バッククォート・
// 二重引用符・角括弧）を 1 層だけ取り除く。列名は単純な識別子の並びである
// 前提で、値のようなネストした丸括弧・引用符付きカンマの考慮はしない
// （実務の INSERT 文の列リストで十分。VALUES 側の値はネストや引用符を
// sqlSplitTupleValues で正しく扱う）。
func sqlSplitColumnList(s string) []string {
	rawCols := strings.Split(s, ",")
	cols := make([]string, len(rawCols))
	for i, c := range rawCols {
		cols[i] = sqlUnquoteIdentifier(strings.TrimSpace(c))
	}
	return cols
}

// sqlUnquoteIdentifier は s の先頭・末尾が対応する引用ペア
// （バッククォート・二重引用符・角括弧）で囲まれていれば、その 1 層だけを
// 取り除く。囲まれていなければそのまま返す。
func sqlUnquoteIdentifier(s string) string {
	if len(s) < 2 {
		return s
	}
	switch {
	case s[0] == '`' && s[len(s)-1] == '`',
		s[0] == '"' && s[len(s)-1] == '"',
		s[0] == '[' && s[len(s)-1] == ']':
		return s[1 : len(s)-1]
	}
	return s
}

// sqlColumnSignals は列リストの各列名から csvColumnSignal を通じて
// PositiveText/NegativeText を求める。ok[i]=false の列（空文字列などラベルに
// ならない列名）には文脈を割り当てない。
func sqlColumnSignals(columns []string) (positives, negatives []string, ok []bool) {
	positives = make([]string, len(columns))
	negatives = make([]string, len(columns))
	ok = make([]bool, len(columns))
	for i, col := range columns {
		p, n, has := csvColumnSignal(col)
		if !has {
			continue
		}
		positives[i], negatives[i], ok[i] = p, n, true
	}
	return positives, negatives, ok
}

// sqlStatementContextsForLine は正規化済みの 1 行を解析し、単一物理行に
// 完結する `INSERT INTO <table> (<col1>, ...) VALUES (<v1>, ...)[, (...)]*`
// 形式であれば、各タプルの値ごとに対応する列名由来の statementContext を
// 返す。マッチしない・パースに失敗した場合や、列数と値数が一致しないタプルは
// 何も返さない（安全側。パッケージ先頭のコメント参照）。
func sqlStatementContextsForLine(norm string) []statementContext {
	if !sqlLineLooksLikeInsert(norm) {
		return nil
	}
	m := sqlInsertHeaderRe.FindStringSubmatchIndex(norm)
	if m == nil {
		return nil
	}
	columns := sqlSplitColumnList(norm[m[2]:m[3]])
	positives, negatives, hasSignal := sqlColumnSignals(columns)

	var stmts []statementContext
	for _, values := range sqlTuples(norm, m[1]) {
		if len(values) != len(columns) {
			// 列数と値数が一致しないタプルには何も付与しない（安全側）。
			continue
		}
		for i, v := range values {
			if v.start >= v.end || !hasSignal[i] {
				continue
			}
			stmts = append(stmts, statementContext{
				Start:        v.start,
				End:          v.end,
				PositiveText: positives[i],
				NegativeText: negatives[i],
			})
		}
	}
	return stmts
}

// sqlLineContexts は .sql ファイルの各行を独立に解析し、INSERT INTO ...
// VALUES (...) 文の列名を、同位置の値の statementContext に割り当てる
// （sourceLineContexts・sourceLineContextsForDiff の双方から、フル走査・diff
// 走査を区別せず同じ形で呼ばれる）。CSV と異なりヘッダ行のような行をまたぐ
// 状態は持たない。1 つの INSERT 文が列名（列リスト）と値（VALUES 句）の両方を
// 単一行内に持つため、行ごとに独立して解析できる（diff 走査で hunk が一部の
// 行だけを含んでいても、行同士の依存が無いため問題にならない）。
func sqlLineContexts(_ string, lines []string) []lineContext {
	out := make([]lineContext, len(lines))
	for i, line := range lines {
		out[i].Statements = sqlStatementContextsForLine(normalize.Line(line))
	}
	return out
}

// scanSQLNameColumns は csv_context.go の scanCSVNameColumns の SQL 版。
// INSERT 文の列名が氏名系の強いラベル（rule.CSVNameHeaderRe）と完全一致する
// 列について、対応するタプルの値が氏名として妥当か（rule.CSVNameValueRe +
// rule.ValidCrossLineName の姓名辞書照合）を検証し person-name-structured
// として報告する。person-name-structured は高再現率限定のルールのため、
// crossLineName が有効なときだけ呼ばれる。
//
// person-name ルール自身は「ラベル + 区切り + 値」が同一正規表現内で隣接する
// ことを前提にしており（personNameSep はコロン・イコールの直後だけを区切りと
// 認める）、INSERT 文のように列名（列リスト）と値（VALUES 句）が同じ行の
// 離れた位置にある構造は拾えない。そのため sqlStatementContextsForLine が
// 割り当てる一般的な PositiveText/NegativeText 経由の文脈昇格では届かず、
// csv_context.go の scanCSVNameColumns と同じ専用の値検証経路が必要になる。
func (d *Detector) scanSQLNameColumns(file string, lines []string) []Finding {
	if rule.Medium < d.scanMinConf {
		return nil
	}
	if d.crossLineName == nil {
		return nil
	}
	var out []Finding
	for li, line := range lines {
		norm := normalize.Line(line)
		if !sqlLineLooksLikeInsert(norm) {
			continue
		}
		m := sqlInsertHeaderRe.FindStringSubmatchIndex(norm)
		if m == nil {
			continue
		}
		columns := sqlSplitColumnList(norm[m[2]:m[3]])
		nameCols := map[int]bool{}
		for ci, col := range columns {
			if col != "" && rule.CSVNameHeaderRe.MatchString(col) {
				nameCols[ci] = true
			}
		}
		if len(nameCols) == 0 {
			continue
		}
		var origRunes []rune
		for _, values := range sqlTuples(norm, m[1]) {
			if len(values) != len(columns) {
				continue
			}
			for ci, v := range values {
				if !nameCols[ci] || v.start >= v.end {
					continue
				}
				field := norm[v.start:v.end]
				vm := rule.CSVNameValueRe.FindStringSubmatchIndex(field)
				if vm == nil || vm[2] < 0 {
					continue
				}
				entity := field[vm[2]:vm[3]]
				if !rule.ValidCrossLineName(entity) || d.allowlisted(entity) {
					continue
				}
				rs := len([]rune(norm[:v.start+vm[2]]))
				re := rs + len([]rune(entity))
				if origRunes == nil {
					origRunes = []rune(line)
				}
				if re > len(origRunes) {
					continue
				}
				finding := Finding{
					RuleID:      d.crossLineName.ID,
					Description: d.crossLineName.Description,
					File:        file,
					Line:        li + 1,
					Column:      rs + 1,
					Match:       string(origRunes[rs:re]),
					Confidence:  rule.Medium,
					Reason: DetectReason{
						BaseConfidence:  rule.Medium.String(),
						FinalConfidence: rule.Medium.String(),
						Validated:       true,
					},
					start:         rs,
					end:           re,
					scoreEvidence: confidenceScoreEvidence{structuredPair: true},
				}
				finalizeFindingScore(&finding)
				out = append(out, finding)
			}
		}
	}
	return out
}
