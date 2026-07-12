package detect

import (
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/rule"
)

// このファイルのサンプル値は非公開評価コーパス不要で実行できる
// （csv_context_test.go と同じ方針）:
//   - 7 桁の数字は口座番号ルールが桁数＋文脈だけを要求するダミー値。
//   - ハイフン区切りの電話番号風の値は detect_test.go 全体で広く使われている
//     ダミー値（市外局番辞書照合を満たす形）。
//   - 氏名風の値は埋め込み姓名辞書に含まれる/detect_test.go で架空値として
//     使われているリテラル。
//
// PII 形のサンプル値を含む Go ソース行は、行末に jp-pii-detector:ignore
// マーカーを付けて自己 dogfood（このファイル自身を .go として走査した場合）
// から除外する。このマーカーはあくまで Go ソース行（コメント）としての注釈で
// あり、d.ScanContent に渡す「模擬 .sql ファイルの内容」文字列そのものには
// 含まれない（マーカーが値側の文字列に混入すると、検出対象文脈が変質して
// テストの意味が失われるため）。複数物理行にまたがる内容はバッククォートの
// raw 文字列ではなく 1 行文字列 + 連結で組み立て、PII 形を含む行だけに
// マーカーを付けられるようにする。

// --- Part A: 低レベルパーサ（sqlSplitTupleValues / sqlTuples / 列リスト） ---

func TestSQLSplitTupleValuesUnquoted(t *testing.T) {
	line := "(1,22,333)"
	values, next, ok := sqlSplitTupleValues(line, 1)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	want := []string{"1", "22", "333"}
	if len(values) != len(want) {
		t.Fatalf("values = %d 件, want %d: %+v", len(values), len(want), values)
	}
	for i, v := range values {
		if got := line[v.start:v.end]; got != want[i] {
			t.Errorf("values[%d] = %q, want %q", i, got, want[i])
		}
	}
	if next != len(line) {
		t.Errorf("next = %d, want %d（閉じ括弧の直後）", next, len(line))
	}
}

func TestSQLSplitTupleValuesQuoted(t *testing.T) {
	line := `('a', 'bb', 'ccc')`
	values, _, ok := sqlSplitTupleValues(line, 1)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	want := []string{"a", "bb", "ccc"}
	if len(values) != len(want) {
		t.Fatalf("values = %d 件, want %d: %+v", len(values), len(want), values)
	}
	for i, v := range values {
		if got := line[v.start:v.end]; got != want[i] {
			t.Errorf("values[%d] = %q, want %q", i, got, want[i])
		}
	}
}

func TestSQLSplitTupleValuesMixedQuotedAndUnquoted(t *testing.T) {
	line := `('a', 123, NULL, 'b')`
	values, _, ok := sqlSplitTupleValues(line, 1)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	want := []string{"a", "123", "NULL", "b"}
	if len(values) != len(want) {
		t.Fatalf("values = %d 件, want %d: %+v", len(values), len(want), values)
	}
	for i, v := range values {
		if got := line[v.start:v.end]; got != want[i] {
			t.Errorf("values[%d] = %q, want %q", i, got, want[i])
		}
	}
}

// "" は同じ引用符 1 個にエスケープされ、値を終端しない（csv_context の
// splitCSVLine と同じ規約）。後続の値の位置がずれないことも併せて確認する。
func TestSQLSplitTupleValuesEscapedQuoteDoesNotShiftColumns(t *testing.T) {
	line := `('a''b', 'c')`
	values, next, ok := sqlSplitTupleValues(line, 1)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if len(values) != 2 {
		t.Fatalf("values = %d 件, want 2: %+v", len(values), values)
	}
	if got := line[values[0].start:values[0].end]; got != "a''b" {
		t.Errorf("values[0] = %q, want a''b（エスケープされた引用符を含む生の範囲）", got)
	}
	if got := line[values[1].start:values[1].end]; got != "c" {
		t.Errorf("values[1] = %q, want c（前の値のエスケープでずれていない）", got)
	}
	if next != len(line) {
		t.Errorf("next = %d, want %d", next, len(line))
	}
}

// ダブルクォートでも同じエスケープ規約が働く。
func TestSQLSplitTupleValuesDoubleQuoteEscape(t *testing.T) {
	line := `("a""b", "c")`
	values, _, ok := sqlSplitTupleValues(line, 1)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if got := line[values[0].start:values[0].end]; got != `a""b` {
		t.Errorf("values[0] = %q, want a\"\"b", got)
	}
	if got := line[values[1].start:values[1].end]; got != "c" {
		t.Errorf("values[1] = %q, want c", got)
	}
}

// NOW() のようなネストした丸括弧を含む値は、内側のカンマ・閉じ括弧で
// タプルが誤って終端しない。
func TestSQLSplitTupleValuesNestedParens(t *testing.T) {
	line := `(1, NOW(), POINT(1,2), 2)`
	values, _, ok := sqlSplitTupleValues(line, 1)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	want := []string{"1", "NOW()", "POINT(1,2)", "2"}
	if len(values) != len(want) {
		t.Fatalf("values = %d 件, want %d: %+v", len(values), len(want), values)
	}
	for i, v := range values {
		if got := line[v.start:v.end]; got != want[i] {
			t.Errorf("values[%d] = %q, want %q", i, got, want[i])
		}
	}
}

// 行末までに閉じ引用符が見つからない場合は ok=false（複数物理行にまたがる
// 値・INSERT 文の可能性。パッケージ先頭のコメント参照）。
func TestSQLSplitTupleValuesUnterminatedQuoteFails(t *testing.T) {
	_, _, ok := sqlSplitTupleValues(`('a, 'b')`, 1)
	if ok {
		t.Fatal("ok = true, want false（開き引用符のまま行末に到達）")
	}
	_, _, ok = sqlSplitTupleValues(`('unterminated`, 1)
	if ok {
		t.Fatal("ok = true, want false（閉じ引用符なし）")
	}
}

// 引用符なしの値の内部に引用符が現れるのは構文エラー（列がずれる可能性がある
// ため、splitCSVLine が非引用フィールド内の引用符を拒否するのと同じ方針）。
func TestSQLSplitTupleValuesRejectsQuoteInsideUnquotedValue(t *testing.T) {
	_, _, ok := sqlSplitTupleValues(`(abc'def, 1)`, 1)
	if ok {
		t.Fatal("ok = true, want false")
	}
}

// 閉じ丸括弧が行末までに見つからない（対応する区切りが無い）場合は ok=false。
func TestSQLSplitTupleValuesUnbalancedParenFails(t *testing.T) {
	_, _, ok := sqlSplitTupleValues(`(1, 2`, 1)
	if ok {
		t.Fatal("ok = true, want false")
	}
}

func TestSQLTuplesMultiple(t *testing.T) {
	norm := "INSERT INTO t (a,b) VALUES (1,2), (3,4);"
	m := sqlInsertHeaderRe.FindStringSubmatchIndex(norm)
	if m == nil {
		t.Fatal("header did not match")
	}
	tuples := sqlTuples(norm, m[1])
	if len(tuples) != 2 {
		t.Fatalf("tuples = %d 件, want 2: %+v", len(tuples), tuples)
	}
	want := [][]string{{"1", "2"}, {"3", "4"}}
	for ti, tuple := range tuples {
		if len(tuple) != 2 {
			t.Fatalf("tuple[%d] = %d 件, want 2", ti, len(tuple))
		}
		for vi, v := range tuple {
			if got := norm[v.start:v.end]; got != want[ti][vi] {
				t.Errorf("tuple[%d][%d] = %q, want %q", ti, vi, got, want[ti][vi])
			}
		}
	}
}

// 1 つ目のタプルが破損している（構文エラー）場合、それより前に確定した
// タプルは無いのでタプルは 0 件になる。
func TestSQLTuplesStopsAtFirstBrokenTuple(t *testing.T) {
	norm := "INSERT INTO t (a) VALUES ('unterminated"
	m := sqlInsertHeaderRe.FindStringSubmatchIndex(norm)
	if m == nil {
		t.Fatal("header did not match")
	}
	tuples := sqlTuples(norm, m[1])
	if len(tuples) != 0 {
		t.Fatalf("tuples = %d 件, want 0: %+v", len(tuples), tuples)
	}
}

// 2 つ目以降のタプルが破損していても、手前で確定したタプルは保持する
// （同じ行の手前のタプルは曖昧さなく確定しているため、後続タプルの構文
// エラーで巻き添えにしない設計）。
func TestSQLTuplesKeepsEarlierTuplesWhenLaterTupleBreaks(t *testing.T) {
	norm := "INSERT INTO t (a) VALUES (1), ('unterminated"
	m := sqlInsertHeaderRe.FindStringSubmatchIndex(norm)
	if m == nil {
		t.Fatal("header did not match")
	}
	tuples := sqlTuples(norm, m[1])
	if len(tuples) != 1 {
		t.Fatalf("tuples = %d 件, want 1: %+v", len(tuples), tuples)
	}
	if got := norm[tuples[0][0].start:tuples[0][0].end]; got != "1" {
		t.Errorf("tuples[0][0] = %q, want 1", got)
	}
}

func TestSQLSplitColumnList(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"単純な識別子", "name, phone, order_id", []string{"name", "phone", "order_id"}},
		{"バッククォート", "`name`, `phone`", []string{"name", "phone"}},
		{"二重引用符", `"name", "phone"`, []string{"name", "phone"}},
		{"角括弧(MSSQL)", "[name], [phone]", []string{"name", "phone"}},
		{"空白のみのばらつき", "  name  ,phone", []string{"name", "phone"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sqlSplitColumnList(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("got = %#v, want %#v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSQLLineLooksLikeInsert(t *testing.T) {
	positives := []string{"INSERT INTO t (a) VALUES (1);", "  insert into t (a) values (1);", "Insert Into t(a)Values(1);"}
	for _, line := range positives {
		if !sqlLineLooksLikeInsert(line) {
			t.Errorf("sqlLineLooksLikeInsert(%q) = false, want true", line)
		}
	}
	negatives := []string{"CREATE TABLE t (a int);", "-- comment", "UPDATE t SET a = 1;", ""}
	for _, line := range negatives {
		if sqlLineLooksLikeInsert(line) {
			t.Errorf("sqlLineLooksLikeInsert(%q) = true, want false", line)
		}
	}
}

// --- Part B: sqlStatementContextsForLine / sqlLineContexts（一般的な文脈割り当て） ---

// name 列の値には氏名系ラベルの文脈（PositiveText）が届く。person-name
// ルール自体は「ラベル + 区切り + 値」が同一正規表現内で隣接することを前提と
// しており INSERT 文の列名・値の位置関係は拾えないため（Part C の
// scanSQLNameColumns 参照）、ここでは source_context_test.go の
// TestSourceLineContextsExtractStatement と同じ流儀で、割り当てられる
// PositiveText 自体を直接検証する。
func TestSQLStatementContextsNameColumnPositiveText(t *testing.T) {
	line := "INSERT INTO users (name, memo) VALUES ('架空花子', 'note');"
	stmts := sqlStatementContextsForLine(line)
	if len(stmts) != 2 {
		t.Fatalf("stmts = %d 件, want 2: %+v", len(stmts), stmts)
	}
	nameValue := `'架空花子'`
	nameStart := strings.Index(line, nameValue) + 1 // 開き引用符の直後
	nameEnd := nameStart + len("架空花子")
	st := (lineContext{Statements: stmts}).statementFor(nameStart, nameEnd)
	if st == nil {
		t.Fatalf("name 列の値に statementContext が割り当てられていない: %+v", stmts)
	}
	if st.PositiveText != "name" {
		t.Errorf("PositiveText = %q, want name", st.PositiveText)
	}
}

// order_id 列の値には「注文 ID」を意味する負文脈（NegativeText）が届く
// （TestSourceLineContextsNegativeText と同じ流儀）。
func TestSQLStatementContextsOrderIDColumnNegativeText(t *testing.T) {
	line := "INSERT INTO t (order_id) VALUES (1234567);"
	stmts := sqlStatementContextsForLine(line)
	if len(stmts) != 1 {
		t.Fatalf("stmts = %d 件, want 1: %+v", len(stmts), stmts)
	}
	if !strings.Contains(stmts[0].NegativeText, "id") || !strings.Contains(stmts[0].NegativeText, "order") {
		t.Fatalf("NegativeText = %q, want id と order を含む", stmts[0].NegativeText)
	}
	if got := line[stmts[0].Start:stmts[0].End]; got != "1234567" {
		t.Fatalf("value = %q, want 1234567", got)
	}
}

// 日本語の列名（氏名 等）も csvColumnSignal の非 ASCII フォールバックにより
// PositiveText としてそのまま届く。
func TestSQLStatementContextsJapaneseColumnName(t *testing.T) {
	line := "INSERT INTO users (氏名) VALUES ('架空太郎');"
	stmts := sqlStatementContextsForLine(line)
	if len(stmts) != 1 {
		t.Fatalf("stmts = %d 件, want 1: %+v", len(stmts), stmts)
	}
	if stmts[0].PositiveText != "氏名" {
		t.Errorf("PositiveText = %q, want 氏名", stmts[0].PositiveText)
	}
}

// 列数と値数が一致しないタプルには何も付与しない（安全側）。
func TestSQLStatementContextsColumnValueCountMismatchAssignsNothing(t *testing.T) {
	line := "INSERT INTO t (name, phone) VALUES ('架空太郎', '03-0000-0000', 'extra');" // jp-pii-detector:ignore
	stmts := sqlStatementContextsForLine(line)
	if len(stmts) != 0 {
		t.Fatalf("stmts = %+v, want none（列数 2・値数 3 で不一致）", stmts)
	}
}

// 複数タプルのうち一致するものだけ文脈を得る（1 つ目は 2 列 2 値で一致、
// 2 つ目は値が 1 つ多く不一致）。
func TestSQLStatementContextsPerTupleMismatch(t *testing.T) {
	line := "INSERT INTO t (name, phone) VALUES ('架空一郎', '03-1111-1111'), ('架空二郎', '03-2222-2222', 'extra');" // jp-pii-detector:ignore
	stmts := sqlStatementContextsForLine(line)
	// 1 つ目のタプル分（name・phone の 2 件）のみ付与される。
	if len(stmts) != 2 {
		t.Fatalf("stmts = %d 件, want 2（1 つ目のタプル分のみ）: %+v", len(stmts), stmts)
	}
}

// 列リストのない INSERT（INSERT INTO t VALUES (...)）はヘッダ用正規表現が
// マッチしないため、対象外（何も付与しない）。
func TestSQLStatementContextsNoColumnListAssignsNothing(t *testing.T) {
	line := "INSERT INTO t VALUES ('架空太郎', '03-0000-0000');" // jp-pii-detector:ignore
	stmts := sqlStatementContextsForLine(line)
	if len(stmts) != 0 {
		t.Fatalf("stmts = %+v, want none（列リストなし）", stmts)
	}
}

// 複数の物理行にまたがる INSERT（値がフィールド内改行を含む）は対象外。
// 1 行目はタプルの引用符が閉じないため何も付与されず、2 行目（続き）も
// 単独では INSERT INTO ... VALUES の形にならないため何も付与されない。
func TestSQLLineContextsMultiLineInsertAssignsNothing(t *testing.T) {
	lines := []string{
		"INSERT INTO users (name, memo) VALUES ('架空太郎', '複数行に",
		"またがるメモです');",
	}
	ctxs := sqlLineContexts("dump.sql", lines)
	if len(ctxs) != 2 {
		t.Fatalf("ctxs = %d 行, want 2", len(ctxs))
	}
	for i, c := range ctxs {
		if len(c.Statements) != 0 {
			t.Errorf("line %d の statements = %+v, want none（複数行にまたがる INSERT は対象外）", i+1, c.Statements)
		}
	}
}

// エスケープ ” を含む値があっても、後続タプル・後続列の位置がずれない
// （sqlStatementContextsForLine 経由の統合レベル確認）。
func TestSQLStatementContextsEscapedQuoteDoesNotShiftSubsequentColumn(t *testing.T) {
	const phoneValue = "090-1234-5678" // jp-pii-detector:ignore
	line := "INSERT INTO t (memo, phone) VALUES ('a''b', '" + phoneValue + "');"
	stmts := sqlStatementContextsForLine(line)
	if len(stmts) != 2 {
		t.Fatalf("stmts = %d 件, want 2: %+v", len(stmts), stmts)
	}
	phoneStart := strings.Index(line, phoneValue)
	phoneEnd := phoneStart + len(phoneValue)
	st := (lineContext{Statements: stmts}).statementFor(phoneStart, phoneEnd)
	if st == nil {
		t.Fatalf("phone 列の値に statementContext が割り当てられていない（前の値のエスケープでずれた可能性）: %+v", stmts)
	}
	if st.PositiveText != "phone" {
		t.Errorf("PositiveText = %q, want phone", st.PositiveText)
	}
}

// .sql 以外の拡張子には SQL 列コンテキストの影響が及ばない
// （sourceKindForPath が .sql だけを sourceKindSQL に分類するため）。
func TestSQLContextDoesNotApplyToOtherExtensions(t *testing.T) {
	if sourceKindForPath("dump.sql") != sourceKindSQL {
		t.Fatal("dump.sql は sourceKindSQL であるべき")
	}
	if sourceKindForPath("dump.txt") == sourceKindSQL {
		t.Fatal("dump.txt は sourceKindSQL であってはならない")
	}
	line := "INSERT INTO t (phone) VALUES ('03-1234-5678');" // jp-pii-detector:ignore
	ctxs := sourceLineContexts("dump.txt", []string{line})
	if len(ctxs) != 1 || len(ctxs[0].Statements) != 0 {
		t.Fatalf("dump.txt に SQL 列コンテキストが付与された: %+v", ctxs)
	}
}

// diff 走査（sourceLineContextsForDiff の基盤である baseSourceLineContexts）は
// .sql を対象外にする（CSV と同じ理由。フル走査限定）。
func TestSQLContextDoesNotApplyToDiffScanBase(t *testing.T) {
	_, ok := baseSourceLineContexts("dump.sql", []string{"INSERT INTO t (phone) VALUES ('03-1234-5678');"}) // jp-pii-detector:ignore
	if ok {
		t.Fatal("baseSourceLineContexts が .sql を通した（diff 走査に列コンテキストが漏れる）")
	}
}

// --- Part C: Detector.ScanContent 統合レベル ---

// phone 列の番号は、列名（ラベル）から離れた位置にあっても（前後 40 ルーン窓の
// テキスト近接に頼らず）構造的な列コンテキストで電話文脈が届き、High へ
// 昇格する。padding 列の長い値でラベルと値の間を意図的に 40 ルーンより
// 大きく引き離し、隣接テキスト window だけでは届かないことを保証する。
func TestSQLInsertPhoneColumnPromotesBeyondFortyRuneWindow(t *testing.T) {
	d := newDetector(t, "")
	const testPhone = "03-1234-5678"   // jp-pii-detector:ignore
	padding := strings.Repeat("x", 80) // phone ラベルを 40 ルーン窓の外へ押し出す埋め草
	line := "INSERT INTO t (padding, phone) VALUES ('" + padding + "', '" + testPhone + "');"
	fs := d.ScanContent("dump.sql", line+"\n")

	var found *Finding
	for i := range fs {
		if fs[i].RuleID == "jp-phone-number" && fs[i].Match == testPhone {
			found = &fs[i]
		}
	}
	if found == nil {
		t.Fatalf("jp-phone-number が検出されない: %+v", fs)
	}
	if found.Confidence != rule.High {
		t.Errorf("confidence = %v, want High（構造的な列コンテキストで昇格するはず）", found.Confidence)
	}
	if !found.Reason.ContextPromoted {
		t.Errorf("ContextPromoted = false, want true")
	}
}

// 上と対になる回帰テスト: 列数と値数が一致しないタプルには文脈が付与
// されないため、同じ padding 構造でも昇格しない（Medium のまま）。
// 39 桁を超える window では届かないことを利用して、昇格が「たまたま」
// 起きていないことを確認する。
func TestSQLInsertPhoneColumnMismatchedTupleDoesNotPromote(t *testing.T) {
	d := newDetector(t, "")
	const testPhone = "03-1234-5678" // jp-pii-detector:ignore
	padding := strings.Repeat("x", 80)
	line := "INSERT INTO t (padding, phone) VALUES ('" + padding + "', '" + testPhone + "', 'extra');"
	fs := d.ScanContent("dump.sql", line+"\n")

	var found *Finding
	for i := range fs {
		if fs[i].RuleID == "jp-phone-number" && fs[i].Match == testPhone {
			found = &fs[i]
		}
	}
	if found == nil {
		t.Fatalf("jp-phone-number が検出されない（パターン自体は文脈なしでも Base で検出されるはず）: %+v", fs)
	}
	if found.Confidence != rule.Medium {
		t.Errorf("confidence = %v, want Medium（列数不一致タプルには文脈が付与されないはず）", found.Confidence)
	}
	if found.Reason.ContextPromoted {
		t.Errorf("ContextPromoted = true, want false")
	}
}

// order_id 列の 7 桁の値は、口座番号ルールの負文脈（「注文 ID」を意味する
// order/id）によって銀行口座番号として誤検出されない。同じ行の
// bank_account 列自身の値は通常どおり検出されることも確認し、負文脈が
// ルールそのものを無効化しているのではなく、列単位で正しく効いている
// ことを示す。
func TestSQLInsertOrderIDColumnSuppressesBankAccountFalsePositive(t *testing.T) {
	d := newDetector(t, "")
	line := "INSERT INTO t (kouza,order_id) VALUES ('1234567',7654321);" // jp-pii-detector:ignore
	fs := d.ScanContent("dump.sql", line+"\n")

	gotBankAccountValue, gotOrderIDFalsePositive := false, false
	for _, f := range fs {
		if f.RuleID != "jp-bank-account" {
			continue
		}
		switch f.Match {
		case "1234567":
			gotBankAccountValue = true
		case "7654321":
			gotOrderIDFalsePositive = true
		}
	}
	if !gotBankAccountValue {
		t.Fatalf("kouza 列自身の口座番号が検出されない（前提条件が崩れている）: %+v", fs)
	}
	if gotOrderIDFalsePositive {
		t.Fatalf("order_id 列の値が銀行口座番号として誤検出された（負文脈が効いていない）: %+v", fs)
	}
}

// 同一行の複数タプル VALUES (...), (...) の両方が処理される。
func TestSQLInsertMultipleTuplesBothPromoted(t *testing.T) {
	d := newDetector(t, "")
	phones := []string{"03-1111-1111", "03-2222-2222"} // jp-pii-detector:ignore
	line := "INSERT INTO users (name, phone) VALUES ('架空一郎', '" + phones[0] + "'), ('架空二郎', '" + phones[1] + "');"
	fs := d.ScanContent("dump.sql", line+"\n")

	got := map[string]rule.Confidence{}
	for _, f := range fs {
		if f.RuleID == "jp-phone-number" {
			got[f.Match] = f.Confidence
		}
	}
	for _, phone := range phones {
		conf, ok := got[phone]
		if !ok {
			t.Errorf("%s が検出されない: %+v", phone, fs)
			continue
		}
		if conf != rule.High {
			t.Errorf("%s の confidence = %v, want High", phone, conf)
		}
	}
}

// 非 .sql ファイルには適用されない（同じ padding 構造・同じ内容でも、
// .txt では構造的な列コンテキストが働かず Medium のまま）。
func TestSQLContextDoesNotApplyToNonSQLFile(t *testing.T) {
	d := newDetector(t, "")
	const testPhone = "03-1234-5678" // jp-pii-detector:ignore
	padding := strings.Repeat("x", 80)
	line := "INSERT INTO t (padding, phone) VALUES ('" + padding + "', '" + testPhone + "');"
	fs := d.ScanContent("dump.txt", line+"\n")

	var found *Finding
	for i := range fs {
		if fs[i].RuleID == "jp-phone-number" && fs[i].Match == testPhone {
			found = &fs[i]
		}
	}
	if found == nil {
		t.Fatalf("jp-phone-number が検出されない: %+v", fs)
	}
	if found.Confidence != rule.Medium {
		t.Errorf("confidence = %v, want Medium（.txt では SQL 列コンテキストが働かないはず）", found.Confidence)
	}
}

// --- Part D: 氏名列（Part C・高再現率限定・scanSQLNameColumns） ---

// name 列の氏名は、person-name 相当の構造化検出（person-name-structured、
// csv_context.go の scanCSVNameColumns の SQL 版）により高再現率モードで
// 拾える。列名は rule.CSVNameHeaderRe と完全一致する必要があるため、CSV の
// TestCSVNameColumnPromotesRowsBeyondAdjacentWindow と同じ「氏名」を使う
// （裸の ASCII "name" は personNameLabelASCIIStrong に含まれず対象外。
// full_name 等の強いラベルなら ASCII でも拾える）。
func TestSQLInsertNameColumnDetectsStructuredName(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	line := "INSERT INTO users (氏名, memo) VALUES ('山田太郎', 'note');" // jp-pii-detector:ignore
	fs := d.ScanContent("dump.sql", line+"\n")

	found := false
	for _, f := range fs {
		if f.RuleID == "person-name-structured" && f.Match == "山田太郎" {
			found = true
			if f.Confidence != rule.Medium {
				t.Errorf("confidence = %v, want Medium", f.Confidence)
			}
		}
	}
	if !found {
		t.Fatalf("person-name-structured が検出されない: %+v", fs)
	}
}

// ASCII の強いラベル（full_name）でも同様に拾える。
func TestSQLInsertFullNameColumnDetectsStructuredName(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	line := "INSERT INTO users (full_name, memo) VALUES ('山田太郎', 'note');" // jp-pii-detector:ignore
	fs := d.ScanContent("dump.sql", line+"\n")

	found := false
	for _, f := range fs {
		if f.RuleID == "person-name-structured" && f.Match == "山田太郎" {
			found = true
		}
	}
	if !found {
		t.Fatalf("person-name-structured が検出されない: %+v", fs)
	}
}

// 高再現率が既定 OFF のときは氏名列の構造化検出も走らない（既定挙動を
// 変えない。csv_context.go の TestCSVNameColumnDisabledByDefault と同じ方針）。
func TestSQLInsertNameColumnDisabledByDefault(t *testing.T) {
	d := newDetector(t, "")
	line := "INSERT INTO users (氏名, memo) VALUES ('山田太郎', 'note');" // jp-pii-detector:ignore
	fs := d.ScanContent("dump.sql", line+"\n")

	for _, f := range fs {
		if f.RuleID == "person-name-structured" {
			t.Fatalf("高再現率 OFF なのに person-name-structured が検出された: %+v", fs)
		}
	}
}

// 複数タプルの両方の氏名列が検出される。
func TestSQLInsertNameColumnMultipleTuples(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	line := "INSERT INTO users (氏名) VALUES ('山田太郎'), ('鈴木花子');" // jp-pii-detector:ignore
	fs := d.ScanContent("dump.sql", line+"\n")

	got := map[string]bool{}
	for _, f := range fs {
		if f.RuleID == "person-name-structured" {
			got[f.Match] = true
		}
	}
	for _, name := range []string{"山田太郎", "鈴木花子"} {
		if !got[name] {
			t.Errorf("%s が検出されない: %+v", name, fs)
		}
	}
}
