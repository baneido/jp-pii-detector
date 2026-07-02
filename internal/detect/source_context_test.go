package detect

import (
	"strings"
	"testing"
)

func TestSourceKindForPath(t *testing.T) {
	positives := []string{"user.go", "user.ts", "user.py", "config.yaml", ".env", "service.properties"}
	for _, path := range positives {
		if sourceKindForPath(path) == sourceKindNone {
			t.Fatalf("sourceKindForPath(%q) = none", path)
		}
	}
	if sourceKindForPath("memo.txt") != sourceKindNone {
		t.Fatal("memo.txt should not enable source context")
	}
}

func TestSourceLineContextsExtractStatement(t *testing.T) {
	ctxs := sourceLineContexts("user.ts", []string{`const bankAccountNo = "1234567"`})
	if len(ctxs) != 1 || len(ctxs[0].Statements) != 1 {
		t.Fatalf("contexts = %#v, want one statement", ctxs)
	}
	stmt := ctxs[0].Statements[0]
	if stmt.PositiveText != "bank account no" {
		t.Fatalf("PositiveText = %q, want bank account no", stmt.PositiveText)
	}
	if stmt.NegativeText != "" {
		t.Fatalf("NegativeText = %q, want empty", stmt.NegativeText)
	}
	if stmt.Start <= 0 || stmt.End <= stmt.Start {
		t.Fatalf("invalid range: %+v", stmt)
	}
}

func TestSourceLineContextsNegativeText(t *testing.T) {
	ctxs := sourceLineContexts("user.ts", []string{`const orderId = "1234567"`})
	if len(ctxs) != 1 || len(ctxs[0].Statements) != 1 {
		t.Fatalf("contexts = %#v, want one statement", ctxs)
	}
	stmt := ctxs[0].Statements[0]
	if !strings.Contains(stmt.NegativeText, "id") || !strings.Contains(stmt.NegativeText, "order") {
		t.Fatalf("NegativeText = %q, want id and order", stmt.NegativeText)
	}
}

func TestFindSourceAssignmentOperatorSkipsQuotedOperators(t *testing.T) {
	tests := []struct {
		name      string
		segment   string
		wantPos   int
		wantWidth int
	}{
		{
			name:      "colon in assigned string",
			segment:   `const bankAccountNo = "version:1234567"`,
			wantPos:   strings.IndexByte(`const bankAccountNo = "version:1234567"`, '='),
			wantWidth: 1,
		},
		{
			name:      "walrus in assigned string",
			segment:   `bankAccountNo: "prefix:=1234567"`,
			wantPos:   strings.IndexByte(`bankAccountNo: "prefix:=1234567"`, ':'),
			wantWidth: 1,
		},
		{
			name:      "equals in quoted map key",
			segment:   `values["bank=account"] = "1234567"`,
			wantPos:   strings.LastIndexByte(`values["bank=account"] = "1234567"`, '='),
			wantWidth: 1,
		},
		{
			name:      "escaped quote before colon in assigned string",
			segment:   `bankAccountNo = "prefix\":1234567"`,
			wantPos:   strings.IndexByte(`bankAccountNo = "prefix\":1234567"`, '='),
			wantWidth: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPos, gotWidth, ok := findSourceAssignmentOperator(tt.segment)
			if !ok {
				t.Fatalf("findSourceAssignmentOperator(%q) ok = false, want true", tt.segment)
			}
			if gotPos != tt.wantPos || gotWidth != tt.wantWidth {
				t.Fatalf("findSourceAssignmentOperator(%q) = (%d, %d), want (%d, %d)", tt.segment, gotPos, gotWidth, tt.wantPos, tt.wantWidth)
			}
		})
	}
}

func TestSplitSourceStatementsKeepsBacktickStrings(t *testing.T) {
	// バッククォート（Go の raw string / JS テンプレートリテラル）内の
	// カンマ・セミコロンは文の区切りではない。findSourceAssignmentOperator が
	// バッククォートを文字列リテラルとして扱う（indexUnquotedByte）のと整合させる。
	tests := []struct {
		name string
		line string
		want []string
	}{
		{
			name: "comma inside backtick raw string",
			line: "config := `timeout=30,bankAccountNo:1234567`",
			want: []string{"config := `timeout=30,bankAccountNo:1234567`"},
		},
		{
			name: "semicolon inside backtick raw string",
			line: "q := `SELECT a; SELECT b`",
			want: []string{"q := `SELECT a; SELECT b`"},
		},
		{
			name: "real comma between statements still splits",
			line: "a := `x`, b := `y`",
			want: []string{"a := `x`", " b := `y`"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segs := splitSourceStatements(tt.line)
			got := make([]string, 0, len(segs))
			for _, sg := range segs {
				got = append(got, tt.line[sg.start:sg.end])
			}
			if len(got) != len(tt.want) {
				t.Fatalf("splitSourceStatements(%q) = %#v, want %#v", tt.line, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("splitSourceStatements(%q) = %#v, want %#v", tt.line, got, tt.want)
				}
			}
		})
	}
}

func TestSourceLineContextsSkipUnknownFiles(t *testing.T) {
	ctxs := sourceLineContexts("memo.txt", []string{`const bankAccountNo = "1234567"`})
	if len(ctxs) != 1 {
		t.Fatalf("contexts len = %d, want 1", len(ctxs))
	}
	if len(ctxs[0].Statements) != 0 {
		t.Fatalf("memo.txt statements = %#v, want none", ctxs[0].Statements)
	}
}

func TestSourceLineContextsSkipUnknownCrossLineFiles(t *testing.T) {
	ctxs := sourceLineContexts("memo.txt", []string{"bankAccountNo:", `"1234567"`})
	if len(ctxs) != 2 {
		t.Fatalf("contexts len = %d, want 2", len(ctxs))
	}
	if len(ctxs[0].Statements) != 0 || len(ctxs[1].Statements) != 0 {
		t.Fatalf("memo.txt contexts = %#v, want no statements", ctxs)
	}
}

// quoteStartsAt はクォート開始判定の中心ロジック（#54 で追加）。
// prefix と quote 文字を組み立てて渡し、クォート文字の位置（= len(prefix)）を
// 手計算せずに求めることで、境界インデックスの数え間違いを避ける。
func TestQuoteStartsAt(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		quote  byte
		suffix string
		want   bool
	}{
		{"行頭のクォートは開始とみなす", "", '"', `abc"`, true},
		{"空白直後のクォートは開始とみなす", `x = `, '"', `abc"`, true},
		{"コロン直後のクォートは開始とみなす", `x:`, '"', `abc"`, true},
		{"開き括弧直後のクォートは開始とみなす", `f(`, '"', `abc")`, true},
		// 回帰: コメント中の英語の省略形（don't 等）のアポストロフィは、直前が
		// 識別子内部の文字（区切り記号でも文字列プレフィックスでもない）のため
		// クォート開始とみなさない（#54: この判定漏れで行末までクォート中と
		// 誤認され、以降の文脈抽出が壊れていた）。
		{"識別子内部のアポストロフィは開始とみなさない(don't)", `don`, '\'', `t forget`, false},
		{"識別子内部のアポストロフィは開始とみなさない(it's)", `it`, '\'', `s fine`, false},
		// "user's" の "r" は文字列プレフィックス候補の文字だが、その直前が
		// 区切り記号ではなく識別子の続き（"use" の "e"）なので、プレフィックスとは
		// 扱わずクォート開始としない（誤検出防止）。
		{"識別子語尾のプレフィックス様の文字は誤認しない(user's)", `user`, '\'', `s token`, false},
		// Python のような文字列プレフィックス（f/r/b/u、1〜2 文字）は、
		// プレフィックスさらに直前が区切り記号（または行頭）ならクォート開始とみなす。
		{"f-string プレフィックス", `msg = f`, '"', `account={value}"`, true},
		{"raw string プレフィックス", `pattern = r`, '\'', `\d+'`, true},
		{"2 文字プレフィックス(rb)", `data = rb`, '\'', `\x00'`, true},
		{"2 文字プレフィックス(Rb) 大文字小文字混在", `data = Rb`, '\'', `\x00'`, true},
		// 3 文字連続する疑似プレフィックス（abr）は、2 文字を超えた分の直前が
		// 区切り記号ではないため、識別子の一部とみなしクォート開始としない。
		{"3文字の疑似プレフィックスは識別子の一部とみなす", `data = abr`, '\'', `x00'`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := tt.prefix + string(tt.quote) + tt.suffix
			pos := len(tt.prefix)
			if got := quoteStartsAt(line, pos); got != tt.want {
				t.Errorf("quoteStartsAt(%q, %d) = %v, want %v", line, pos, got, tt.want)
			}
		})
	}
}

// #54 の回帰ケース: コメント中の英語省略形のアポストロフィ（don't）で、
// splitSourceStatements / indexUnquotedByte の引用符状態機械が以降の行末までを
// 引用中と誤認し、代入演算子（:）が見つからず文脈抽出が丸ごと失われていた。
func TestSourceLineContextsCommentApostropheRegression(t *testing.T) {
	line := `// don't forget bank_account_order_id: 1234567`
	ctxs := sourceLineContexts("service.go", []string{line})
	if len(ctxs) != 1 || len(ctxs[0].Statements) != 1 {
		t.Fatalf("contexts = %#v, want one statement (アポストロフィで文脈抽出が失われている)", ctxs)
	}
	stmt := ctxs[0].Statements[0]
	if !strings.Contains(stmt.NegativeText, "id") || !strings.Contains(stmt.NegativeText, "order") {
		t.Fatalf("NegativeText = %q, want id and order", stmt.NegativeText)
	}
	if got := line[stmt.Start:stmt.End]; got != "1234567" {
		t.Fatalf("value = %q, want 1234567", got)
	}
}

// 上と同じ回帰ケースを ScanContent（統合レベル）で確認する。#54 修正前は
// アポストロフィ以降が「引用中」と誤認されて文脈抽出が失われ、
// order_id ラベルにもかかわらず銀行口座番号として誤検出（FP）していた。
func TestScanContentCommentApostropheDoesNotBreakSourceContext(t *testing.T) {
	d := newDetector(t, "")
	line := `// don't forget bank_account_order_id: 1234567`
	assertRules(t, d.ScanContent("service.go", line))
}

// splitSourceStatements のカンマ・セミコロンによる文分割も、コメント中の
// アポストロフィでクォート中と誤認されて壊れないことを確認する（#54）。
func TestSplitSourceStatementsApostropheInCommentDoesNotSuppressSplit(t *testing.T) {
	line := `// don't forget; log the value`
	segs := splitSourceStatements(line)
	got := make([]string, 0, len(segs))
	for _, sg := range segs {
		got = append(got, line[sg.start:sg.end])
	}
	want := []string{`// don't forget`, ` log the value`}
	if len(got) != len(want) {
		t.Fatalf("splitSourceStatements(%q) = %#v, want %#v", line, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("splitSourceStatements(%q) = %#v, want %#v", line, got, want)
		}
	}
}

// クォート種別をまたぐネストは、開いたクォートと異なる種類のクォート文字
// （バッククォート文字列中のアポストロフィ等）で閉じてしまわないことを
// 回帰確認する（既存の状態機械の性質。#54 の修正でも壊さないことを保証する）。
func TestSplitSourceStatementsApostropheInsideBacktickStringDoesNotClose(t *testing.T) {
	line := "config := `it's fine, 30`, next := `y`"
	segs := splitSourceStatements(line)
	got := make([]string, 0, len(segs))
	for _, sg := range segs {
		got = append(got, line[sg.start:sg.end])
	}
	want := []string{"config := `it's fine, 30`", " next := `y`"}
	if len(got) != len(want) {
		t.Fatalf("splitSourceStatements(%q) = %#v, want %#v", line, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("splitSourceStatements(%q) = %#v, want %#v", line, got, want)
		}
	}
}

// エスケープされたクォートに続くアポストロフィ的な文字でも、既存の
// エスケープ処理（quote != 0 のときのみ有効）が優先され、意図しないクォート
// 終了が起きないことを確認する。
func TestFindSourceAssignmentOperatorEscapedQuoteThenApostrophe(t *testing.T) {
	segment := `bankAccountNo = "it\'s 1234567"`
	pos, width, ok := findSourceAssignmentOperator(segment)
	if !ok {
		t.Fatalf("findSourceAssignmentOperator(%q) ok = false, want true", segment)
	}
	wantPos := strings.IndexByte(segment, '=')
	if pos != wantPos || width != 1 {
		t.Fatalf("findSourceAssignmentOperator(%q) = (%d, %d), want (%d, 1)", segment, pos, width, wantPos)
	}
}
