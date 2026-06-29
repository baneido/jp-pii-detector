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
