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
