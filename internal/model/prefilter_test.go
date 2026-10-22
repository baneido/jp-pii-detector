package model

import (
	"reflect"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/external"
)

// ダミー値のみを使う。
func TestCandidateLine(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"func main() {", false},
		{"\treturn x + 1", false},
		{"version = 1.2.3", false},
		{"// 担当: 山田", true},
		{"ｔｅｓｔ", true},
		{"mail: someone@example.com", true},
		{"tel 090-1234-5678", true},
		{"id := 12345", false},
		{"dob 1990/01/02", true},
		{"Taro Yamada", true},
		{"yamada taro", true},
		{"return Some Value", false},
		{"x = y", false},
		{"taro, yamada", false},
		{strings.Repeat("a", maxCandidateLineBytes) + " 山田", false},
	}
	for _, c := range cases {
		if got := candidateLine(c.line); got != c.want {
			t.Errorf("candidateLine(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

func TestNumericCandidate(t *testing.T) {
	cases := map[string]bool{
		"1234567":        true,
		"123456":         false,
		"03-1234-5678":   true,
		"(03) 1234 5678": true,
		"1990.01.02":     true,
		"1.2.3":          false,
		"abc1234def567":  false,
		"v1.20.300":      true,
	}
	for in, want := range cases {
		if got := numericCandidate(in); got != want {
			t.Errorf("numericCandidate(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSelectLinesIncludesContext(t *testing.T) {
	lines := []string{"a := 1", "b := 2", "// 連絡先", "c := 3", "d := 4", "e := 5"}
	got := selectLines(lines)
	want := []bool{false, true, true, true, false, false}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selectLines = %v, want %v", got, want)
	}
}

func TestJoinSelectedAndRemapLines(t *testing.T) {
	lines := []string{"l0", "l1", "l2", "l3", "l4", "l5"}
	sel := []bool{false, true, true, false, false, true}
	short, orig := joinSelected(lines, sel)
	if short != "l1\nl2\n\nl5" {
		t.Fatalf("joinSelected text = %q", short)
	}
	if !reflect.DeepEqual(orig, []int{1, 2, -1, 5}) {
		t.Fatalf("joinSelected orig = %v", orig)
	}
	cands := []external.Candidate{
		{RuleID: "a", Line: 1, Column: 2, Length: 1},
		{RuleID: "sep", Line: 3, Column: 1, Length: 1},
		{RuleID: "b", Line: 4, Column: 1, Length: 2},
		{RuleID: "oob", Line: 9, Column: 1, Length: 1},
	}
	got := remapLines(cands, orig)
	want := []external.Candidate{
		{RuleID: "a", Line: 2, Column: 2, Length: 1},
		{RuleID: "b", Line: 6, Column: 1, Length: 2},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("remapLines = %+v, want %+v", got, want)
	}
	// 縮めたテキストの各行は元の行と同じ中身（列がずれない）。
	for i, s := range strings.Split(short, "\n") {
		if orig[i] >= 0 && s != lines[orig[i]] {
			t.Errorf("line %d = %q, want %q", i, s, lines[orig[i]])
		}
	}
}
