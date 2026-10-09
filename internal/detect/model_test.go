package detect

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/external"
)

// wordModel は text 中の word の出現をすべて person-name の候補として返す偽のモデル。
type wordModel struct {
	word string
	err  error
}

func (m wordModel) Recognize(text string) ([]external.Candidate, error) {
	if m.err != nil {
		return nil, m.err
	}
	var out []external.Candidate
	for i, line := range strings.Split(text, "\n") {
		for off := 0; ; {
			k := strings.Index(line[off:], m.word)
			if k < 0 {
				break
			}
			col := utf8.RuneCountInString(line[:off+k]) + 1
			out = append(out, external.Candidate{RuleID: "person-name", Line: i + 1, Column: col,
				Length: utf8.RuneCountInString(m.word), Confidence: "high"})
			off += k + len(m.word)
		}
	}
	return out, nil
}

func TestScanContentIncludesModelFindings(t *testing.T) {
	d := newDetector(t, "")
	d.SetModel(wordModel{word: "XYZW"})
	got := d.ScanContent("f.txt", "一行目\n連絡は XYZW まで\nXYZW です jp-pii-detector:ignore\n")
	if len(got) != 1 {
		t.Fatalf("got %+v, want 1（ignore マーカーの行は抑制）", got)
	}
	f := got[0]
	if f.RuleID != "person-name" || f.Line != 2 || f.Column != 5 || f.Match != "XYZW" || !f.Reason.Model || f.Reason.External {
		t.Errorf("got %+v reason=%+v", f, f.Reason)
	}
}

func TestScanContentModelRespectsDisabledRules(t *testing.T) {
	d := newDetector(t, "[rules]\ndisabled = [\"person-name\"]\n")
	d.SetModel(wordModel{word: "XYZW"})
	if got := d.ScanContent("f.txt", "連絡は XYZW まで\n"); len(got) != 0 {
		t.Errorf("無効化したルール ID のモデル候補が残った: %+v", got)
	}
}

func TestScanDiffHunkReportsModelFindingsOnAddedLinesOnly(t *testing.T) {
	d := newDetector(t, "")
	d.SetModel(wordModel{word: "XYZW"})
	got := d.ScanDiffHunk("f.txt", []DiffLine{
		{Text: "既存の XYZW", Added: false},
		{Text: "追加した XYZW", Added: true},
	})
	if len(got) != 1 || got[0].Line != 2 {
		t.Errorf("got %+v, want 追加行（2 行目）の 1 件だけ", got)
	}
}

func TestModelErrorIsRecorded(t *testing.T) {
	d := newDetector(t, "")
	d.SetModel(wordModel{err: errors.New("boom")})
	if got := d.ScanContent("f.txt", "XYZW\n"); len(got) != 0 {
		t.Errorf("got %+v", got)
	}
	if err := d.ModelError(); err == nil || !strings.Contains(err.Error(), "f.txt") {
		t.Errorf("ModelError() = %v, want f.txt を含むエラー", err)
	}
}
