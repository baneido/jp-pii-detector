package jppii

import (
	"testing"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/publiceval"
)

// 架空のテスト値だけを使う。
const spanDummy = "担当: 見本 花子\n電話番号: 090-0000-0000\nメール: hanako@example.jp\n" // jp-pii-detector:ignore 架空のテスト値

func checkSpans(t *testing.T, text string, res Result) (withOffset int) {
	t.Helper()
	for _, f := range res.Findings {
		if !f.HasOffset {
			continue
		}
		withOffset++
		if f.ByteOffset < 0 || f.ByteEndOffset > len(text) || f.ByteOffset > f.ByteEndOffset {
			t.Fatalf("%s: byte span out of range [%d,%d) len=%d", f.RuleID, f.ByteOffset, f.ByteEndOffset, len(text))
		}
		if got := text[f.ByteOffset:f.ByteEndOffset]; got != f.Match {
			t.Fatalf("%s: text[ByteOffset:ByteEndOffset] != Match", f.RuleID)
		}
		if got := utf8.RuneCountInString(text[:f.ByteOffset]); got != f.Offset {
			t.Fatalf("%s: Offset=%d, want %d", f.RuleID, f.Offset, got)
		}
		if got := f.Offset + utf8.RuneCountInString(f.Match); got != f.EndOffset {
			t.Fatalf("%s: EndOffset=%d, want %d", f.RuleID, f.EndOffset, got)
		}
	}
	return withOffset
}

func TestScanTextSpanFields(t *testing.T) {
	s, err := NewScanner(Options{ConfigTOML: ptr(""), DisableIgnoreMarkers: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, text := range []string{spanDummy, "\uFEFF" + spanDummy, "\r\n" + spanDummy} {
		res := s.ScanText("<test>", text)
		if len(res.Findings) == 0 {
			t.Fatal("no findings")
		}
		if n := checkSpans(t, text, res); n != len(res.Findings) {
			t.Fatalf("only %d/%d findings have offsets", n, len(res.Findings))
		}
		if res.BOMStripped != (text[0] == 0xEF) || res.EscapesDecoded {
			t.Fatalf("BOMStripped=%v EscapesDecoded=%v", res.BOMStripped, res.EscapesDecoded)
		}
		for _, f := range res.Findings {
			if f.Kind != "pii" || f.Reason.Source != SourceRule || f.Reason.Model || f.Reason.External {
				t.Fatalf("unexpected kind/reason: %s %q %+v", f.RuleID, f.Kind, f.Reason)
			}
			if f.RuleID == "jp-phone-number" && f.SubKind != "mobile" {
				t.Fatalf("SubKind = %q, want mobile", f.SubKind)
			}
		}
	}
}

func TestDisableIgnoreMarkers(t *testing.T) {
	line := "電話番号: 090-0000-0000 // jp-pii-detector:ignore 架空のテスト値\n"
	def, err := NewScanner(Options{ConfigTOML: ptr("")})
	if err != nil {
		t.Fatal(err)
	}
	if res := def.ScanText("<test>", line); len(res.Findings) != 0 {
		t.Fatalf("default must honour the ignore marker: %d findings", len(res.Findings))
	}
	off, err := NewScanner(Options{ConfigTOML: ptr(""), DisableIgnoreMarkers: true})
	if err != nil {
		t.Fatal(err)
	}
	res := off.ScanText("<test>", line)
	var found bool
	for _, f := range res.Findings {
		if f.RuleID == "jp-phone-number" && f.Match == "090-0000-0000" {
			found = true
		}
	}
	if !found {
		t.Fatalf("DisableIgnoreMarkers must report the phone number: %+v", res.Findings)
	}
}

func TestNoDecodeEscapes(t *testing.T) {
	// "見本" を JSON のエスケープで書いた架空の値。
	text := `{"name": "\u898b\u672c \u82b1\u5b50", "tel": "090-0000-0000"}` + "\n"
	def, err := NewScanner(Options{ConfigTOML: ptr("")})
	if err != nil {
		t.Fatal(err)
	}
	res := def.ScanText("<test>", text)
	if !res.EscapesDecoded {
		t.Fatal("default should decode escapes")
	}
	for _, f := range res.Findings {
		if f.HasOffset {
			t.Fatalf("offsets must not be set when escapes were decoded: %+v", f)
		}
	}
	raw, err := NewScanner(Options{ConfigTOML: ptr(""), NoDecodeEscapes: true})
	if err != nil {
		t.Fatal(err)
	}
	res = raw.ScanText("<test>", text)
	if res.EscapesDecoded {
		t.Fatal("NoDecodeEscapes must skip decoding")
	}
	if checkSpans(t, text, res) != len(res.Findings) || len(res.Findings) == 0 {
		t.Fatalf("all findings should carry offsets: %+v", res.Findings)
	}
}

// 公開合成コーパスの全ケースで、付いた位置がいつも Match を指すことを確かめる。
func TestSpansOnPublicSyntheticCorpus(t *testing.T) {
	for _, opts := range []Options{{ConfigTOML: ptr("")}, {ConfigTOML: ptr(""), HighRecall: true, NameRoster: true, MinConfidence: "low"}} {
		s, err := NewScanner(opts)
		if err != nil {
			t.Fatal(err)
		}
		var total, with int
		for _, c := range publiceval.Cases() {
			text := c.Content
			if text == "" {
				text = c.Line
			}
			if text == "" {
				continue
			}
			res := s.ScanText(c.File, text)
			total += len(res.Findings)
			w := checkSpans(t, text, res)
			with += w
			if !res.EscapesDecoded && w != len(res.Findings) {
				t.Errorf("case %s: %d/%d findings without offsets", c.ID, len(res.Findings)-w, len(res.Findings))
			}
		}
		t.Logf("high-recall=%v: %d/%d findings with offsets", opts.HighRecall, with, total)
		if total == 0 {
			t.Fatal("no findings on corpus")
		}
	}
}
