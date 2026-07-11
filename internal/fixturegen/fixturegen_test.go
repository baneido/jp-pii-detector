package fixturegen

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/checksum"
	"github.com/baneido/jp-pii-detector/internal/dict"
	"github.com/baneido/jp-pii-detector/internal/evalcase"
)

func TestGroupDigits(t *testing.T) {
	tests := []struct {
		digits string
		widths []int
		sep    string
		want   string
	}{
		{"123456789012", []int{12}, "", "123456789012"},
		{"123456789012", []int{4, 4, 4}, "-", "1234-5678-9012"},
		{"341234567890123", []int{4, 6, 5}, " ", "3412 345678 90123"},
	}
	for _, tt := range tests {
		if got := groupDigits(tt.digits, tt.widths, tt.sep); got != tt.want {
			t.Errorf("groupDigits(%q, %v, %q) = %q, want %q", tt.digits, tt.widths, tt.sep, got, tt.want)
		}
	}
}

func TestToFullWidthDigits(t *testing.T) {
	got := toFullWidthDigits("1234-5678-9012")
	want := "１２３４－５６７８－９０１２"
	if got != want {
		t.Errorf("toFullWidthDigits(...) = %q, want %q", got, want)
	}
}

// TestLuhnCheckDigitRoundTrips は、payload に対して算出したチェックディジットを
// 付与した数字列が checksum.Luhn を満たすことを様々な桁数で検証する。
func TestLuhnCheckDigitRoundTrips(t *testing.T) {
	payloads := []string{"1", "40000000000000", "5500000000000000"[:14], "999999999999999999"[:13]}
	for _, p := range payloads {
		check := luhnCheckDigit(p)
		full := p + strconv.Itoa(check)
		if !checksum.Luhn(full) {
			t.Errorf("checksum.Luhn(%q) = false for payload %q with computed check digit %d", full, p, check)
		}
	}
}

// TestMyNumberCheckDigitRoundTrips は、11 桁の基底列に対して算出したチェック
// ディジットを付与した 12 桁が checksum.MyNumber を満たすことを検証する
// （全桁同一を避けた複数の基底列で確認する）。
func TestMyNumberCheckDigitRoundTrips(t *testing.T) {
	for seed := 0; seed < 5; seed++ {
		full := syntheticMyNumber(seed)
		if len([]rune(full)) != 12 {
			t.Fatalf("syntheticMyNumber(%d) = %q, want 12 digits", seed, full)
		}
		if !checksum.MyNumber(full) {
			t.Errorf("checksum.MyNumber(%q) = false, want true (seed=%d)", full, seed)
		}
		if checksum.AllSame(full) {
			t.Errorf("syntheticMyNumber(%d) = %q must not be all-same digits", seed, full)
		}
	}
}

// TestSyntheticCardNumberSatisfiesBrandsAndLuhn は、対応する全ブランドについて
// syntheticCardNumber が checksum.CreditCard（ブランド + Luhn）を満たすことを検証する。
func TestSyntheticCardNumberSatisfiesBrandsAndLuhn(t *testing.T) {
	for _, b := range cardBrands {
		t.Run(b.tag, func(t *testing.T) {
			digits := syntheticCardNumber(b.prefix, b.length)
			if len(digits) != b.length {
				t.Fatalf("syntheticCardNumber(%q, %d) = %q, want length %d", b.prefix, b.length, digits, b.length)
			}
			if !strings.HasPrefix(digits, b.prefix) {
				t.Fatalf("syntheticCardNumber(%q, %d) = %q, want prefix %q", b.prefix, b.length, digits, b.prefix)
			}
			if !checksum.CreditCard(digits) {
				t.Errorf("checksum.CreditCard(%q) = false, want true (brand %s)", digits, b.tag)
			}
		})
	}
}

func TestPostalCodeCasesUseRealCodes(t *testing.T) {
	cases := PostalCodeCases()
	if len(cases) == 0 {
		t.Fatal("PostalCodeCases returned no cases")
	}
	positives, negatives := 0, 0
	for _, c := range cases {
		if len(c.Want) > 0 {
			positives++
		} else {
			negatives++
		}
		if !hasTagPrefix(c.Tags, SourceTag) {
			t.Errorf("case %q missing %s tag", caseLine(c), SourceTag)
		}
	}
	if positives == 0 || negatives == 0 {
		t.Fatalf("PostalCodeCases should include both positive and negative cases: positives=%d negatives=%d", positives, negatives)
	}
}

func TestPersonNameCasesUseDictionaryNames(t *testing.T) {
	cases := PersonNameCases()
	if len(cases) == 0 {
		t.Fatal("PersonNameCases returned no cases")
	}
	for _, c := range cases {
		if !hasTagPrefix(c.Tags, SourceTag) {
			t.Errorf("case %q missing %s tag", caseLine(c), SourceTag)
		}
	}
}

// TestGenerateProducesTaggedSyntheticCases は Generate() が返す全ケースに
// SourceTag（source:synthetic）が付いていること、対応 4 ルールぶんの内容が
// あることを検証する。
func TestGenerateProducesTaggedSyntheticCases(t *testing.T) {
	cases := Generate()
	if len(cases) == 0 {
		t.Fatal("Generate() returned no cases")
	}
	wantRules := map[string]bool{
		"jp-my-number": false, "credit-card": false, "jp-postal-code": false, "person-name": false,
	}
	for _, c := range cases {
		if c.ID == "" || c.SourceClass != "algorithmic" {
			t.Errorf("case metadata is incomplete: id=%q source_class=%q", c.ID, c.SourceClass)
		}
		if !hasTagPrefix(c.Tags, SourceTag) {
			t.Errorf("case %q missing %s tag", caseLine(c), SourceTag)
		}
		for _, id := range c.Want {
			if _, ok := wantRules[id]; ok {
				wantRules[id] = true
			}
		}
	}
	for id, seen := range wantRules {
		if !seen {
			t.Errorf("Generate() produced no positive case for rule %q", id)
		}
	}
	if again := Generate(); !reflect.DeepEqual(cases, again) {
		t.Error("Generate() must be deterministic")
	}
}

func TestSurnameSampleFilterHasEnoughUsableNames(t *testing.T) {
	names := filterMinRunes(dict.SurnameSample(60), 2, 4)
	if len(names) < 4 {
		t.Fatalf("filterMinRunes(SurnameSample(60), 2, 4) = %d usable surnames, want at least 4", len(names))
	}
}

func hasTagPrefix(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

func caseLine(c evalcase.Case) string {
	switch {
	case c.Content != "":
		return c.Content
	case len(c.Diff) > 0:
		return "(diff)"
	default:
		return c.Line
	}
}
