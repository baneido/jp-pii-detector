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
// SourceTag（source:synthetic）が付いていること、対応 7 ルールぶんの内容が
// あることを検証する。
func TestGenerateProducesTaggedSyntheticCases(t *testing.T) {
	cases := Generate()
	if len(cases) == 0 {
		t.Fatal("Generate() returned no cases")
	}
	wantRules := map[string]bool{
		"jp-my-number": false, "credit-card": false, "jp-postal-code": false, "person-name": false,
		"jp-phone-number": false, "jp-birthdate": false, "jp-address": false,
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

// TestToFullWidthAllConvertsAllASCIIAndSpace は toFullWidthAll が数字・記号・
// 半角スペース・英字を含む値全体を全角化することを検証する（toFullWidthDigits は
// 数字とハイフンのみが対象のため、電話番号の空白・括弧・+81 国際表記や生年月日の
// スラッシュ・ドット区切り・元号略記のアルファベットには使えない）。
func TestToFullWidthAllConvertsAllASCIIAndSpace(t *testing.T) {
	got := toFullWidthAll("+81-90 (1) S.2")
	want := "＋８１－９０　（１）　Ｓ．２"
	if got != want {
		t.Errorf("toFullWidthAll(...) = %q, want %q", got, want)
	}
}

// TestSyntheticPhoneDigitsAvoidsPlaceholderPatterns は syntheticPhoneDigits が
// 全桁同一にも昇順・降順連番にもならないことを、実際に使う seed・桁数を含む
// 組み合わせで検証する（validPhone の checksum.AllSame 棄却と、ダミー値としての
// 見た目の両方を回帰確認する）。
func TestSyntheticPhoneDigitsAvoidsPlaceholderPatterns(t *testing.T) {
	for seed := 0; seed < 4; seed++ {
		for _, length := range []int{4, 8} {
			got := syntheticPhoneDigits(seed, length)
			if len(got) != length {
				t.Fatalf("syntheticPhoneDigits(%d, %d) = %q, want length %d", seed, length, got, length)
			}
			if checksum.AllSame(got) {
				t.Errorf("syntheticPhoneDigits(%d, %d) = %q must not be all-same digits", seed, length, got)
			}
			if checksum.IsZeroPaddedSequential(got) {
				t.Errorf("syntheticPhoneDigits(%d, %d) = %q must not be a sequential run", seed, length, got)
			}
		}
	}
}

// TestPhoneNumberCasesMatrixShape は PhoneNumberCases() の件数（種別2 × 区切り4 ×
// 表記2 の陽性ケース + 陰性ケース2件）とタグ付与を検証する。
func TestPhoneNumberCasesMatrixShape(t *testing.T) {
	cases := PhoneNumberCases()
	positives, negatives := 0, 0
	for _, c := range cases {
		if !hasTagPrefix(c.Tags, SourceTag) {
			t.Errorf("case %q missing %s tag", caseLine(c), SourceTag)
		}
		if !hasTagPrefix(c.Tags, "rule:jp-phone-number") {
			t.Errorf("case %q missing rule:jp-phone-number tag", caseLine(c))
		}
		if len(c.Want) > 0 {
			positives++
		} else {
			negatives++
		}
	}
	const wantPositives = 2 * 4 * 2 // 種別(携帯/固定)2 × 区切り4 × 表記2
	if positives != wantPositives {
		t.Errorf("PhoneNumberCases() positive count = %d, want %d", positives, wantPositives)
	}
	if negatives != 2 {
		t.Errorf("PhoneNumberCases() negative count = %d, want 2", negatives)
	}
}

// TestBirthdateCasesMatrixShape は BirthdateCases() の件数（ラベル3 × 形式4 ×
// 表記2、すべて陽性）とタグ付与を検証する。
func TestBirthdateCasesMatrixShape(t *testing.T) {
	cases := BirthdateCases()
	const want = 3 * 4 * 2 // ラベル(生年月日/誕生日/DOB)3 × 形式4 × 表記2
	if len(cases) != want {
		t.Fatalf("BirthdateCases() = %d cases, want %d", len(cases), want)
	}
	for _, c := range cases {
		if !hasTagPrefix(c.Tags, SourceTag) {
			t.Errorf("case %q missing %s tag", caseLine(c), SourceTag)
		}
		if !hasTagPrefix(c.Tags, "rule:jp-birthdate") {
			t.Errorf("case %q missing rule:jp-birthdate tag", caseLine(c))
		}
		if len(c.Want) == 0 {
			t.Errorf("case %q should be positive (BirthdateCases has no negative cases)", caseLine(c))
		}
	}
}

// TestAddressCasesMatrixShape は AddressCases() の件数（(形式2 × 表記2) + 漢数字
// 番地1 の陽性ケース + 陰性ケース1件）とタグ付与を検証する。
func TestAddressCasesMatrixShape(t *testing.T) {
	cases := AddressCases()
	positives, negatives := 0, 0
	for _, c := range cases {
		if !hasTagPrefix(c.Tags, SourceTag) {
			t.Errorf("case %q missing %s tag", caseLine(c), SourceTag)
		}
		if !hasTagPrefix(c.Tags, "rule:jp-address") {
			t.Errorf("case %q missing rule:jp-address tag", caseLine(c))
		}
		if len(c.Want) > 0 {
			positives++
		} else {
			negatives++
		}
	}
	const wantPositives = 2*2 + 1 // (形式:banchi-marker/dash 2 × 表記2) + 漢数字番地1
	if positives != wantPositives {
		t.Errorf("AddressCases() positive count = %d, want %d", positives, wantPositives)
	}
	if negatives != 1 {
		t.Errorf("AddressCases() negative count = %d, want 1", negatives)
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
