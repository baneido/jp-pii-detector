// Package testfixtures は、公開リポジトリ内の単体・結合テストで使う
// 決定的な合成値を提供する。
//
// ここで返す値は実人物から採取したものではなく、人物の複数属性を相互に
// 結び付けない。ただし、チェックディジットや書式を満たす値が実在する番号空間と
// 偶然一致しないことまでは保証できない。そのため値をログへ出さず、外部評価
// コーパスの精度指標にも混ぜない。
package testfixtures

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// TB は *testing.T / *testing.B が満たす最小インターフェース。
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// MustGet は移行中の既存テスト向け互換API。新規テストでは Phone などの
// 型付きヘルパーを直接使うこと。
func MustGet(t TB, key string) string {
	t.Helper()
	v, ok := value(key)
	if !ok {
		t.Fatalf("公開テストフィクスチャにキー %q がありません", key)
	}
	return v
}

// Phone は決定的な携帯電話形式を返す。seed は異なるケースを作る識別子。
func Phone(seed int, separated bool) string {
	prefixes := []string{"090", "080", "070"}
	digits := prefixes[seed%len(prefixes)] + digitRun(seed+11, 8)
	if !separated {
		return digits
	}
	return digits[:3] + "-" + digits[3:7] + "-" + digits[7:]
}

func fixedPhone(seed int, separated bool) string {
	digits := "03" + digitRun(seed+31, 8)
	if !separated {
		return digits
	}
	return digits[:2] + "-" + digits[2:6] + "-" + digits[6:]
}

func ipPhone(seed int) string {
	digits := "050" + digitRun(seed+51, 8)
	return digits[:3] + "-" + digits[3:7] + "-" + digits[7:]
}

func digitRun(seed, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(byte('0' + (seed*7+i*3+1)%10))
	}
	return b.String()
}

func myNumber(seed int) string {
	base := digitRun(seed+71, 11)
	sum := 0
	for n := 1; n <= 11; n++ {
		p := int(base[11-n] - '0')
		q := n + 1
		if n >= 7 {
			q = n - 5
		}
		sum += p * q
	}
	check := 11 - sum%11
	if check >= 10 {
		check = 0
	}
	return base + strconv.Itoa(check)
}

func group(s string, widths ...int) string {
	var out []string
	i := 0
	for _, w := range widths {
		out = append(out, s[i:i+w])
		i += w
	}
	return strings.Join(out, "-")
}

func toFullWidth(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r - '0' + '０')
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r - 'A' + 'Ａ')
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'ａ')
		case r == '-':
			b.WriteRune('－')
		case r == '@':
			b.WriteRune('＠')
		case r == ' ':
			b.WriteRune('　')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func postal(index int) string {
	codes := dict.SamplePostalCodes(index + 1)
	if len(codes) <= index {
		panic("郵便番号辞書に合成テスト用候補がありません")
	}
	c := codes[index]
	return c[:3] + "-" + c[3:]
}

func nameParts(index int, kana bool) (string, string) {
	surnames := filterNames(dict.SurnameSample(20000), kana)
	givens := filterNames(dict.GivenNameSample(20000), kana)
	if len(surnames) == 0 || len(givens) == 0 {
		panic("姓名辞書に合成テスト用候補がありません")
	}
	return surnames[index%len(surnames)], givens[(index*7+3)%len(givens)]
}

func filterNames(in []string, kana bool) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		rs := []rune(s)
		if len(rs) < 2 || len(rs) > 4 {
			continue
		}
		allKana := true
		allKanji := true
		for _, r := range rs {
			if r < 'ァ' || r > 'ヶ' {
				allKana = false
			}
			if !unicode.Is(unicode.Han, r) {
				allKanji = false
			}
		}
		if (kana && allKana) || (!kana && allKanji) {
			out = append(out, s)
		}
	}
	return out
}

func fullName(index int, spaced, kana bool) string {
	s, g := nameParts(index, kana)
	sep := ""
	if spaced {
		sep = " "
	}
	return s + sep + g
}

func oneRuneGiven() string {
	for _, s := range dict.GivenNameSample(20000) {
		if len([]rune(s)) == 1 {
			return s
		}
	}
	panic("姓名辞書に1文字名がありません")
}

func email(seed int, domain string) string {
	return fmt.Sprintf("codexfixture%02d@%s", seed, domain)
}

func value(key string) (string, bool) {
	mobile := Phone(1, true)
	mobileNoSep := Phone(1, false)
	fixed := fixedPhone(1, true)
	ip := ipPhone(1)
	mynum := myNumber(1)
	surname, given := nameParts(1, false)
	kanaSurname, kanaGiven := nameParts(1, true)

	switch key {
	case "phone.mobile", "cmd.phone_mobile_sep", "source.phone_mobile_sep", "detect.phone_mobile_sep", "rule.phone_mobile_sep", "report.phone_match", "detect.finding_phone":
		return mobile, true
	case "phone.mobile_nosep", "cmd.phone_mobile_nosep", "source.phone_mobile_nosep", "detect.phone_mobile_nosep", "rule.phone_mobile_nosep":
		return mobileNoSep, true
	case "detect.phone_mobile_sep_a":
		return Phone(2, true), true
	case "detect.phone_mobile_sep_b":
		return Phone(3, true), true
	case "detect.phone_mobile_sep_c":
		return Phone(4, true), true
	case "detect.phone_mobile_nosep_a":
		return Phone(2, false), true
	case "detect.phone_mobile_nosep_b":
		return Phone(3, false), true
	case "detect.phone_fixed_tokyo", "rule.phone_landline_sep":
		return fixed, true
	case "detect.phone_ip", "rule.phone_ip_sep":
		return ip, true
	case "detect.phone_intl_mobile", "rule.phone_mobile_intl":
		return "+81-" + mobile[1:], true
	case "detect.phone_intl_fixed", "rule.phone_landline_intl":
		return "+81-" + fixed[1:], true
	case "detect.phone_mobile_fullwidth":
		return toFullWidth(mobile), true
	case "detect.phone_mobile_fullwidth_longvowel":
		return strings.ReplaceAll(toFullWidth(mobile), "－", "ー"), true
	case "detect.phone_mobile_stopword":
		return Phone(8, true), true
	case "detect.phone_mobile_stopword_fullwidth":
		return toFullWidth(Phone(8, true)), true
	case "detect.mynumber_valid":
		return mynum, true
	case "detect.mynumber_valid_sep":
		return group(mynum, 4, 4, 4), true
	case "detect.mynumber_valid_fullwidth":
		return toFullWidth(mynum), true
	case "detect.postal_osaka":
		return postal(0), true
	case "detect.postal_shibuya":
		return postal(1), true
	case "detect.address_umeda":
		return "大阪" + "府大阪市北区梅田" + "1丁目2番3号", true
	case "detect.address_umeda_full":
		return "大阪" + "府大阪市北区梅田" + "1丁目2番3号", true
	case "detect.address_shibuya":
		return "東京" + "都渋谷区神南" + "1丁目2番3号", true
	case "detect.address_shibuya_ward", "address.shibuya_ward":
		return "渋谷区神南" + "1丁目2番3号", true
	case "detect.email_gmail":
		return email(1, "baneido.com"), true
	case "detect.email_gmail_a":
		return email(2, "baneido.com"), true
	case "detect.email_gmail_b":
		return email(3, "baneido.com"), true
	case "detect.email_gmail_fullwidth_at":
		return strings.Replace(email(1, "baneido.com"), "@", "＠", 1), true
	case "detect.email_subdomain":
		return "codex.fixture+tag" + "@" + "fixtures.baneido.com", true
	case "detect.email_dev":
		return email(4, "baneido.com"), true
	case "detect.email_baneido":
		return email(5, "baneido.com"), true
	case "detect.drivers_license":
		return "30" + digitRun(91, 10), true
	case "detect.passport":
		return "AB" + digitRun(92, 7), true
	case "detect.pension_number":
		return digitRun(93, 10), true
	case "detect.pension_number_sep":
		p := digitRun(93, 10)
		return p[:4] + "-" + p[4:], true
	case "detect.residence_card":
		return "AB" + digitRun(94, 8) + "CD", true
	case "detect.bank_account":
		return digitRun(95, 7), true
	case "detect.health_insurance":
		return digitRun(96, 8), true
	case "detect.birthdate_seireki":
		return "1992年3月14日", true
	case "detect.birthdate_wareki":
		return "平成4年3月14日", true
	case "detect.name_full":
		return surname + given, true
	case "detect.name_full_spaced":
		return surname + " " + given, true
	case "detect.name_sei":
		return surname, true
	case "detect.name_mei":
		return given, true
	case "detect.name_kana_full":
		return kanaSurname + kanaGiven, true
	case "detect.name_kana_full_wide":
		return kanaSurname + "　" + kanaGiven, true
	case "detect.name_dict_external_full":
		return "龍" + "凰" + "蒼" + "月", true
	case "detect.name_sei_plus_one_mei":
		return surname + oneRuneGiven(), true
	case "detect.name_sato_hanako":
		return fullName(2, false, false), true
	case "detect.name_sato_ichiro_spaced":
		return fullName(3, true, false), true
	case "detect.name_suzuki_hanako":
		return fullName(4, false, false), true
	case "detect.name_suzuki_ichiro":
		return fullName(5, false, false), true
	case "detect.name_takahashi_kenta":
		return fullName(6, false, false), true
	case "detect.name_tanaka_hanako":
		return fullName(7, false, false), true
	case "detect.name_tanaka_taro":
		return fullName(8, false, false), true
	case "detect.name_ito_misaki_spaced":
		return fullName(9, true, false), true
	case "normalize.name_fullwidth_in":
		return "ＡＢＣ　１２３", true
	case "normalize.name_fullwidth_out":
		return "ABC 123", true
	case "normalize.fw_phone_in":
		return toFullWidth(mobile), true
	case "normalize.fw_phone_out":
		return mobile, true
	case "normalize.hyphen_phone_in":
		return strings.ReplaceAll(mobile, "-", "―"), true
	case "normalize.hyphen_phone_out":
		return mobile, true
	case "normalize.lv_phone_in":
		return strings.ReplaceAll(mobile, "-", "ー"), true
	case "normalize.lv_phone_out":
		return mobile, true
	case "normalize.small_hyphen_phone_in":
		return strings.ReplaceAll(mobile, "-", "﹣"), true
	case "normalize.small_hyphen_phone_out":
		return mobile, true
	case "normalize.postal_addr_in":
		return toFullWidth(postal(0)) + "　" + "大阪府", true
	case "normalize.fw_lv_phone_bench":
		return strings.ReplaceAll(toFullWidth(mobile), "－", "ー"), true
	case "report.phone_for_mask":
		return "09" + strings.Repeat("x", 9) + "00", true
	case "report.phone_fullwidth_in":
		return "０９" + strings.Repeat("あ", 7) + "００", true
	}
	return "", false
}
