package rule

import (
	"math"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

var (
	// ASCII メールの境界には全Unicode Letter/Numberを含める。高再現率モードが
	// 無効でも、EAI/confusable候補のASCII接尾部だけを通常メールとして
	// 切り出す部分一致を防ぐ。
	emailASCIIRe = regexp.MustCompile(`(?:^|[^\p{L}\p{N}._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:[^\p{L}\p{N}_%+:-]|$)`)
	// EAI はローカル部・ドメインとも Unicode Letter/Number を許す。左境界を
	// 空白・引用符・構造区切りへ限定し、日本語本文がローカル部へ吸着するのを防ぐ。
	emailEAIRe = regexp.MustCompile(`(?:^|[\s"'(<\[{=:,;|、])([\p{L}\p{N}._%+-]+@[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+)(?:[^\p{L}\p{N}_%+:-]|$)`)
	// confusable 候補は広めに切り出し、文字集合・混入率・ASCII スケルトンの
	// 妥当性を validConfusableEmail で厳密に検証する。
	emailConfusableRe = regexp.MustCompile(`(?:^|[^\p{L}\p{N}._%+-])([\p{L}\p{N}._%+-]+@[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+)(?:[^\p{L}\p{N}_%+:-]|$)`)
)

// validEAIEmail は日本語を含む EAI 候補を検証する。高再現率ルールの初期導入で
// 他言語本文まで対象を広げないよう、漢字・ひらがな・カタカナのいずれかを必須とする。
// ドメインは許容文字を Punycode 化し、既存の IANA TLD 辞書へ照合する。
// 正規化結果は検証だけに使うため、報告位置は常に原文と一致する。
func validEAIEmail(m string) bool {
	if len(m) > 254 {
		return false
	}
	at := strings.LastIndexByte(m, '@')
	if at <= 0 || at == len(m)-1 {
		return false
	}
	local, domain := m[:at], m[at+1:]
	if len(local) > 64 || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") ||
		strings.Contains(local, "..") || hasEAILabelPrefix(local) || !validEAILocal(local) {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	hasJapanese := containsJapanese(local)
	encodedDomainLen := len(labels) - 1
	for _, label := range labels {
		if !validEAIDomainLabel(label) {
			return false
		}
		if strings.EqualFold(label, "example") {
			return false
		}
		ascii, ok := punycodeDomainLabel(label)
		if !ok || len(ascii) > 63 {
			return false
		}
		encodedDomainLen += len(ascii)
		hasJapanese = hasJapanese || containsJapanese(label)
	}
	if !hasJapanese || encodedDomainLen > 253 ||
		containsEmailDummyWord(local) || containsEmailDummyWord(labels[0]) {
		return false
	}
	tld, ok := punycodeDomainLabel(labels[len(labels)-1])
	if !ok {
		return false
	}
	switch tld {
	case "test", "invalid", "localhost", "example", "local":
		return false
	}
	return dict.ValidTLD(tld)
}

// hasEAILabelPrefix は行頭の日本語ラベルが区切りなしでローカル部へ吸着した候補を
// 棄却する。EAI では日本語本文とローカル部の文字種だけでは境界を判定できないため、
// 高頻度ラベルに限定した安全側のガードを置く。
func hasEAILabelPrefix(local string) bool {
	for _, prefix := range []string{"メールアドレス", "メール", "連絡先", "連絡"} {
		if strings.HasPrefix(local, prefix) {
			return true
		}
	}
	return false
}

func validEAILocal(local string) bool {
	hasLetterOrNumber := false
	for _, r := range local {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			hasLetterOrNumber = true
			continue
		}
		switch r {
		case '.', '_', '%', '+', '-':
		default:
			return false
		}
	}
	return hasLetterOrNumber
}

func validEAIDomainLabel(label string) bool {
	if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return false
	}
	for _, r := range label {
		if r != '-' && !unicode.IsLetter(r) && !unicode.IsNumber(r) {
			return false
		}
	}
	return true
}

func containsJapanese(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) ||
			unicode.Is(unicode.Katakana, r) {
			return true
		}
	}
	return false
}

// validConfusableEmail は既知 confusable を 1〜2 文字だけ含む ASCII 中心候補を
// 検証する。英数字の 80% 以上かつ最低 6 文字が ASCII であることを要求し、
// ギリシャ語・キリル語の通常の EAI アドレスを難読化として扱わない。
func validConfusableEmail(m string) bool {
	var skeleton strings.Builder
	skeleton.Grow(len(m))
	asciiAlnum, identifierAlnum, confusables := 0, 0, 0
	for _, r := range m {
		if mapped, ok := emailConfusableASCII(r); ok {
			skeleton.WriteByte(mapped)
			identifierAlnum++
			confusables++
			continue
		}
		if r > unicode.MaxASCII {
			return false
		}
		skeleton.WriteByte(byte(r))
		if isASCIIAlnumByte(byte(r)) {
			asciiAlnum++
			identifierAlnum++
		}
	}
	if confusables == 0 || confusables > 2 || asciiAlnum < 6 ||
		asciiAlnum*5 < identifierAlnum*4 {
		return false
	}
	return validEmail(skeleton.String())
}

func isASCIIAlnumByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func emailConfusableASCII(r rune) (byte, bool) {
	switch r {
	case 'Α', 'А':
		return 'A', true
	case 'Β', 'В':
		return 'B', true
	case 'Ε', 'Е':
		return 'E', true
	case 'Η', 'Н':
		return 'H', true
	case 'Ι':
		return 'I', true
	case 'Κ', 'К':
		return 'K', true
	case 'Μ', 'М':
		return 'M', true
	case 'Ν':
		return 'N', true
	case 'Ο', 'О':
		return 'O', true
	case 'Ρ', 'Р':
		return 'P', true
	case 'С':
		return 'C', true
	case 'Τ', 'Т':
		return 'T', true
	case 'Υ':
		return 'Y', true
	case 'Χ', 'Х':
		return 'X', true
	case 'α', 'а':
		return 'a', true
	case 'ε', 'е':
		return 'e', true
	case 'ι', 'і':
		return 'i', true
	case 'κ':
		return 'k', true
	case 'ν':
		return 'v', true
	case 'ο', 'о':
		return 'o', true
	case 'ρ', 'р':
		return 'p', true
	case 'с':
		return 'c', true
	case 'τ':
		return 't', true
	case 'υ', 'у':
		return 'y', true
	case 'χ', 'х':
		return 'x', true
	case 'ѕ':
		return 's', true
	case 'ј':
		return 'j', true
	}
	return 0, false
}

// punycodeDomainLabel は RFC 3492 の Punycode 符号化を行う。呼び出し元が
// Letter/Number/ハイフンへ制限するため、IDNA の互換写像や正規化は行わない。
func punycodeDomainLabel(label string) (string, bool) {
	label = strings.ToLower(label)
	if label == "" || !utf8.ValidString(label) {
		return "", false
	}
	input := []rune(label)
	var out strings.Builder
	basic := 0
	for _, r := range input {
		if r < utf8.RuneSelf {
			out.WriteByte(byte(r))
			basic++
		}
	}
	if basic == len(input) {
		return out.String(), true
	}
	if basic > 0 {
		out.WriteByte('-')
	}
	n, delta, bias, handled := 128, 0, 72, basic
	for handled < len(input) {
		m := math.MaxInt
		for _, r := range input {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		if m == math.MaxInt || m-n > (math.MaxInt-delta)/(handled+1) {
			return "", false
		}
		delta += (m - n) * (handled + 1)
		n = m
		for _, r := range input {
			v := int(r)
			if v < n {
				if delta == math.MaxInt {
					return "", false
				}
				delta++
			}
			if v != n {
				continue
			}
			q := delta
			for k := 36; ; k += 36 {
				t := k - bias
				if t < 1 {
					t = 1
				} else if t > 26 {
					t = 26
				}
				if q < t {
					break
				}
				out.WriteByte(punycodeDigit(t + (q-t)%(36-t)))
				q = (q - t) / (36 - t)
			}
			out.WriteByte(punycodeDigit(q))
			bias = adaptPunycodeBias(delta, handled+1, handled == basic)
			delta = 0
			handled++
		}
		if delta == math.MaxInt || n == math.MaxInt {
			return "", false
		}
		delta++
		n++
	}
	return "xn--" + out.String(), true
}

func punycodeDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

func adaptPunycodeBias(delta, points int, first bool) int {
	if first {
		delta /= 700
	} else {
		delta /= 2
	}
	delta += delta / points
	k := 0
	for delta > 455 {
		delta /= 35
		k += 36
	}
	return k + 36*delta/(delta+38)
}
