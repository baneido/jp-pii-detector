// Package checksum は番号体系ごとのチェックディジット検証を提供する。
package checksum

import "strings"

// AllSame は全桁同一（明らかなダミー値）かどうかを返す。
func AllSame(digits string) bool {
	if digits == "" {
		return false
	}
	return strings.Count(digits, digits[:1]) == len(digits)
}

// IsZeroPaddedSequential は「先頭ゼロ埋め＋末尾が昇順連番」または「全体が
// 公差 1 の昇順・降順の等差数列」である、明らかなダミー値らしい数字列かを
// 返す（0000001 / 0000123 / 1234567 / 9876543210 等）。
// マイナンバー・運転免許証番号の Validate から利用する（用途ごとの意味づけは
// 呼び出し側のコメントを参照）。
func IsZeroPaddedSequential(digits string) bool {
	if len(digits) < 2 || !numeric(digits) {
		return false
	}
	i := 0
	for i < len(digits)-1 && digits[i] == '0' {
		i++
	}
	if i > 0 && isSequentialRun(digits[i:], true) {
		return true
	}
	return isSequentialRun(digits, true) || isSequentialRun(digits, false)
}

// isSequentialRun は digits が公差 1 の等差数列（ascending なら昇順、そうで
// なければ降順）かどうかを返す。1 桁以下は常に true（呼び出し側で長さ制約済み）。
func isSequentialRun(digits string, ascending bool) bool {
	for i := 1; i < len(digits); i++ {
		prev := int(digits[i-1] - '0')
		cur := int(digits[i] - '0')
		if ascending {
			if cur != prev+1 {
				return false
			}
		} else if cur != prev-1 {
			return false
		}
	}
	return true
}

// MyNumber は個人番号（マイナンバー）12 桁の検査用数字を検証する。
// アルゴリズムは総務省令（平成 26 年総務省令第 85 号）第 5 条による:
//
//	Pn = 検査用数字を除いた 11 桁のうち末尾から n 桁目の数字
//	Qn = n+1 (n <= 6), n-5 (n >= 7)
//	検査用数字 = 11 - (ΣPn*Qn mod 11)、ただし mod 11 <= 1 のとき 0
func MyNumber(digits string) bool {
	if len(digits) != 12 || !numeric(digits) || AllSame(digits) {
		return false
	}
	sum := 0
	for n := 1; n <= 11; n++ {
		p := int(digits[11-n] - '0')
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
	return int(digits[11]-'0') == check
}

// Luhn は Luhn アルゴリズム（ISO/IEC 7812）でチェックディジットを検証する。
func Luhn(digits string) bool {
	if len(digits) < 2 || !numeric(digits) {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// CreditCard は主要ブランドのプレフィックス・桁数制約と Luhn を検証する。
// 日本で発行数の多い JCB（3528-3589）を含む。
func CreditCard(digits string) bool {
	n := len(digits)
	if n < 13 || n > 19 || !numeric(digits) || AllSame(digits) {
		return false
	}
	if !brandOK(digits) {
		return false
	}
	return Luhn(digits)
}

func brandOK(d string) bool {
	n := len(d)
	p2 := atoi(d[:2])
	switch {
	case d[0] == '4': // Visa
		// 13 桁の旧 Visa 形式は現在ほぼ廃止されており、稀に現存する
		// 13 桁 Visa の検出漏れより、45/49 始まりの JAN コード等の
		// 13 桁数字列の誤検出抑制を優先する（docs/detection-methods.md 参照）。
		return n == 16 || n == 19
	case p2 >= 51 && p2 <= 55: // Mastercard
		return n == 16
	case atoi(d[:4]) >= 2221 && atoi(d[:4]) <= 2720: // Mastercard (2-series)
		return n == 16
	case p2 == 34 || p2 == 37: // American Express
		return n == 15
	case atoi(d[:4]) >= 3528 && atoi(d[:4]) <= 3589: // JCB
		return n >= 16 && n <= 19
	case p2 == 36 || p2 == 38 || p2 == 39 || (atoi(d[:3]) >= 300 && atoi(d[:3]) <= 305): // Diners Club
		return n >= 14 && n <= 19
	case d[:4] == "6011" || p2 == 65 || (atoi(d[:3]) >= 644 && atoi(d[:3]) <= 649): // Discover
		return n == 16 || n == 19
	}
	return false
}

func numeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func atoi(s string) int {
	v := 0
	for i := 0; i < len(s); i++ {
		v = v*10 + int(s[i]-'0')
	}
	return v
}
