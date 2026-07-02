// Package checksum は番号体系ごとのチェックディジット検証を提供する。
package checksum

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

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
// マイナンバー・運転免許証番号・銀行口座番号・健康保険番号の Validate から
// 利用する（用途ごとの意味づけは呼び出し側のコメントを参照）。
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

// knownTestPANHashes は決済処理業者（Stripe 等）が公開しており、実務で
// 広く使い回されているテスト用ダミー PAN の SHA-256 ハッシュ（hex）の集合。
// 生の PAN 文字列をソースに残さないためハッシュ化して比較する（本リポジトリを
// jp-pii-detect 自身で走査した際に、可読なダミー PAN がソースに残ることと、
// 走査結果の自己検出を両方避けるため）。
var knownTestPANHashes = map[string]struct{}{
	"477bba133c182267fe5f086924abdc5db71f77bfc27f01f2843f2cdc69d89f05": {}, // Visa (Stripe)
	"9bbef19476623ca56c17da75fd57734dbf82530686043a6e491c6d71befe8f6e": {}, // Visa（複数決済処理業者で共通利用）
	"2f725bbd1f405a1ed0336abaf85ddfeb6902a9984a76fd877c3b5cc3b5085a82": {}, // Mastercard (Stripe)
	"304945e91de3deff52a61d08733141d72dd42ec9d47972f1060534d54c0c7f90": {}, // Mastercard（複数決済処理業者で共通利用）
	"3a134ef77d4e2e4cdad2d2945ff1f76c1a23296c93c851f6244220a8cedea130": {}, // American Express (Stripe)
	"53a8fc816e63b7a5ccd17aaff93f28bcf13abbf418209dcd93947722d7c326ba": {}, // American Express (Stripe)
	"19ff47cc8024c133d5845d3f8938caca289929031e7d508c3adf7adff177f0c2": {}, // Discover (Stripe)
	"d8086d483c15c711ebba19f966b97d3c2adcba74025ff8d7e07c3698c9531deb": {}, // Discover (Stripe)
	"1c9d38ed26cd808fa3b02b9b3b988a7caf474e2e42d95789c0fe07e267c80d8f": {}, // JCB (Stripe)
	"d79449f462cec9af0d857c3e1af888d4fa8bbdaa511b9eaaafcd2805c4ea6471": {}, // JCB (Stripe)
	"51a4ae4c6ae999146474a67cbcb3b05fbcf4c17ab683043a066459da95513ea8": {}, // Diners Club (Stripe)
	"f41e7ca4a3d71c4f047581f2ae2d6a8dbb8c58e51a020fa227edc724474aab6e": {}, // Diners Club (Stripe)
}

// isKnownTestPAN は digits が公知のテスト用ダミー PAN かどうかを返す。
func isKnownTestPAN(digits string) bool {
	sum := sha256.Sum256([]byte(digits))
	_, ok := knownTestPANHashes[hex.EncodeToString(sum[:])]
	return ok
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
// 日本で発行数の多い JCB（3528-3589）を含む。決済処理業者が公開している
// 公知のテスト用ダミー PAN（isKnownTestPAN）は Luhn を通過してしまうため
// 別途棄却する。
func CreditCard(digits string) bool {
	n := len(digits)
	if n < 13 || n > 19 || !numeric(digits) || AllSame(digits) {
		return false
	}
	if isKnownTestPAN(digits) {
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
