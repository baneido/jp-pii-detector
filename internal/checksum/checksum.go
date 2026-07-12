// Package checksum は番号体系ごとのチェックディジット検証を提供する。
package checksum

import (
	"crypto/sha256"
	"strings"
)

// knownTestPANHashes は決済事業者のドキュメント等で広く使われる公知の
// sandbox用PANだけをSHA-256で保持する。番号リテラルをソースへ置くと
// dogfood scanが自己検出するため、比較時に入力側をハッシュ化する。
var knownTestPANHashes = map[[sha256.Size]byte]struct{}{
	{0x9b, 0xbe, 0xf1, 0x94, 0x76, 0x62, 0x3c, 0xa5, 0x6c, 0x17, 0xda, 0x75, 0xfd, 0x57, 0x73, 0x4d, 0xbf, 0x82, 0x53, 0x06, 0x86, 0x04, 0x3a, 0x6e, 0x49, 0x1c, 0x6d, 0x71, 0xbe, 0xfe, 0x8f, 0x6e}: {},
	{0x47, 0x7b, 0xba, 0x13, 0x3c, 0x18, 0x22, 0x67, 0xfe, 0x5f, 0x08, 0x69, 0x24, 0xab, 0xdc, 0x5d, 0xb7, 0x1f, 0x77, 0xbf, 0xc2, 0x7f, 0x01, 0xf2, 0x84, 0x3f, 0x2c, 0xdc, 0x69, 0xd8, 0x9f, 0x05}: {},
	{0x2f, 0x72, 0x5b, 0xbd, 0x1f, 0x40, 0x5a, 0x1e, 0xd0, 0x33, 0x6a, 0xba, 0xf8, 0x5d, 0xdf, 0xeb, 0x69, 0x02, 0xa9, 0x98, 0x4a, 0x76, 0xfd, 0x87, 0x7c, 0x3b, 0x5c, 0xc3, 0xb5, 0x08, 0x5a, 0x82}: {},
	{0x3a, 0x13, 0x4e, 0xf7, 0x7d, 0x4e, 0x2e, 0x4c, 0xda, 0xd2, 0xd2, 0x94, 0x5f, 0xf1, 0xf7, 0x6c, 0x1a, 0x23, 0x29, 0x6c, 0x93, 0xc8, 0x51, 0xf6, 0x24, 0x42, 0x20, 0xa8, 0xce, 0xde, 0xa1, 0x30}: {},
	{0x53, 0xa8, 0xfc, 0x81, 0x6e, 0x63, 0xb7, 0xa5, 0xcc, 0xd1, 0x7a, 0xaf, 0xf9, 0x3f, 0x28, 0xbc, 0xf1, 0x3a, 0xbb, 0xf4, 0x18, 0x20, 0x9d, 0xcd, 0x93, 0x94, 0x77, 0x22, 0xd7, 0xc3, 0x26, 0xba}: {},
	{0x19, 0xff, 0x47, 0xcc, 0x80, 0x24, 0xc1, 0x33, 0xd5, 0x84, 0x5d, 0x3f, 0x89, 0x38, 0xca, 0xca, 0x28, 0x99, 0x29, 0x03, 0x1e, 0x7d, 0x50, 0x8c, 0x3a, 0xdf, 0x7a, 0xdf, 0xf1, 0x77, 0xf0, 0xc2}: {},
	{0xd8, 0x08, 0x6d, 0x48, 0x3c, 0x15, 0xc7, 0x11, 0xeb, 0xba, 0x19, 0xf9, 0x66, 0xb9, 0x7d, 0x3c, 0x2a, 0xdc, 0xba, 0x74, 0x02, 0x5f, 0xf8, 0xd7, 0xe0, 0x7c, 0x36, 0x98, 0xc9, 0x53, 0x1d, 0xeb}: {},
	{0x51, 0xa4, 0xae, 0x4c, 0x6a, 0xe9, 0x99, 0x14, 0x64, 0x74, 0xa6, 0x7c, 0xbc, 0xb3, 0xb0, 0x5f, 0xbc, 0xf4, 0xc1, 0x7a, 0xb6, 0x83, 0x04, 0x3a, 0x06, 0x64, 0x59, 0xda, 0x95, 0x51, 0x3e, 0xa8}: {},
	{0x1c, 0x9d, 0x38, 0xed, 0x26, 0xcd, 0x80, 0x8f, 0xa3, 0xb0, 0x2b, 0x9b, 0x3b, 0x98, 0x8a, 0x7c, 0xaf, 0x47, 0x4e, 0x2e, 0x42, 0xd9, 0x57, 0x89, 0xc0, 0xfe, 0x07, 0xe2, 0x67, 0xc8, 0x0d, 0x8f}: {},
}

// KnownTestPAN は digits が公知の決済sandbox用PANかどうかを返す。
// 任意のLuhn妥当値は実在番号と区別できないため、明示集合だけを棄却する。
func KnownTestPAN(digits string) bool {
	if !numeric(digits) {
		return false
	}
	_, ok := knownTestPANHashes[sha256.Sum256([]byte(digits))]
	return ok
}

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

// Modulus10Weight21 は、末尾の検証番号を除く数字へ右端から 2・1 を交互に
// 乗じ、2 桁の積は各桁を加算してから 10 の補数を取る検証番号を確認する。
// 国民健康保険の 6 桁保険者番号などで使われる M10W21 方式である。
//
// 算式の一次資料: 厚生省保険局国民健康保険課長通知
// 「診療報酬明細書等に記載される保険者番号の設定について」
// （昭和49年9月20日 保険発第104号）
// https://www.mhlw.go.jp/web/t_doc?dataId=00tb0648&dataType=1&pageNo=1
func Modulus10Weight21(digits string) bool {
	if len(digits) < 2 || !numeric(digits) {
		return false
	}
	sum := 0
	weight := 2
	for i := len(digits) - 2; i >= 0; i-- {
		product := int(digits[i]-'0') * weight
		sum += product/10 + product%10
		weight = 3 - weight // 2 と 1 を交互に切り替える。
	}
	check := (10 - sum%10) % 10
	return int(digits[len(digits)-1]-'0') == check
}

// CorporateNumber は法人番号（13 桁）の検査用数字を検証する。アルゴリズムは
// 「法人番号の指定等に関する省令」（平成26年財務省令第70号）による:
//
//	Pn = 検査用数字を除いた 12 桁（基礎番号）のうち末尾から n 桁目の数字
//	Qn = 1 (n が奇数) / 2 (n が偶数)
//	検査用数字 = 9 - (ΣPn*Qn mod 9)
//
// 先頭 1 桁が検査用数字、残り 12 桁が基礎番号（法人は法務省の会社法人等番号と
// 同一）。国税庁公表の計算例（会社法人等番号 700110005901 → 検査用数字 8）で
// 検証済み: https://www.houjin-bangou.nta.go.jp/documents/checkdigit.pdf
func CorporateNumber(digits string) bool {
	if len(digits) != 13 || !numeric(digits) || AllSame(digits) {
		return false
	}
	sum := 0
	for n := 1; n <= 12; n++ {
		p := int(digits[13-n] - '0')
		q := 1
		if n%2 == 0 {
			q = 2
		}
		sum += p * q
	}
	check := 9 - sum%9
	return int(digits[0]-'0') == check
}

// YuchoAccount は、ゆうちょ銀行の記号 5 桁と番号（最大 8 桁）について、
// 記号 4 桁目の検査数字を検証する。
//
// 一次資料は、ゆうちょ銀行公式「記号番号から振込用の店名・預金種目・口座番号を
// 調べる」の公開 JavaScript（関数 checkdigit / set_checkdigit、2026-07 確認）:
// https://www.jp-bank.japanpost.jp/kojin/sokin/furikomi/kouza/js/kouza_1.js
// （この Web 仕様には文書番号は付されていない）。番号を 8 桁に左ゼロ埋めし、
// 記号の検査数字以外の 4 桁と合わせて次の重み付き和を求める。D(x) は x を 2 倍し、
// 10 以上なら 9 を引く処理（十進各桁の和）を表す。
//
//	記号 = s1 s2 s3 c s5、8 桁化した番号 = n1 ... n8
//	S = s1 + 3*s2 + D(s3) + 3*s5
//	    + D(n1) + n2 + 3*n3 + D(n4) + n5 + 3*n6 + D(n7) + n8
//	検査数字 c = S mod 10
//
// 口座種別ごとの先頭・末尾や桁数の制約は番号体系の形状であり、呼び出し側で
// 判定する。この関数は公式式を適用できる 5 桁記号・1〜8 桁番号だけを受け付ける。
func YuchoAccount(symbol, number string) bool {
	if len(symbol) != 5 || len(number) < 1 || len(number) > 8 ||
		!numeric(symbol) || !numeric(number) {
		return false
	}

	padded := strings.Repeat("0", 8-len(number)) + number
	doubleDigit := func(b byte) int {
		d := int(b-'0') * 2
		if d >= 10 {
			d -= 9
		}
		return d
	}
	sum := int(symbol[0]-'0') + 3*int(symbol[1]-'0') + doubleDigit(symbol[2]) + 3*int(symbol[4]-'0')
	sum += doubleDigit(padded[0]) + int(padded[1]-'0') + 3*int(padded[2]-'0') + doubleDigit(padded[3])
	sum += int(padded[4]-'0') + 3*int(padded[5]-'0') + doubleDigit(padded[6]) + int(padded[7]-'0')
	return int(symbol[3]-'0') == sum%10
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
	if n < 13 || n > 19 || !numeric(digits) || AllSame(digits) || KnownTestPAN(digits) {
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
