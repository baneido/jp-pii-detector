package checksum

import (
	"fmt"
	"testing"
)

// genMyNumber は先頭 11 桁から検査用数字を計算して 12 桁を生成する
// （実装と独立に総務省令のアルゴリズムを書き下したもの）。
func genMyNumber(first11 string) string {
	sum := 0
	for n := 1; n <= 11; n++ {
		p := int(first11[11-n] - '0')
		q := n + 1
		if n >= 7 {
			q = n - 5
		}
		sum += p * q
	}
	r := sum % 11
	check := 0
	if r > 1 {
		check = 11 - r
	}
	return first11 + fmt.Sprint(check)
}

func TestMyNumber(t *testing.T) {
	valid := []string{
		genMyNumber("12345678901"), // = 123456789018
		genMyNumber("98765432109"),
		genMyNumber("00000000019"),
	}
	for _, v := range valid {
		if !MyNumber(v) {
			t.Errorf("MyNumber(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"123456789012", // 検査用数字不一致（正しくは 8）
		"123456789018x",
		"12345678901",  // 11 桁
		"111111111111", // 全桁同一はダミー扱い
		"",
	}
	for _, v := range invalid {
		if MyNumber(v) {
			t.Errorf("MyNumber(%q) = true, want false", v)
		}
	}
}

func TestMyNumberKnownValue(t *testing.T) {
	// 手計算による既知値: 12345678901 の検査用数字は 8
	if got := genMyNumber("12345678901"); got != "123456789018" {
		t.Fatalf("genMyNumber = %q, want 123456789018", got)
	}
}

func TestLuhn(t *testing.T) {
	if !Luhn("4111111111111111") {
		t.Error("Luhn(4111111111111111) = false, want true")
	}
	if Luhn("4111111111111112") {
		t.Error("Luhn(4111111111111112) = true, want false")
	}
}

func TestCreditCard(t *testing.T) {
	valid := []string{
		"4111111111111111", // Visa テスト番号
		"5555555555554444", // Mastercard テスト番号
		"3530111333300000", // JCB テスト番号
		"378282246310005",  // Amex テスト番号
		"30569309025904",   // Diners テスト番号
	}
	for _, v := range valid {
		if !CreditCard(v) {
			t.Errorf("CreditCard(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"4111111111111112", // Luhn 不正
		"9111111111111111", // 未知のプレフィックス
		"41111111",         // 桁数不足
		"1234567890123456", // プレフィックス不正
	}
	for _, v := range invalid {
		if CreditCard(v) {
			t.Errorf("CreditCard(%q) = true, want false", v)
		}
	}
}

func TestAllSame(t *testing.T) {
	if !AllSame("0000") {
		t.Error("AllSame(0000) = false")
	}
	if AllSame("0001") {
		t.Error("AllSame(0001) = true")
	}
}
