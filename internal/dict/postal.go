package dict

import (
	_ "embed"
	"strings"
)

// postal_codes.bitset は日本郵便の 7 桁郵便番号の実在集合を表す
// 10,000,000 ビット（= 1,250,000 バイト）のビットセット。internal/dict/gen が
// 公式 KEN_ALL データから生成してコミットする（月次更新は
// .github/workflows/postal-update.yml）。インデックス n（0〜9999999）のビットが
// 立っていれば、7 桁郵便番号 n が実在する。
//
//go:embed postal_codes.bitset
var postalBitset []byte

const postalCodeCount = 10_000_000 // 7 桁郵便番号の値域（0000000〜9999999）

// PostalBitsetSize は完全なビットセットのバイト長（1 ビット 1 郵便番号）。
// internal/dict/gen が生成物のサイズ検証に共有する。
const PostalBitsetSize = postalCodeCount / 8 // 1,250,000 バイト

// ValidPostalCode は 7 桁郵便番号が実在するか（ビットセットに登録されているか）を返す。
// 上位 3 桁ではなく 7 桁完全一致で判定するため、150-9999 のように上位 3 桁は実在しても
// 7 桁としては割り当てられていない番号は棄却される。
func ValidPostalCode(postalCode string) bool {
	digits := digitsOnly(postalCode)
	if len(digits) != 7 {
		return false
	}
	return postalInBitset(postalBitset, digits)
}

// postalInBitset は 7 桁の数字文字列 digits に対応するビットが bitset に
// 立っているかを返す（埋め込み変数から切り離してテスト可能にした下請け）。
func postalInBitset(bitset []byte, digits string) bool {
	n := PostalCodeIndex(digits)
	idx := int(n >> 3)
	return idx < len(bitset) && bitset[idx]&(1<<(n&7)) != 0
}

// PostalCodeIndex は 7 桁の数字文字列をビットセットのインデックス（0〜9999999）へ
// 変換する。internal/dict/gen が生成時に同じエンコーディングを共有するため公開する
// （dict 側と gen 側で別実装になり無言で乖離するのを防ぐ）。引数は 7 桁数字であること。
func PostalCodeIndex(digits string) uint32 {
	var n uint32
	for i := range 7 {
		n = n*10 + uint32(digits[i]-'0')
	}
	return n
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
