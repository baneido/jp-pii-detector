package dict

import (
	"embed"
	"strings"
)

//go:embed postal_prefixes.txt
var postalFS embed.FS

// postal_codes.bitset は日本郵便の 7 桁郵便番号の実在集合を表す
// 10,000,000 ビット（= 1,250,000 バイト）のビットセット。internal/dict/gen が
// 公式 CSV から生成する。リポジトリには空のプレースホルダを置いており、
// その場合は上位 3 桁の実在チェック（postal_prefixes.txt）へフォールバックする。
// メンテナが gen でビットセットを生成・差し替えると 7 桁完全一致に切り替わる。
//
//go:embed postal_codes.bitset
var postalBitset []byte

const (
	// postalCodeCount は 7 桁郵便番号の値域（0000000〜9999999）。
	postalCodeCount = 10_000_000
	// postalBitsetSize は完全なビットセットのバイト長。
	postalBitsetSize = postalCodeCount / 8 // 1,250,000 バイト
)

// usePreciseBitset は 7 桁完全一致のビットセットが生成済み（期待サイズ）かどうか。
// プレースホルダ（空ファイル等で期待サイズでない）の場合は false。
var usePreciseBitset = len(postalBitset) == postalBitsetSize

var validPostalPrefixes = loadPostalPrefixes()

func loadPostalPrefixes() map[string]bool {
	data, err := postalFS.ReadFile("postal_prefixes.txt")
	if err != nil {
		panic(err)
	}
	out := map[string]bool{}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out[line] = true
		}
	}
	return out
}

// ValidPostalCode は 7 桁郵便番号が実在するかを返す。生成済みのビットセットが
// あれば 7 桁完全一致で判定し、なければ上位 3 桁の実在チェックへフォールバックする。
func ValidPostalCode(postalCode string) bool {
	digits := digitsOnly(postalCode)
	if len(digits) != 7 {
		return false
	}
	if usePreciseBitset {
		return postalInBitset(postalBitset, digits)
	}
	return validPostalPrefixes[digits[:3]]
}

// ValidPostalCodePrefix は 7 桁郵便番号の上位 3 桁が実在するかを返す
// （ビットセット未生成時のフォールバック。後方互換のため公開を維持）。
func ValidPostalCodePrefix(postalCode string) bool {
	digits := digitsOnly(postalCode)
	return len(digits) == 7 && validPostalPrefixes[digits[:3]]
}

// postalInBitset は 7 桁の数字文字列 digits に対応するビットが bitset に
// 立っているかを返す（埋め込み変数から切り離してテスト可能にした下請け）。
func postalInBitset(bitset []byte, digits string) bool {
	n := postalToIndex(digits)
	idx := int(n >> 3)
	return idx < len(bitset) && bitset[idx]&(1<<(n&7)) != 0
}

// postalToIndex は 7 桁の数字文字列をビットセットのインデックス（0〜9999999）へ変換する。
func postalToIndex(digits string) uint32 {
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
