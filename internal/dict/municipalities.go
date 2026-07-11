package dict

import (
	_ "embed"
	"strings"
)

// municipalities.txt は日本郵便 KEN_ALL（住所の郵便番号 UTF-8 版）由来の
// 市区町村名一覧。internal/dict/gen が公式データから生成してコミットする
// （postal_codes.bitset と同じ月次更新: .github/workflows/postal-update.yml）。
// 郡付きエントリは郡省略形、政令指定都市の区は市単独形も併録している
// （詳細は internal/dict/gen/postal.go の addMunicipalityVariants を参照）。
//
//go:embed municipalities.txt
var municipalitiesRaw string

var municipalities = loadMunicipalitySet(municipalitiesRaw)

func loadMunicipalitySet(raw string) map[string]bool {
	out := map[string]bool{}
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = true
	}
	return out
}

// NormalizeMunicipalityKa は市区町村名の「ヶ」を「ケ」に正規化する
// （鶴ヶ島市 ⇔ 鶴ケ島市 のような表記揺れを 1 つに畳む）。internal/dict/gen が
// 辞書生成時に、MunicipalitySuffixMatch が照合時に、同じ正規化を両側へ適用する
// ことで、生成側と実行側の乖離なくどちらの表記の住所も一致させる。
func NormalizeMunicipalityKa(s string) string {
	return strings.ReplaceAll(s, "ヶ", "ケ")
}

// MunicipalitySuffixMatch は s（住所候補の全体文字列）の中に、実在する
// 市区町村名で終わる部分文字列が含まれるかを返す。s 内のすべての市区町村
// マーカー文字（市・区・町・村）の出現位置ごとに、その位置で終わる部分
// 文字列の末尾（後方一致）が辞書のいずれかの市区町村名と一致するかを調べる。
//
// jp-address-high-recall の Validate に使う（既定の jp-address には付けない。
// 郡・表記揺れによる FN リスクが高再現率でない既定ルールでは相対的に大きいため）。
// 「通学区域は3丁目まで」のように市区町村ではない語（通学区）を municipality と
// 誤認した検出は、辞書に実在しないため棄却できる。
func MunicipalitySuffixMatch(s string) bool {
	norm := NormalizeMunicipalityKa(s)
	rs := []rune(norm)
	for end, r := range rs {
		if r != '市' && r != '区' && r != '町' && r != '村' {
			continue
		}
		for start := 0; start <= end; start++ {
			if municipalities[string(rs[start:end+1])] {
				return true
			}
		}
	}
	return false
}
