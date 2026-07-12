package dict

import (
	_ "embed"
	"strings"

	"golang.org/x/text/unicode/norm"
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
		out[NormalizeMunicipalityKa(line)] = true
	}
	return out
}

// municipalityVariants は KEN_ALL の市区町村名に実在する旧字体と、その一般的な
// 新字体の対応。市区町村・町字の実在性検証だけに使い、検出位置を決める
// internal/normalize.Line には適用しない。
//
// いずれも 1 ルーンから 1 ルーンへの置換に限定する。NormalizeMunicipalityKa は
// 生成側と照合側の両方で呼ばれ、TownPrefixMatch は一致したルーン数を元入力の
// バイト位置へ戻すため、この不変条件を保つ必要がある。
var municipalityVariants = strings.NewReplacer(
	"ヶ", "ケ",
	"龍", "竜",
	"竈", "釜",
	"嶋", "島",
	"條", "条",
	"惠", "恵",
	"檜", "桧",
	// NFKC で統合されない Unicode 互換漢字も明示しておく。NFKC で既に
	// 統合される Go/Unicode 版では no-op になる。
	"﨑", "崎",
	"髙", "高",
	"神", "神",
	"塚", "塚",
)

// NormalizeMunicipalityKa は市区町村・町字名の表記揺れを正規化する。
// 関数名は既存 API との互換のため残しているが、ヶ/ケ に加えて NFKC の CJK
// 互換漢字と、KEN_ALL の公式名に実在する旧字体（龍/竈/嶋/條/惠/檜）を
// 一般的な新字体へ畳む。internal/dict/gen が辞書生成時に、各照合器が実行時に
// 同じ関数を両側へ適用することで、公式表記と一般表記のどちらも一致させる。
func NormalizeMunicipalityKa(s string) string {
	return municipalityVariants.Replace(norm.NFKC.String(s))
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
