package dict

import (
	_ "embed"
	"strings"
)

// towns.txt はデジタル庁アドレス・ベース・レジストリ（ABR）「全国 町字マスター」
// 由来の大字・町名一覧。internal/dict/gen -towns が公式データから生成して
// コミットする（出典 URL・データ版・取得日・SHA-256・ライセンスはファイル冒頭の
// コメントを参照）。municipalities.txt（市区町村名）とは独立した辞書で、
// TownPrefixMatch / MunicipalityThenTownMatch は昇格専用エビデンスとしてのみ
// 使う（棄却には使わない。詳細は各関数のコメント参照）。
//
//go:embed towns.txt
var townsRaw string

var towns, townsMaxRuneLen = loadTownSet(townsRaw)

func loadTownSet(raw string) (map[string]bool, int) {
	out := map[string]bool{}
	maxLen := 0
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = true
		if n := len([]rune(line)); n > maxLen {
			maxLen = n
		}
	}
	return out, maxLen
}

// TownPrefixMatch は s の先頭が、実在する町字名（ABR 町字マスター由来の
// 大字・町名）と最長一致するかを判定する。一致した場合、一致した町字名の
// s 内でのバイト長 matchLen と true を返す。不一致は matchLen=0, ok=false。
//
// NormalizeMunicipalityKa（ヶ→ケ）を照合前に適用するが、この正規化はルーン
// 単位で 1:1（バイト長を変えない）なので、返す matchLen は s（正規化前の
// 元文字列）内でのバイト長としてそのまま使える
// （internal/normalize.Line と同じ 1 ルーン = 1 ルーンの不変条件に準じる）。
//
// jp-address-high-recall の昇格専用 Validate（MunicipalityThenTownMatch）が
// 使う。町字マスターに存在しない語（通学区域・団地名等）は素通りする
// （ok=false）だけで、棄却には使わない＝recall を落とさない。
func TownPrefixMatch(s string) (matchLen int, ok bool) {
	norm := NormalizeMunicipalityKa(s)
	rs := []rune(norm)
	maxLen := townsMaxRuneLen
	if len(rs) < maxLen {
		maxLen = len(rs)
	}
	for l := maxLen; l >= 1; l-- {
		cand := string(rs[:l])
		if towns[cand] {
			return len(cand), true
		}
	}
	return 0, false
}

// MunicipalityThenTownMatch は s（住所候補の全体文字列）の中に、実在する
// 市区町村名で終わる部分文字列の直後から、実在する町字名（TownPrefixMatch）が
// 続く位置が存在するかを返す。市区町村マーカー文字（市・区・町・村）の
// 出現位置ごとに、その位置で終わる部分文字列が municipalities（実在市区町村名
// 辞書）のいずれかと一致し、かつ続くギャップの先頭が TownPrefixMatch に
// 一致するかを調べる（MunicipalitySuffixMatch と同じ市区町村マーカー走査を
// 独立に行う。municipalities マップは同一パッケージ内の municipalities.go が
// 所有するデータをそのまま参照するだけで、municipalities.go 自体は変更しない）。
//
// jp-address-high-recall の Pattern 単位 Validate に使う: 従来の Rule 単位
// Validate（MunicipalitySuffixMatch、Base Medium 判定）に加えて、続く
// 「大字・町名」部分が ABR 町字マスター由来の辞書に実在する場合だけ
// Medium→High へ昇格させる twin パターン用（person-name の辞書検証 twin と
// 同じ手法）。**昇格専用**: この関数が false を返しても Medium のまま残る
// だけで検出そのものは棄却されない（recall には影響しない）。
func MunicipalityThenTownMatch(s string) bool {
	norm := NormalizeMunicipalityKa(s)
	rs := []rune(norm)
	for end, r := range rs {
		if r != '市' && r != '区' && r != '町' && r != '村' {
			continue
		}
		for start := 0; start <= end; start++ {
			if !municipalities[string(rs[start:end+1])] {
				continue
			}
			if _, ok := TownPrefixMatch(string(rs[end+1:])); ok {
				return true
			}
		}
	}
	return false
}
