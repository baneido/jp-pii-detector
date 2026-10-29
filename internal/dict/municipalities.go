package dict

import (
	_ "embed"
	"strings"
	"sync"

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

// municipalitySet は市区町村名辞書の遅延ロード（sync.OnceValue）。全行に
// NormalizeMunicipalityKa（NFKC）を適用するためロードは軽くなく、住所ルールを
// 使わないプロセスでは不要なので初回参照時に一度だけ構築する。並行安全。
var municipalitySet = sync.OnceValue(func() map[string]bool {
	return loadMunicipalitySet(municipalitiesRaw)
})

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

// prefectures は都道府県名（47）。IsMunicipalityOrPrefecture が使う。
var prefectures = map[string]bool{}

func init() {
	for _, p := range strings.Fields("北海道 青森県 岩手県 宮城県 秋田県 山形県 福島県 茨城県 栃木県 群馬県 埼玉県 千葉県 東京都 神奈川県 " +
		"新潟県 富山県 石川県 福井県 山梨県 長野県 岐阜県 静岡県 愛知県 三重県 滋賀県 京都府 大阪府 兵庫県 奈良県 和歌山県 " +
		"鳥取県 島根県 岡山県 広島県 山口県 徳島県 香川県 愛媛県 高知県 福岡県 佐賀県 長崎県 熊本県 大分県 宮崎県 鹿児島県 沖縄県") {
		prefectures[p] = true
	}
}

// IsMunicipalityOrPrefecture は s が実在する市区町村名・都道府県名、または
// 「都道府県名 + 市区町村名」と完全一致するかを返す（部分一致は見ない）。
// 敬称アンカーの「北九州市様」「兵庫県さん」のように自治体を敬称付きで呼ぶ表記を
// 氏名候補から外すために使う。
func IsMunicipalityOrPrefecture(s string) bool {
	n := NormalizeMunicipalityKa(s)
	if prefectures[n] {
		return true
	}
	municipalities := municipalitySet()
	if municipalities[n] {
		return true
	}
	for p := range prefectures {
		if rest, ok := strings.CutPrefix(n, p); ok && municipalities[rest] {
			return true
		}
	}
	return false
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
	// 走査ループの内側で毎回 Once を経由しないよう、辞書は先にローカルへ束ねる。
	municipalities := municipalitySet()
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
