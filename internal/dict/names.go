package dict

import (
	"embed"
	"sort"
	"strings"
)

//go:embed surnames.txt given_names.txt
var namesFS embed.FS

var (
	surnames   = loadNameSet("surnames.txt")
	givenNames = loadNameSet("given_names.txt")
	// surnameList / givenNameList は SurnameSample / GivenNameSample 用に、
	// 辞書を決定的な（バイト列順にソート済みの）スライスへ複製したもの。
	// map のイテレーション順は不定なため、合成ケース生成のような再現性が
	// 必要な用途向けに別途保持する。
	surnameList   = sortedKeys(surnames)
	givenNameList = sortedKeys(givenNames)
)

func loadNameSet(name string) map[string]bool {
	data, err := namesFS.ReadFile(name)
	if err != nil {
		panic(err)
	}
	out := map[string]bool{}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// nameComponentMaxRunes は分割検証で許す姓・名 1 要素あたりの最大ルーン数。
// これを超える長い文字列は人名要素として扱わない（一般名詞・組織名の誤検証防止）。
const nameComponentMaxRunes = 4

// nonPersonHomographs は「姓 + 名」に構造的には分割できるが、実際には人名では
// ない固有名詞（品種名・地名等）の denylist。山田錦は山田（姓）+錦（名）に分割
// でき、両要素とも辞書に収録されているため SplitFullName の分割ループ単体では
// 弾けない（姓側 2 ルーン・名側 1 ルーンで「両方 1 ルーン」制約の対象外）。
var nonPersonHomographs = map[string]bool{
	"山田錦": true, // 酒米の品種名（山田 + 錦 の分割が姓名辞書上は成立してしまう）
}

// NameMatch は MatchPersonName が返す判定根拠。二値の是非だけでなく、
// 呼び出し側が信頼度を作り分けられるよう根拠を区別する。
type NameMatch int

const (
	// NoMatch は姓・名のいずれの辞書にも一致せず、姓+名にも分割できない。
	NoMatch NameMatch = iota
	// SurnameOnly は単独の姓として辞書に収録されている（地名・企業名と同形の
	// 姓もありうるため、FullNameSplit より弱い根拠として扱う）。
	SurnameOnly
	// GivenOnly は単独の名として辞書に収録されている。
	GivenOnly
	// FullNameSplit は「姓 + 名」に分割でき、両要素とも辞書に収録されている
	// （最も強い根拠）。
	FullNameSplit
)

func (m NameMatch) String() string {
	switch m {
	case SurnameOnly:
		return "surname_only"
	case GivenOnly:
		return "given_only"
	case FullNameSplit:
		return "full_name_split"
	}
	return "no_match"
}

// SplitFullName は s を「姓 + 名」に分割できる最初の組み合わせを返す
// （不成立なら ok=false）。空白区切り（"山田 太郎"）と区切りなし
// （"山田太郎"）の両方に対応する。
//
// 区切りなしの場合、姓・名の両方が 1 ルーンとなる分割は不成立とする
// （関心=関+心、東大=東+大、森永=森+永 のような一般名詞・固有名詞の複合語を
// 誤って人名分割しないため）。空白区切りは従来どおり 1 ルーン同士でも許可する
// （空白という明示的な区切りがあり、単独の 1 文字姓+1 文字名の実在人名
// （林 学 等）を取りこぼさないため）。
//
// nonPersonHomographs に載る既知の非人名同形語（山田錦 等）は分割不成立として扱う。
//
// 注: 全角スペース分岐は防御用。本番経路では normalize.Line が U+3000 を半角
// スペースに畳んでから値が渡るため通常は到達しないが、検証器を正規化前の生入力に
// 対して直接呼ぶ呼び出し元（テスト等）でも正しく動くよう両対応にしている。
func SplitFullName(s string) (surname, given string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" || nonPersonHomographs[s] {
		return "", "", false
	}
	if strings.ContainsAny(s, " 　") {
		fields := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '　' })
		if len(fields) == 2 && surnames[fields[0]] && givenNames[fields[1]] {
			return fields[0], fields[1], true
		}
		return "", "", false
	}
	rs := []rune(s)
	for i := 1; i < len(rs); i++ {
		if i > nameComponentMaxRunes || len(rs)-i > nameComponentMaxRunes {
			continue
		}
		if i == 1 && len(rs)-i == 1 {
			continue // 姓・名とも 1 ルーンの分割（区切りなし）は不成立
		}
		sur, giv := string(rs[:i]), string(rs[i:])
		if surnames[sur] && givenNames[giv] {
			return sur, giv, true
		}
	}
	return "", "", false
}

// SplitsAsFullName は s を「姓 + 名」に分割でき、両要素とも辞書に収録されて
// いるかを返す（単独の姓・単独の名は false）。SplitFullName の可否だけを見る
// 後方互換の薄いラッパー。
func SplitsAsFullName(s string) bool {
	_, _, ok := SplitFullName(s)
	return ok
}

// IsSurname は s が収録済みの姓かを返す。
func IsSurname(s string) bool { return surnames[s] }

// IsGivenName は s が収録済みの名かを返す。
func IsGivenName(s string) bool { return givenNames[s] }

// MatchPersonName は候補文字列 s が人名らしいかを姓名辞書で検証し、その判定
// 根拠（NameMatch）を返す。優先順位は FullNameSplit（姓+名に分割）＞
// SurnameOnly／GivenOnly（単独一致）＞ NoMatch。
//
// SurnameOnly は地名・企業名と同形の姓（渋谷・大和・本田 等）を含みうるため、
// FullNameSplit より弱い根拠として扱う。呼び出し側はこの判定根拠に応じて
// 信頼度を作り分けること（二値の IsPersonName だけでは根拠を区別できず、
// Base を一律に上げると FP が増える）。
func MatchPersonName(s string) NameMatch {
	s = strings.TrimSpace(s)
	if s == "" {
		return NoMatch
	}
	if SplitsAsFullName(s) {
		return FullNameSplit
	}
	switch {
	case surnames[s]:
		return SurnameOnly
	case givenNames[s]:
		return GivenOnly
	default:
		return NoMatch
	}
}

// IsPersonName は候補文字列 s が人名らしいかを姓名辞書で検証する。
// 単独の姓・単独の名、または「姓 + 名」に分割できる場合に true を返す。
// MatchPersonName の判定根拠を区別しない後方互換の薄いラッパー
// （判定根拠が必要な呼び出し側は MatchPersonName を直接使うこと）。
//
// この関数は全文走査の検出器ではなく、ラベル・敬称などで得た候補の
// 検証器（validator）として使う想定。辞書は頻出名に絞っているため、
// 収録外の人名は false になりうる（再現率より適合率を優先する設計）。
// 単独 1 文字の名は日常語と衝突しやすいため、ラベル種別で絞り込む
// 呼び出し側（builtin.go の validGivenField 等）では別途長さを制限する。
func IsPersonName(s string) bool {
	return MatchPersonName(s) != NoMatch
}

// SurnameSample は姓辞書から先頭 n 件を決定的に返す（バイト列でソート済み）。
// n が辞書サイズを超える場合は辞書全体を返す。合成テストケース生成
// （internal/fixturegen）や、辞書に実在する値だけを使いたいテストのための
// 列挙用エクスポート関数で、非公開の map を外部から直読みさせないために用意する。
func SurnameSample(n int) []string { return sampleList(surnameList, n) }

// GivenNameSample は名辞書から先頭 n 件を決定的に返す。SurnameSample を参照。
func GivenNameSample(n int) []string { return sampleList(givenNameList, n) }

func sampleList(list []string, n int) []string {
	if n <= 0 {
		return nil
	}
	if n > len(list) {
		n = len(list)
	}
	out := make([]string, n)
	copy(out, list[:n])
	return out
}
