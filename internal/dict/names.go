package dict

import (
	"embed"
	"sort"
	"strings"
)

//go:embed surnames.txt given_names.txt given_names_katakana_org.txt name_homographs.txt
var namesFS embed.FS

var (
	surnames   = loadNameSet(namesFS, "surnames.txt")
	givenNames = loadNameSet(namesFS, "given_names.txt")
	// extendedGivenNames は org 版の読みから既定（opti）との差分だけを収録した
	// 高再現率用カタカナ名。既定 person-name の精度を変えず、明示的な
	// high-recall 経路だけで使う。
	extendedGivenNames = loadNameSet(namesFS, "given_names_katakana_org.txt")
	// surnameList / givenNameList は SurnameSample / GivenNameSample 用に、
	// 辞書を決定的な（バイト列順にソート済みの）スライスへ複製したもの。
	// map のイテレーション順は不定なため、合成ケース生成のような再現性が
	// 必要な用途向けに別途保持する。
	surnameList   = sortedKeys(surnames)
	givenNameList = sortedKeys(givenNames)
)

// loadNameSet は fsys に go:embed された name（改行区切り、# 始まりはコメント）を
// 集合として読み込む。姓名辞書とローマ字姓名辞書の両方から共用する。
func loadNameSet(fsys embed.FS, name string) map[string]bool {
	data, err := fsys.ReadFile(name)
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
var nonPersonHomographs = loadNameSet(namesFS, "name_homographs.txt")

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
	return splitFullName(s, false, true)
}

// SplitFullNameExtended は SplitFullName と同じ分割を行い、名側だけは org 版の
// 高再現率用カタカナ名も許可する。high-recall ルール専用で、既定ルールから
// 呼ばないこと。
func SplitFullNameExtended(s string) (surname, given string, ok bool) {
	return splitFullName(s, true, true)
}

// SplitFullNameCandidate は denylist 適用前の姓名分割候補を返す。非公開評価
// コーパスの陰性ケースから同形語候補を収集する開発用 probe のための API で、
// 検出ルールの Validate には SplitFullName / SplitFullNameExtended を使うこと。
func SplitFullNameCandidate(s string) (surname, given string, ok bool) {
	return splitFullName(s, false, false)
}

func splitFullName(s string, includeExtended, applyDenylist bool) (surname, given string, ok bool) {
	s = ComposeKana(strings.TrimSpace(s))
	if s == "" || (applyDenylist && nonPersonHomographs[s]) {
		return "", "", false
	}
	if strings.ContainsAny(s, " 　") {
		fields := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '　' })
		if len(fields) == 2 && surnames[fields[0]] && isGivenName(fields[1], includeExtended) {
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
		if surnames[sur] && isGivenName(giv, includeExtended) {
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

// IsGivenNameExtended は既定辞書に加え、高再現率用 org 版カタカナ名も照合する。
func IsGivenNameExtended(s string) bool { return isGivenName(s, true) }

func isGivenName(s string, includeExtended bool) bool {
	return givenNames[s] || (includeExtended && extendedGivenNames[s])
}

// MatchPersonName は候補文字列 s が人名らしいかを姓名辞書で検証し、その判定
// 根拠（NameMatch）を返す。優先順位は FullNameSplit（姓+名に分割）＞
// SurnameOnly／GivenOnly（単独一致）＞ NoMatch。
//
// SurnameOnly は地名・企業名と同形の姓（渋谷・大和・本田 等）を含みうるため、
// FullNameSplit より弱い根拠として扱う。呼び出し側はこの判定根拠に応じて
// 信頼度を作り分けること（二値の IsPersonName だけでは根拠を区別できず、
// Base を一律に上げると FP が増える）。
func MatchPersonName(s string) NameMatch {
	s = ComposeKana(strings.TrimSpace(s))
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
//
// s は照合前に ComposeKana で濁点・半濁点を合成する。半角カナ由来の
// 「ﾔﾏﾀﾞ」は normalize.Line で「ヤマダ」（ダ = タ + 結合濁点、2 ルーン）に
// 折り畳まれるため、合成しないと辞書（濁点合成済み表記で収録）に一致しない。
func IsPersonName(s string) bool {
	return MatchPersonName(s) != NoMatch
}

// IsPersonNameExtended は高再現率用 org 版カタカナ名まで含めて人名を検証する。
// 既定ルールの confidence を暗黙に変えないよう、high-recall 経路だけで使う。
func IsPersonNameExtended(s string) bool {
	s = ComposeKana(strings.TrimSpace(s))
	if s == "" {
		return false
	}
	if _, _, ok := SplitFullNameExtended(s); ok {
		return true
	}
	return surnames[s] || isGivenName(s, true)
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

// combiningDakuten・combiningHandakuten は半角カナの濁点・半濁点
// （U+FF9E/U+FF9F）が normalize.Line で折り畳まれた結合文字。1 ルーン = 1 ルーンの
// 不変条件を保つため、正規化は基底の仮名と合成せずこの結合文字のまま残す。
const (
	combiningDakuten    = '゙'
	combiningHandakuten = '゚'
)

// kanaComposition は「基底の仮名 + 結合濁点/半濁点」→ 合成済み 1 文字のテーブル
// （ひらがな・カタカナ計 56 ペア）。golang.org/x/text/unicode/norm への依存を
// 避けるため、濁点・半濁点が付きうる仮名だけを対象にした手動テーブルとして持つ
// （NFC 正規化全体の実装ではない）。
var kanaComposition = map[[2]rune]rune{
	{'う', combiningDakuten}:    'ゔ',
	{'か', combiningDakuten}:    'が',
	{'き', combiningDakuten}:    'ぎ',
	{'く', combiningDakuten}:    'ぐ',
	{'け', combiningDakuten}:    'げ',
	{'こ', combiningDakuten}:    'ご',
	{'さ', combiningDakuten}:    'ざ',
	{'し', combiningDakuten}:    'じ',
	{'す', combiningDakuten}:    'ず',
	{'せ', combiningDakuten}:    'ぜ',
	{'そ', combiningDakuten}:    'ぞ',
	{'た', combiningDakuten}:    'だ',
	{'ち', combiningDakuten}:    'ぢ',
	{'つ', combiningDakuten}:    'づ',
	{'て', combiningDakuten}:    'で',
	{'と', combiningDakuten}:    'ど',
	{'は', combiningDakuten}:    'ば',
	{'ひ', combiningDakuten}:    'び',
	{'ふ', combiningDakuten}:    'ぶ',
	{'へ', combiningDakuten}:    'べ',
	{'ほ', combiningDakuten}:    'ぼ',
	{'は', combiningHandakuten}: 'ぱ',
	{'ひ', combiningHandakuten}: 'ぴ',
	{'ふ', combiningHandakuten}: 'ぷ',
	{'へ', combiningHandakuten}: 'ぺ',
	{'ほ', combiningHandakuten}: 'ぽ',
	{'ウ', combiningDakuten}:    'ヴ',
	{'カ', combiningDakuten}:    'ガ',
	{'キ', combiningDakuten}:    'ギ',
	{'ク', combiningDakuten}:    'グ',
	{'ケ', combiningDakuten}:    'ゲ',
	{'コ', combiningDakuten}:    'ゴ',
	{'サ', combiningDakuten}:    'ザ',
	{'シ', combiningDakuten}:    'ジ',
	{'ス', combiningDakuten}:    'ズ',
	{'セ', combiningDakuten}:    'ゼ',
	{'ソ', combiningDakuten}:    'ゾ',
	{'タ', combiningDakuten}:    'ダ',
	{'チ', combiningDakuten}:    'ヂ',
	{'ツ', combiningDakuten}:    'ヅ',
	{'テ', combiningDakuten}:    'デ',
	{'ト', combiningDakuten}:    'ド',
	{'ハ', combiningDakuten}:    'バ',
	{'ヒ', combiningDakuten}:    'ビ',
	{'フ', combiningDakuten}:    'ブ',
	{'ヘ', combiningDakuten}:    'ベ',
	{'ホ', combiningDakuten}:    'ボ',
	{'ワ', combiningDakuten}:    'ヷ',
	{'ヰ', combiningDakuten}:    'ヸ',
	{'ヱ', combiningDakuten}:    'ヹ',
	{'ヲ', combiningDakuten}:    'ヺ',
	{'ハ', combiningHandakuten}: 'パ',
	{'ヒ', combiningHandakuten}: 'ピ',
	{'フ', combiningHandakuten}: 'プ',
	{'ヘ', combiningHandakuten}: 'ペ',
	{'ホ', combiningHandakuten}: 'ポ',
}

// ComposeKana は s に含まれる「基底の仮名 + 結合濁点/半濁点（U+3099/U+309A）」を
// 対応する濁点・半濁点つきの 1 文字へ合成して返す。半角カナの折り畳み
// （normalize.Line）は 1 ルーン = 1 ルーンの位置不変条件を保つため濁点・半濁点を
// 未合成の結合文字のまま返す。姓名辞書は合成済み表記（ガ・ダ 等）で収録して
// いるため、辞書照合の直前でこの関数を通す。結合文字を含まない入力は
// 割り当てなしでそのまま返す。
func ComposeKana(s string) string {
	if !strings.ContainsRune(s, combiningDakuten) && !strings.ContainsRune(s, combiningHandakuten) {
		return s
	}
	rs := []rune(s)
	out := make([]rune, 0, len(rs))
	for i := 0; i < len(rs); i++ {
		if i+1 < len(rs) {
			if c, ok := kanaComposition[[2]rune{rs[i], rs[i+1]}]; ok {
				out = append(out, c)
				i++
				continue
			}
		}
		out = append(out, rs[i])
	}
	return string(out)
}
