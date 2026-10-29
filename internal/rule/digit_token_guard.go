package rule

import "strings"

// 数値ルール（マイナンバー・クレジットカード）の、OSS コーパスで実測した
// 偽陽性の型を棄却する ValidateLine 群（docs/development.md「OSS コーパスでの
// 偽陽性率計測」）。共有の境界ガード（dgNoAlnumHyphen 等）を厳しくすると全数値
// ルールの再現率に波及するため、実測で偽陽性が集中したルールのパターンにだけ使う。

// allValidateLine は、すべての ValidateLine が true を返すときだけ true を返す。
func allValidateLine(fs ...func(string, int, int) bool) func(string, int, int) bool {
	return func(line string, start, end int) bool {
		for _, f := range fs {
			if !f(line, start, end) {
				return false
			}
		}
		return true
	}
}

func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

// rejectNumericTokenPart は、数字列が独立した番号ではなく、より大きな数値・
// 識別子トークンの一部である場合に棄却する。
//   - 小数の一部: 直前が「数字 + .」（"29.7062300000000015" の小数部、
//     "0.968994140625"）、または直後が「. + 数字」（"148966367200.372"）。
//   - 識別子の一部: 直前・直後がアンダースコア（"blk_3550669278239526374"）。
//     英数字・ハイフンの連結は境界ガードが既に除外しており、それと同じ扱い。
func rejectNumericTokenPart(line string, start, end int) bool {
	if start > 0 {
		switch line[start-1] {
		case '_':
			return false
		case '.':
			if start > 1 && isASCIIDigit(line[start-2]) {
				return false
			}
		}
	}
	if end < len(line) {
		switch line[end] {
		case '_':
			return false
		case '.':
			if end+1 < len(line) && isASCIIDigit(line[end+1]) {
				return false
			}
		}
	}
	return true
}

// hexDumpNeighborTokens は、前後それぞれ何トークンまで 16 進ダンプの判定に見るか。
const hexDumpNeighborTokens = 8

// rejectHexDumpGroup は、空白区切りの 16 進ダンプ（"ffff 54cd 7484 9797 9999"、
// "00000130  64 67 69 74 73 20 50 74  79 20 4c 74"、PNG テストデータの
// 12 桁ずつの 16 進の並び等）の中で、たまたま英字 a-f を含まない
// グループの並びを棄却する。マッチの前後 hexDumpNeighborTokens 個以内に、
// マッチの先頭グループと同じ幅で英字 a-f を含む 16 進トークンが空白区切りで
// 連続して並んでいれば 16 進ダンプとみなす（途中に 16 進でないトークンがあれば
// そこで打ち切る）。
func rejectHexDumpGroup(line string, start, end int) bool {
	width := 0
	for i := start; i < end && isASCIIDigit(line[i]); i++ {
		width++
	}
	if width == 0 {
		return true
	}
	return !hexNeighbor(strings.Fields(line[:start]), width, true) &&
		!hexNeighbor(strings.Fields(line[end:]), width, false)
}

// hexNeighbor は、tokens（reverse なら末尾から）を最大 hexDumpNeighborTokens 個
// 見て、幅 width で英字 a-f を含む 16 進トークンがあるかを返す。
func hexNeighbor(tokens []string, width int, reverse bool) bool {
	for k := 0; k < len(tokens) && k < hexDumpNeighborTokens; k++ {
		t := tokens[k]
		if reverse {
			t = tokens[len(tokens)-1-k]
		}
		letter, ok := hexToken(t)
		if !ok {
			return false
		}
		if letter && len(t) == width {
			return true
		}
	}
	return false
}

// hexToken は、t が 16 進数字だけからなるか（ok）と、英字 a-f を含むか（letter）を返す。
func hexToken(t string) (letter, ok bool) {
	if t == "" {
		return false, false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case isASCIIDigit(c):
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			letter = true
		default:
			return false, false
		}
	}
	return letter, true
}

// rejectLogTimestamp66 は、マイナンバーの 6-6 空白区切り形のうち、ログの
// タイムスタンプ（YYMMDD HHMMSS。Hadoop 等のログで行頭に並ぶ）と
// 同形のものを、行にマイナンバーのラベル（context）が無い場合に限り棄却する。
// 6-6 形はチェックディジットで約 1/11 しか絞れず、ログ 1 行ごとに偽陽性を生んでいた。
func rejectLogTimestamp66(context []string) func(string, int, int) bool {
	return func(line string, start, end int) bool {
		m := line[start:end]
		if len(m) != 13 || m[6] != ' ' || !yymmdd(m[:6]) || !hhmmss(m[7:]) {
			return true
		}
		lower := strings.ToLower(line)
		for _, c := range context {
			if strings.Contains(lower, strings.ToLower(c)) {
				return true
			}
		}
		return false
	}
}

func twoDigits(s string) int { return int(s[0]-'0')*10 + int(s[1]-'0') }

func yymmdd(s string) bool {
	m, d := twoDigits(s[2:4]), twoDigits(s[4:6])
	return m >= 1 && m <= 12 && d >= 1 && d <= 31
}

func hhmmss(s string) bool {
	return twoDigits(s[0:2]) <= 23 && twoDigits(s[2:4]) <= 59 && twoDigits(s[4:6]) <= 59
}

// youCompoundStems は、「様」と続けて敬称ではない一般語（同様・仕様・模様・
// 異様・多種多様）を作る直前の文字列。
var youCompoundStems = []string{"同", "仕", "模", "異", "種多"}

// youCompoundTails は、「様」の直後に続いて敬称ではない一般語（様式・様相・様態）を
// 作る文字。行政文書の「申請書様式」「共通様式」「別添様式２」で、直前の漢字列
// （申請書・共通・別添）を敬称付き氏名として切り出す偽陽性を公開文書で実測した
// （様式は書式を指す一般名詞で、個人情報保護法上の個人情報に当たらない）。
var youCompoundTails = []string{"式", "相", "態"}

// rejectYouCompound は、敬称アンカーの「様」が一般語の一部（「新品同様」
// 「従来同様」「構文仕様」「多種多様」「申請書様式」）である場合に棄却する。日本語ドキュメントの
// コーパスで、敬称の直前の漢字 2〜8 文字（「新品同」「構文仕」）を氏名として
// 切り出す偽陽性を実測した。「本多様」のような姓 + 様や、1 文字名「一」+ 様は棄却しない。
func rejectYouCompound(line string, start, end int) bool {
	if !strings.HasPrefix(line[end:], "様") {
		return true
	}
	after := line[end+len("様"):]
	for _, t := range youCompoundTails {
		if strings.HasPrefix(after, t) {
			return false
		}
	}
	for _, s := range youCompoundStems {
		if strings.HasSuffix(line[start:end], s) {
			return false
		}
	}
	return true
}

// rejectShimeiCompound は、敬称アンカーの「氏」が一般語「氏名」の一部である場合に棄却する。
// 個人情報漏えいの公表文書の「生徒氏名、学年」「職員氏名」で、直前の一般語（生徒・職員）を
// 敬称付き氏名として切り出す偽陽性を公開文書で実測した（「氏名」は項目名で、直前の語は
// 人を特定しない）。「<姓>氏名義の口座」のように「氏」+「名義」と読む形は棄却しない。
func rejectShimeiCompound(line string, start, end int) bool {
	rest := line[end:]
	if !strings.HasPrefix(rest, "氏名") {
		return true
	}
	return strings.HasPrefix(rest, "氏名義")
}

// rejectHonorificWordCompound は、敬称アンカーの「様」「さん」「氏」「殿」が一般語の一部で
// ある場合に棄却する。県・市の公開ページで「生物多様性」「総合企画部多様性社会推進課」
// （多様）、「県史編さん」「野外炊さん」（編さん・炊さん）、「皇族各殿下」「女王殿下」（名を含まない殿下）、
// 「選択的夫婦別氏制度」（別氏）、「朝倉氏遺跡」「西山氏庭園」（史跡名）を
// 敬称付き氏名として切り出す偽陽性を実測した。
func rejectHonorificWordCompound(line string, start, end int) bool {
	val := line[start:end]
	rest := line[end:]
	switch {
	case strings.HasSuffix(val, "多") && (strings.HasPrefix(rest, "様性") || strings.HasPrefix(rest, "様化") || strings.HasPrefix(rest, "様な")):
		// 「本多様」「喜多様」のような姓 + 様は残し、多様性・多様化・多様な だけを棄却する。
		return false
	case (strings.HasSuffix(val, "編") || strings.HasSuffix(val, "炊")) && strings.HasPrefix(rest, "さん"):
		return false
	case strings.HasPrefix(rest, "殿下") && (strings.HasSuffix(val, "両") || strings.HasSuffix(val, "各") ||
		val == "女王" || val == "親王" || val == "内親王"):
		// 「両殿下」「各殿下」「女王殿下」のように名を含まない敬称だけを棄却する。
		// 「<名>女王殿下」「<宮家>妃<名>殿下」は特定の個人を指すため残す。
		return false
	case strings.HasSuffix(val, "夫婦別") && strings.HasPrefix(rest, "氏"):
		return false
	}
	for _, w := range []string{"氏遺跡", "氏庭園", "氏館跡", "氏城跡"} {
		if strings.HasPrefix(rest, w) {
			return false
		}
	}
	return true
}

// rejectURLUserinfo は、メールアドレス形の候補が URL のユーザー情報
// （"http://gopher@test.com"、"ssh://git@github.com/user/repo"、
// "http://user:pass@host"）である場合に棄却する。候補を含む空白・引用符区切りの
// トークンで、候補より前に "://" があれば URL とみなす（mailto: は "://" を
// 含まないので棄却しない）。
func rejectURLUserinfo(line string, start, end int) bool {
	i := start
	for i > 0 {
		c := line[i-1]
		if c == ' ' || c == '\t' || c == '"' || c == '\'' || c == '`' || c == '(' || c == '<' || c == '[' || c == '=' || c == ',' {
			break
		}
		i--
	}
	return !strings.Contains(line[i:start], "://")
}

// honorificCommonNouns は、「さん」「様」を付けて人を指すが氏名ではない一般語
// （客・常連・初見・大家 等）。敬称アンカーの直前の漢字列がこれと完全一致する
// 場合に棄却する。初見・大家・奥 のように同表記の姓が辞書にある語も含むが、
// 「さん」「様」付きではまず一般語として使われるため、姓としての再現率より
// 偽陽性の抑制を優先する（「初見太郎さん」のように名が続く値は完全一致しないので
// 引き続き検出する）。
var honorificCommonNouns = map[string]bool{
	"初見": true, "常連": true, "新規": true, "古参": true, "新参": true, "新人": true, "一見": true,
	"旦那": true, "親御": true, "大家": true, "家主": true, "地主": true, "運営": true, "相方": true,
	"奥方": true, "女将": true, "親方": true, "坊主": true, "和尚": true, "住職": true, "神主": true,
	"皆": true, "皆皆": true, "各位": true, "常連客": true, "乗客": true, "顧客": true, "来店客": true,
	"御客": true, "親父": true, "母親": true, "父親": true, "隣人": true, "近所": true, "御近所": true,
}

// honorificCommonNounSuffixes は、「社員皆さん」「来場者皆様」「常連客様」の
// ように、一般語 + 敬称の前に別の語が付いた形の語尾。
var honorificCommonNounSuffixes = []string{"皆", "客"}

// rejectHonorificCommonNoun は、敬称（さん・様）の直前の漢字列が一般語
// （honorificCommonNouns・honorificCommonNounSuffixes）である場合に棄却する。
// 「氏」「殿」は一般語に付くことがほぼ無いので対象外にする。
func rejectHonorificCommonNoun(line string, start, end int) bool {
	rest := line[end:]
	if !strings.HasPrefix(rest, "さん") && !strings.HasPrefix(rest, "様") {
		return true
	}
	v := line[start:end]
	if honorificCommonNouns[v] {
		return false
	}
	for _, s := range honorificCommonNounSuffixes {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	return true
}
