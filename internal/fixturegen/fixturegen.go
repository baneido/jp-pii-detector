// Package fixturegen は「ルール × 表記ゆれ」のマトリクスに沿った合成評価ケース
// （internal/piifixtures.Case）を生成する。値はすべて checksum のチェックディジット
// 算出ロジックや dict の実在辞書から逆算した計算合成で、リテラルの実在 PII は
// ソースに一切含まれない（ドッグフード CI 対策。GitHub Issue #70 のリスク節を参照）。
//
// 対応ルールは、値の妥当性を検証だけでなく合成もできる（チェックディジットを
// 逆算できる、または実在辞書から抽出できる）ものに限定している:
//
//   - jp-my-number: checksum.MyNumber のチェックディジット式を逆算する。
//   - credit-card: checksum.Luhn のチェックディジットを逆算し、ブランド
//     プレフィックス（checksum.CreditCard が要求する範囲）を満たす。
//   - jp-postal-code: dict.SamplePostalCodes でビットセットから実在番号を抽出する
//     （郵便番号自体はチェックディジットを持たないため、実在性でしか合成できない。
//     postal_codes.bitset は既にコミット済みのデータで新規の秘匿情報ではない）。
//   - person-name: dict.SurnameSample / dict.GivenNameSample で姓名辞書から
//     実在する姓・名を抽出する。
//
// 生成物は internal/piifixtures の JSON スキーマ（dataset 配列）に互換な
// []piifixtures.Case で、cmd/pii-dataset-gen が JSON として書き出す。出力は
// レビューのうえ外部データセット（GCS）へ人手でマージする運用を想定しており、
// このリポジトリにはコミットしない。
package fixturegen

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/dict"
	"github.com/baneido/jp-pii-detector/internal/piifixtures"
)

// SourceTag はこのパッケージが生成したケースすべてに付与するタグ。実採取
// データセットと区別し、マクロ平均・層別集計で合成データの重みを緩和するために使う
// （Issue #70 のリスク節: 「タグで合成/実採取を区別」）。
const SourceTag = "source:synthetic"

// Generate はすべての対応ルールの合成ケースを結合して返す。
func Generate() []piifixtures.Case {
	var cases []piifixtures.Case
	cases = append(cases, MyNumberCases()...)
	cases = append(cases, CreditCardCases()...)
	cases = append(cases, PostalCodeCases()...)
	cases = append(cases, PersonNameCases()...)
	return cases
}

// ---- 共通ヘルパー ----

// groupDigits は digits を widths の桁数ごとに分割し、sep で連結する
// （例: widths=[4,4,4], sep="-" の 12 桁なら "XXXX-XXXX-XXXX" の形に区切る）。
// ここでは実際の値を例示しない（値は必ず checksum/dict から計算合成し、
// ドッグフード対象のソースへ literal な PII 形式の文字列を書かないため）。
func groupDigits(digits string, widths []int, sep string) string {
	var b strings.Builder
	i := 0
	for gi, w := range widths {
		if gi > 0 {
			b.WriteString(sep)
		}
		b.WriteString(digits[i : i+w])
		i += w
	}
	return b.String()
}

// toFullWidthDigits は ASCII 数字とハイフンを全角に変換する（normalize.Line の
// 逆写像。ラベル文字列など他の文字はそのまま）。全角表記ゆれのケース生成に使う。
func toFullWidthDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r - '0' + '０') // FULLWIDTH DIGIT ZERO 起点
		case r == '-':
			b.WriteRune('－') // FULLWIDTH HYPHEN-MINUS
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// luhnCheckDigit は payload（チェックディジットを除く数字列）に続くべき Luhn
// チェックディジットを算出する。checksum.Luhn の検証ロジックと対になる合成側。
func luhnCheckDigit(payload string) int {
	sum := 0
	double := true // チェックディジットの直前（payload の末尾）から doubling する
	for i := len(payload) - 1; i >= 0; i-- {
		d := int(payload[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return (10 - sum%10) % 10
}

// myNumberCheckDigit は先頭 11 桁（base11）に続くべきマイナンバーのチェック
// ディジットを算出する。checksum.MyNumber の検証式（総務省令第 85 号第 5 条）を
// 逆算した合成側で、式そのものは internal/checksum/checksum.go の MyNumber と揃える。
func myNumberCheckDigit(base11 string) int {
	sum := 0
	for n := 1; n <= 11; n++ {
		p := int(base11[11-n] - '0')
		q := n + 1
		if n >= 7 {
			q = n - 5
		}
		sum += p * q
	}
	check := 11 - sum%11
	if check >= 10 {
		check = 0
	}
	return check
}

// syntheticMyNumber は seed ごとに異なる（全桁同一にならない）11 桁の基底列から
// checksum.MyNumber を満たす 12 桁の合成マイナンバーを返す。実在のマイナンバーではない。
func syntheticMyNumber(seed int) string {
	base := make([]byte, 11)
	for i := range base {
		d := (i*7 + seed*3 + 1) % 10
		base[i] = byte('0' + d)
	}
	base11 := string(base)
	check := myNumberCheckDigit(base11)
	return base11 + strconv.Itoa(check)
}

// syntheticCardNumber は prefix（ブランドのプレフィックス）から始まる length 桁の、
// checksum.CreditCard（ブランド判定 + Luhn）を満たす合成カード番号を返す。
// 実在のカード番号ではない。
func syntheticCardNumber(prefix string, length int) string {
	payload := prefix
	for len(payload) < length-1 {
		// 0 のみで埋めると桁数次第で AllSame に抵触しうるため、緩やかに変化する
		// 非一様な埋め字にする（1〜9 を循環）。
		payload += strconv.Itoa(len(payload)%9 + 1)
	}
	payload = payload[:length-1]
	check := luhnCheckDigit(payload)
	return payload + strconv.Itoa(check)
}

// ---- jp-my-number ----

// MyNumberCases はマイナンバーのラベル語彙 × 区切り × 全角/半角のマトリクスを返す。
func MyNumberCases() []piifixtures.Case {
	labels := []struct{ tag, text string }{
		{"label:jp-strong", "マイナンバー"},
		{"label:jp-alt", "個人番号"},
		{"label:ascii", "My Number"},
	}
	seps := []struct {
		tag    string
		widths []int
		sep    string
	}{
		{"sep:none", []int{12}, ""},
		{"sep:hyphen", []int{4, 4, 4}, "-"},
	}
	widths := []struct {
		tag  string
		full bool
	}{
		{"notation:halfwidth", false},
		{"notation:fullwidth", true},
	}

	var cases []piifixtures.Case
	for i, lbl := range labels {
		digits := syntheticMyNumber(i)
		for _, sp := range seps {
			grouped := groupDigits(digits, sp.widths, sp.sep)
			for _, w := range widths {
				value := grouped
				if w.full {
					value = toFullWidthDigits(grouped)
				}
				cases = append(cases, piifixtures.Case{
					Line: lbl.text + "：" + value, // ：: 全角コロン
					Want: []string{"jp-my-number"},
					Tags: []string{SourceTag, "rule:jp-my-number", lbl.tag, sp.tag, w.tag},
				})
			}
		}
	}
	return cases
}

// ---- credit-card ----

// cardBrand は checksum.CreditCard のブランド判定を満たすプレフィックスと桁数。
type cardBrand struct {
	tag    string
	prefix string
	length int
}

var cardBrands = []cardBrand{
	{"brand:visa", "4", 16},
	{"brand:mastercard", "55", 16},
	{"brand:jcb", "3540", 16},
	{"brand:amex", "34", 15},
	{"brand:diners", "36", 14},
	{"brand:discover", "6011", 16},
}

// creditCardGrouping はブランドごとの一般的な表示区切り幅（合計は length と一致）。
var creditCardGrouping = map[string][]int{
	"brand:visa":       {4, 4, 4, 4},
	"brand:mastercard": {4, 4, 4, 4},
	"brand:jcb":        {4, 4, 4, 4},
	"brand:amex":       {4, 6, 5},
	"brand:diners":     {4, 6, 4},
	"brand:discover":   {4, 4, 4, 4},
}

// CreditCardCases はクレジットカードのブランド × 区切り × 全角/半角のマトリクスを返す。
func CreditCardCases() []piifixtures.Case {
	seps := []struct {
		tag string
		sep string
	}{
		{"sep:none", ""},
		{"sep:hyphen", "-"},
		{"sep:space", " "},
	}
	widths := []struct {
		tag  string
		full bool
	}{
		{"notation:halfwidth", false},
		{"notation:fullwidth", true},
	}

	var cases []piifixtures.Case
	for _, brand := range cardBrands {
		digits := syntheticCardNumber(brand.prefix, brand.length)
		widthsGroup := creditCardGrouping[brand.tag]
		for _, sp := range seps {
			grouping := []int{brand.length}
			if sp.sep != "" {
				grouping = widthsGroup
			}
			grouped := groupDigits(digits, grouping, sp.sep)
			for _, w := range widths {
				value := grouped
				if w.full {
					value = toFullWidthDigits(grouped)
				}
				cases = append(cases, piifixtures.Case{
					Line: "カード番号：" + value, // "カード番号："
					Want: []string{"credit-card"},
					Tags: []string{SourceTag, "rule:credit-card", brand.tag, sp.tag, w.tag},
				})
			}
		}
	}
	return cases
}

// ---- jp-postal-code ----

// PostalCodeCases は実在する郵便番号（dict.SamplePostalCodes）に対する、
// 〒記号/ラベル語/ラベルなしのマトリクスを返す。ラベルなしケースは
// RequireContext で棄却される陰性ケース（polarity:negative）として含める。
func PostalCodeCases() []piifixtures.Case {
	codes := dict.SamplePostalCodes(2)
	var cases []piifixtures.Case
	for _, code := range codes {
		hyphenated := code[:3] + "-" + code[3:]

		type variant struct {
			tags  []string
			line  string
			match bool // 期待検出があるか（false なら Want は空の陰性ケース）
		}
		variants := []variant{
			{[]string{"format:mark", "sep:hyphen", "notation:halfwidth"}, "〒" + hyphenated, true},
			{[]string{"format:mark", "sep:none", "notation:halfwidth"}, "〒" + code, true},
			{[]string{"format:mark", "sep:hyphen", "notation:fullwidth"}, "〒" + toFullWidthDigits(hyphenated), true},
			{[]string{"format:word", "sep:hyphen", "notation:halfwidth"}, "郵便番号：" + hyphenated, true}, // "郵便番号："
			{[]string{"format:word", "sep:hyphen", "notation:fullwidth"}, "郵便番号：" + toFullWidthDigits(hyphenated), true},
			{[]string{"format:bare", "sep:hyphen", "polarity:negative"}, hyphenated + "を入力", false}, // "を入力" （文脈語・〒なし）
			{[]string{"format:bare", "sep:none", "polarity:negative"}, code + "を入力", false},
		}
		for _, v := range variants {
			c := piifixtures.Case{
				Line: v.line,
				Tags: append([]string{SourceTag, "rule:jp-postal-code"}, v.tags...),
			}
			if v.match {
				c.Want = []string{"jp-postal-code"}
			}
			cases = append(cases, c)
		}
	}

	// クロスライン（content/diff）: ラベルは直前行、値は同一行にマークも文脈語も無い。
	// RequireContext ルールは ScanContent の隣接 2 行ウィンドウで文脈補完されるため
	// 検出される（jp-pii-detect の仕様。CLAUDE.md のアーキテクチャ節を参照）。
	if len(codes) > 0 {
		hyphenated := codes[0][:3] + "-" + codes[0][3:]
		cases = append(cases,
			piifixtures.Case{
				Content: "郵便番号\n" + hyphenated, // ラベル行 + 値行（値は実行時に合成する。コメントへの値の例示は避ける）
				Want:    []string{"jp-postal-code"},
				Tags:    []string{SourceTag, "rule:jp-postal-code", "layout:cross-line", "format:bare", "sep:hyphen"},
			},
			piifixtures.Case{
				Diff: []piifixtures.DiffLine{
					{Text: "郵便番号", Added: false},
					{Text: hyphenated, Added: true},
				},
				Want: []string{"jp-postal-code"},
				Tags: []string{SourceTag, "rule:jp-postal-code", "layout:cross-line", "format:bare", "sep:hyphen"},
			},
		)
	}
	return cases
}

// ---- person-name ----

// personNamePairCount は生成する姓名ペアの数。issue #70 のフェーズ2方針
// （「いきなり100〜300件/ルールではなく、まず数十件/ルールから始める」）に
// 沿って小さく保つ。辞書は数千〜数万件あるが、ここでは表記ゆれの網羅が目的で
// 姓名の種類数を稼ぐことが目的ではない。
const personNamePairCount = 5

// PersonNameCases は氏名辞書からの姓名ペア × ラベル種別のマトリクスを返す。
func PersonNameCases() []piifixtures.Case {
	// 弱いラベル（姓・名単独）は 2 文字以上でないと単独要素として通らない
	// （internal/rule.validNameField）ため、2 文字以上の候補だけを使う。
	// 辞書全体ではなく personNamePairCount 件ぶんだけ確保できればよいが、
	// フィルタで落ちる候補がある分、余裕を持ってサンプルする。
	pool := personNamePairCount * 4
	surnames := filterMinRunes(dict.SurnameSample(pool), 2, 4)
	givens := filterMinRunes(dict.GivenNameSample(pool), 2, 4)
	n := min(personNamePairCount, len(surnames), len(givens))

	var cases []piifixtures.Case
	for i := 0; i < n; i++ {
		surname, given := surnames[i], givens[i]
		full := surname + given
		fullSpaced := surname + " " + given
		fullFullwidthSpace := surname + "　" + given // 全角スペース

		cases = append(cases,
			nameCase("氏名："+full, []string{"label:jp-strong", "format:packed"}),                          // "氏名："
			nameCase("氏名："+fullSpaced, []string{"label:jp-strong", "format:spaced"}),                    // "氏名："
			nameCase("氏名："+fullFullwidthSpace, []string{"label:jp-strong", "notation:fullwidth-space"}), // "氏名："
			nameCase("full_name="+full, []string{"label:ascii-strong", "format:packed"}),
			nameCase("姓："+surname, []string{"label:weak-surname"}), // "姓："
			nameCase("名："+given, []string{"label:weak-given"}),     // "名："
			nameCase("name: "+full, []string{"label:weak-ascii-bare"}),
		)
	}
	// 陰性ケース: 弱い ASCII ラベルはあるが値が辞書に無い（人名らしくない）ため
	// 棄却されるべきケース（表記ゆれではなく値バリデーションの回帰確認。1 件で十分）。
	cases = append(cases, piifixtures.Case{
		Line: "name: プロジェクト", // "name: プロジェクト"
		Tags: []string{SourceTag, "rule:person-name", "label:weak-ascii-bare", "polarity:negative"},
	})
	return cases
}

func nameCase(line string, extraTags []string) piifixtures.Case {
	tags := append([]string{SourceTag, "rule:person-name"}, extraTags...)
	return piifixtures.Case{Line: line, Want: []string{"person-name"}, Tags: tags}
}

// filterMinRunes は minRunes 以上 maxRunes 以下のルーン数を持つ要素だけを残す。
func filterMinRunes(list []string, minRunes, maxRunes int) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		n := len([]rune(s))
		if n >= minRunes && n <= maxRunes {
			out = append(out, s)
		}
	}
	return out
}

// ---- JSON 書き出し（cmd/pii-dataset-gen 用） ----

// File は internal/piifixtures が読み込む JSON スキーマ
// （{"strings": {...}, "dataset": [...]}）と互換の書き出し用構造体。
// fixturegen が計算合成するケースは Strings（生 PII 文字列の定数プール）を
// 使わないため常に空。
type File struct {
	Strings map[string]string  `json:"strings"`
	Dataset []piifixtures.Case `json:"dataset"`
}

// GenerateFile はデータセット全体を File として返す（JSON マーシャルは
// 呼び出し側 / cmd/pii-dataset-gen に任せる）。
func GenerateFile() File {
	return File{Strings: map[string]string{}, Dataset: Generate()}
}

// Summary はルール ID ごとの生成件数を人間可読な文字列で返す（CLI のログ用）。
func Summary(cases []piifixtures.Case) string {
	counts := map[string]int{}
	var order []string
	for _, c := range cases {
		for _, w := range c.Want {
			if counts[w] == 0 {
				order = append(order, w)
			}
			counts[w]++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "total cases: %d\n", len(cases))
	for _, id := range order {
		fmt.Fprintf(&b, "  %s: %d positive\n", id, counts[id])
	}
	return b.String()
}
