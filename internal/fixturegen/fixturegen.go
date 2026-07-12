// Package fixturegen は「ルール × 表記ゆれ」のマトリクスに沿った合成評価ケース
// （internal/evalcase.Case）を生成する。値はすべて checksum のチェックディジット
// 算出ロジックや公開dictから作る合成値、または実在する暦日・市外局番等の
// 形式的制約を計算で満たすダミー値で、人物レコードから採取したPIIはソースに
// 含まれない。生成値が実在する番号空間と偶然一致しないことは保証しない。
//
// 対応ルールは、値の妥当性を検証だけでなく合成もできる（チェックディジットを
// 逆算できる、実在辞書から抽出できる、または実在の形式的制約を計算で満たせる）
// ものに限定している:
//
//   - jp-my-number: checksum.MyNumber のチェックディジット式を逆算する。
//   - credit-card: checksum.Luhn のチェックディジットを逆算し、ブランド
//     プレフィックス（checksum.CreditCard が要求する範囲）を満たす。
//   - jp-postal-code: dict.SamplePostalCodes でビットセットから実在番号を抽出する
//     （郵便番号自体はチェックディジットを持たないため、実在性でしか合成できない。
//     postal_codes.bitset は既にコミット済みのデータで新規の秘匿情報ではない）。
//   - person-name: dict.SurnameSample / dict.GivenNameSample で姓名辞書から
//     実在する姓・名を抽出する。
//   - jp-phone-number: 携帯・固定ともチェックディジットを持たないため、決定式で
//     生成した非連番・非全桁同一のダミー下位桁と、市外局番辞書（dict.ValidAreaCode
//     のシードデータ）に実在する市外局番（03・06）を組み合わせて合成する。
//   - jp-birthdate: validBirthdate が実在する暦日だけを許可するため、実在暦日
//     1 件を固定で使い、西暦・和暦・略記・区切りなし8桁の各表記へ変換する。
//   - jp-address: 都道府県名・市区町村名をサンプリングする公開dict APIが無いため、
//     実在する組み合わせ（東京都渋谷区神南）を 1 つだけ使い、番地部分はパターンが
//     要求する形状のみを満たす架空の値を付与する（番地自体の実在性は検証しない）。
//   - jp-bank-account: 口座番号もチェックディジットを持たないため、
//     syntheticPhoneDigits と同じ決定式（プレースホルダパターンを避けた
//     任意桁数のダミー数字列）を桁数だけ変えて流用する（Validate は
//     checksum.AllSame 棄却のみで、辞書照合や実在性検証は無い）。
//
// 上記に加え、ラベル行と値行が別行に分かれる隣接行相関（クロスライン昇格。
// CrossLinePromotionCases）と、CSV/TSV のヘッダ列名が同一列のデータ行へ文脈を
// 与える経路（CSVColumnContextCases）も、jp-phone-number・jp-bank-account を
// 題材にした契約ケースとして生成する。
//
// 生成物は internal/evalcase の JSON スキーマ（dataset 配列）に互換な
// []evalcase.Case で、cmd/pii-dataset-gen が JSON として書き出す。出力は
// private corpusのF1分母へはマージせず、仕様契約のpass/failにだけ使う。
package fixturegen

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/dict"
	"github.com/baneido/jp-pii-detector/internal/evalcase"
)

// SourceTag はこのパッケージが生成したケースすべてに付与するタグ。非公開評価
// コーパスと混ぜず、公開の仕様契約として層別集計するために使う。
const SourceTag = "source:synthetic"

// Generate はすべての対応ルールの合成ケースを結合して返す。
func Generate() []evalcase.Case {
	var cases []evalcase.Case
	cases = append(cases, MyNumberCases()...)
	cases = append(cases, CreditCardCases()...)
	cases = append(cases, PostalCodeCases()...)
	cases = append(cases, PersonNameCases()...)
	cases = append(cases, PhoneNumberCases()...)
	cases = append(cases, BirthdateCases()...)
	cases = append(cases, AddressCases()...)
	cases = append(cases, CrossLinePromotionCases()...)
	cases = append(cases, CSVColumnContextCases()...)
	counts := map[string]int{}
	for i := range cases {
		key := "negative"
		if len(cases[i].Want) > 0 {
			key = cases[i].Want[0]
		} else {
			for _, tag := range cases[i].Tags {
				if strings.HasPrefix(tag, "rule:") {
					key = strings.TrimPrefix(tag, "rule:") + "-negative"
					break
				}
			}
		}
		counts[key]++
		cases[i].ID = fmt.Sprintf("synthetic-%s-%03d", key, counts[key])
		cases[i].SourceClass = "algorithmic"
	}
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

// expectedSpan は line 内の value に対する期待スパンを作る。検出器と同じ
// ルーンオフセットを使い、生成ロジックの変更で期待位置も追従させる。
func expectedSpan(line, value, ruleID, confidence string, lineNo int) []evalcase.Span {
	byteStart := strings.Index(line, value)
	if byteStart < 0 {
		panic("fixturegen: value is not contained in line")
	}
	start := utf8.RuneCountInString(line[:byteStart])
	return []evalcase.Span{{
		RuleID:         ruleID,
		Line:           lineNo,
		Start:          start,
		End:            start + utf8.RuneCountInString(value),
		WantConfidence: confidence,
	}}
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

// toFullWidthAll は normalize.Line が畳む範囲（ASCII 印字可能文字 U+0021-007E と
// 半角スペース）を全角へ変換する（normalize.Line の逆写像）。toFullWidthDigits は
// 数字とハイフンだけが対象だが、電話番号の空白区切り・括弧書き・+81 国際表記や
// 生年月日のスラッシュ・ドット区切り・元号略記のアルファベットなど、区切り記号や
// 英字を含む値全体を全角化した表記ゆれケースを作るために使う。
func toFullWidthAll(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == ' ':
			b.WriteRune('　') // IDEOGRAPHIC SPACE
		case r >= '!' && r <= '~':
			b.WriteRune(r + 0xFEE0)
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
// checksum.MyNumber を満たす12桁の合成値を返す。採取値ではないが、
// 実在する番号空間との偶然一致までは否定しない。
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
// 採取値ではないが、番号空間との偶然一致までは否定しない。
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
func MyNumberCases() []evalcase.Case {
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

	var cases []evalcase.Case
	for i, lbl := range labels {
		digits := syntheticMyNumber(i)
		for _, sp := range seps {
			grouped := groupDigits(digits, sp.widths, sp.sep)
			for _, w := range widths {
				value := grouped
				if w.full {
					value = toFullWidthDigits(grouped)
				}
				line := lbl.text + "：" + value
				cases = append(cases, evalcase.Case{
					Line:  line, // ：: 全角コロン
					Want:  []string{"jp-my-number"},
					Spans: expectedSpan(line, value, "jp-my-number", "high", 0),
					Tags:  []string{SourceTag, "rule:jp-my-number", lbl.tag, sp.tag, w.tag},
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
func CreditCardCases() []evalcase.Case {
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

	var cases []evalcase.Case
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
				line := "カード番号：" + value
				cases = append(cases, evalcase.Case{
					Line:  line, // "カード番号："
					Want:  []string{"credit-card"},
					Spans: expectedSpan(line, value, "credit-card", "high", 0),
					Tags:  []string{SourceTag, "rule:credit-card", brand.tag, sp.tag, w.tag},
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
func PostalCodeCases() []evalcase.Case {
	codes := dict.SamplePostalCodes(2)
	var cases []evalcase.Case
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
			c := evalcase.Case{
				Line: v.line,
				Tags: append([]string{SourceTag, "rule:jp-postal-code"}, v.tags...),
			}
			if v.match {
				c.Want = []string{"jp-postal-code"}
				value := hyphenated
				confidence := "medium"
				if strings.Contains(v.tags[0], "mark") {
					value = v.line
					confidence = "high"
				} else if strings.Contains(v.tags[2], "fullwidth") {
					value = toFullWidthDigits(hyphenated)
				}
				c.Spans = expectedSpan(v.line, value, "jp-postal-code", confidence, 0)
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
			evalcase.Case{
				Content: "郵便番号\n" + hyphenated, // ラベル行 + 値行（値は実行時に合成する。コメントへの値の例示は避ける）
				Want:    []string{"jp-postal-code"},
				Spans:   expectedSpan(hyphenated, hyphenated, "jp-postal-code", "medium", 2),
				Tags:    []string{SourceTag, "rule:jp-postal-code", "layout:cross-line", "format:bare", "sep:hyphen"},
			},
			evalcase.Case{
				Diff: []evalcase.DiffLine{
					{Text: "郵便番号", Added: false},
					{Text: hyphenated, Added: true},
				},
				Want:  []string{"jp-postal-code"},
				Spans: expectedSpan(hyphenated, hyphenated, "jp-postal-code", "medium", 2),
				Tags:  []string{SourceTag, "rule:jp-postal-code", "layout:cross-line", "format:bare", "sep:hyphen"},
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
func PersonNameCases() []evalcase.Case {
	// 弱いラベル（姓・名単独）は 2 文字以上でないと単独要素として通らない
	// （internal/rule.validNameField）ため、2 文字以上の候補だけを使う。
	// 辞書全体ではなく personNamePairCount 件ぶんだけ確保できればよいが、
	// フィルタで落ちる候補がある分、余裕を持ってサンプルする。
	pool := personNamePairCount * 4
	surnames := filterMinRunes(dict.SurnameSample(pool), 2, 4)
	givens := filterMinRunes(dict.GivenNameSample(pool), 2, 4)
	n := min(personNamePairCount, len(surnames), len(givens))

	var cases []evalcase.Case
	for i := 0; i < n; i++ {
		surname, given := surnames[i], givens[i]
		full := surname + given
		fullSpaced := surname + " " + given
		fullFullwidthSpace := surname + "　" + given // 全角スペース

		cases = append(cases,
			nameCase("氏名："+full, full, []string{"label:jp-strong", "format:packed"}),                                        // "氏名："
			nameCase("氏名："+fullSpaced, fullSpaced, []string{"label:jp-strong", "format:spaced"}),                            // "氏名："
			nameCase("氏名："+fullFullwidthSpace, fullFullwidthSpace, []string{"label:jp-strong", "notation:fullwidth-space"}), // "氏名："
			nameCase("full_name="+full, full, []string{"label:ascii-strong", "format:packed"}),
			nameCase("姓："+surname, surname, []string{"label:weak-surname"}), // "姓："
			nameCase("名："+given, given, []string{"label:weak-given"}),       // "名："
			nameCase("name: "+full, full, []string{"label:weak-ascii-bare"}),
		)
	}
	// 陰性ケース: 弱い ASCII ラベルはあるが値が辞書に無い（人名らしくない）ため
	// 棄却されるべきケース（表記ゆれではなく値バリデーションの回帰確認。1 件で十分）。
	cases = append(cases, evalcase.Case{
		Line: "name: プロジェクト", // "name: プロジェクト"
		Tags: []string{SourceTag, "rule:person-name", "label:weak-ascii-bare", "polarity:negative"},
	})
	return cases
}

func nameCase(line, value string, extraTags []string) evalcase.Case {
	tags := append([]string{SourceTag, "rule:person-name"}, extraTags...)
	return evalcase.Case{
		Line:  line,
		Want:  []string{"person-name"},
		Spans: expectedSpan(line, value, "person-name", "medium", 0),
		Tags:  tags,
	}
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

// ---- jp-phone-number ----

// syntheticPhoneDigits は seed ごとに異なる（全桁同一にも昇順連番にもならない）
// length 桁のダミー電話番号下位桁を返す。既存の syntheticMyNumber と同じ決定式の
// 流儀で生成し、採取値ではない（TestSyntheticPhoneDigitsAvoidsPlaceholderPatterns
// で checksum.AllSame / checksum.IsZeroPaddedSequential のいずれにも該当しないことを
// 回帰確認する）。checksum を持たない他の桁数固定ルール（jp-bank-account の
// 7桁口座番号等）のダミー値合成にも、length を変えるだけで流用する。
func syntheticPhoneDigits(seed, length int) string {
	b := make([]byte, length)
	for i := range b {
		d := (i*3 + seed*7 + 2) % 10
		b[i] = byte('0' + d)
	}
	return string(b)
}

// PhoneNumberCases は種別（携帯090/固定03）× 区切り（ハイフン/なし/空白
// [携帯限定]/括弧[固定限定]/+81 国際）× 全角半角のマトリクスを返す。ドット区切りは
// 対象外（並行変更中のため）。固定電話の市外局番は市外局番辞書のシードデータに
// 確実に存在する 03 のみを使う。
func PhoneNumberCases() []evalcase.Case {
	mobileLocal := syntheticPhoneDigits(0, 8)   // 携帯 "090" に続く8桁
	landlineLocal := syntheticPhoneDigits(1, 8) // 固定 "03" に続く8桁

	// variant.confidence: 区切りなし固定電話（RequireContext）は Base（Medium）から
	// 昇格しないため常に medium。それ以外はラベルによる昇格、または元々の Base が
	// High のため high になる（internal/detect の仕様。CLAUDE.md アーキテクチャ節・
	// internal/detect/detect_test.go の TestPhoneNumberSeparatorVariants 系を参照）。
	type variant struct {
		tags       []string
		value      string
		confidence string
	}
	notations := []struct {
		tag  string
		full bool
	}{{"notation:halfwidth", false}, {"notation:fullwidth", true}}

	render := func(label string, variants []variant) []evalcase.Case {
		var out []evalcase.Case
		for _, v := range variants {
			for _, w := range notations {
				value := v.value
				if w.full {
					value = toFullWidthAll(value)
				}
				line := label + value
				tags := []string{SourceTag, "rule:jp-phone-number"}
				tags = append(tags, v.tags...)
				tags = append(tags, w.tag)
				out = append(out, evalcase.Case{
					Line:  line,
					Want:  []string{"jp-phone-number"},
					Spans: expectedSpan(line, value, "jp-phone-number", v.confidence, 0),
					Tags:  tags,
				})
			}
		}
		return out
	}

	mobileVariants := []variant{
		{[]string{"type:mobile", "sep:hyphen"}, "090-" + mobileLocal[:4] + "-" + mobileLocal[4:], "high"},
		{[]string{"type:mobile", "sep:none"}, "090" + mobileLocal, "high"},
		{[]string{"type:mobile", "sep:space"}, "090 " + mobileLocal[:4] + " " + mobileLocal[4:], "high"},
		{[]string{"type:mobile", "sep:intl"}, "+81-90-" + mobileLocal[:4] + "-" + mobileLocal[4:], "high"},
	}
	landlineVariants := []variant{
		{[]string{"type:landline", "sep:hyphen"}, "03-" + landlineLocal[:4] + "-" + landlineLocal[4:], "high"},
		{[]string{"type:landline", "sep:none"}, "03" + landlineLocal, "medium"},
		{[]string{"type:landline", "sep:parens"}, "(03) " + landlineLocal[:4] + "-" + landlineLocal[4:], "high"},
		{[]string{"type:landline", "sep:intl"}, "+81-3-" + landlineLocal[:4] + "-" + landlineLocal[4:], "high"},
	}

	var cases []evalcase.Case
	cases = append(cases, render("携帯：", mobileVariants)...)     // "携帯："
	cases = append(cases, render("電話番号：", landlineVariants)...) // "電話番号："

	// 陰性ケース（既存 postal の例に倣う。金額文脈での抑制を確認する）。
	cases = append(cases,
		// 汎用負文脈語（伝票番号）は、コンテキストキーワードと同一行にあっても
		// 区切りなし固定電話（RequireContext）を抑制する（既存挙動。
		// internal/detect/detect_test.go の
		// TestPhoneNegativeContextOnlyAppliesToLandlineNoSep 相当）。
		evalcase.Case{
			Line: "電話番号: " + "03" + landlineLocal + " 伝票番号", // "電話番号: " … " 伝票番号"
			Tags: []string{SourceTag, "rule:jp-phone-number", "type:landline", "sep:none", "polarity:negative"},
		},
		// 通貨単位（円）が値に直接隣接すると、ラベルなしの空白区切り携帯は抑制される。
		evalcase.Case{
			Line: "090 " + mobileLocal[:4] + " " + mobileLocal[4:] + "円",
			Tags: []string{SourceTag, "rule:jp-phone-number", "type:mobile", "sep:space", "polarity:negative"},
		},
	)
	return cases
}

// ---- jp-birthdate ----

// birthdateSamples は実在する暦日 1 件（1985-01-02 = 昭和60年1月2日）を、検出
// パターンが要求する 4 形式（西暦・和暦・略記・区切りなし8桁）で表現したもの。
// validBirthdate は実在する暦日だけを許可するため、形式を問わず同じ日で揃える。
var birthdateSamples = []struct {
	tag   string
	value string
}{
	{"format:seireki", "1985/01/02"},
	{"format:wareki", "昭和60年1月2日"},
	{"format:wareki-abbrev", "S60.1.2"},
	{"format:digits8", "19850102"},
}

// BirthdateCases はラベル（生年月日/誕生日/DOB）× 形式（西暦・和暦・略記・区切り
// なし8桁）× 全角半角のマトリクスを返す。jp-birthdate ルールは Context 語彙を持たず
// パターン自体にラベルが埋め込まれているため、信頼度は常に medium（Base から
// 昇格しない）。区切りなし8桁はラベル直結が検出の前提（現行仕様）のため、本
// マトリクスは全形式でラベルと値を同一行・直結（コロンまたは直接連結）で生成する
// （クロスラインの表記ゆれは対象外）。
func BirthdateCases() []evalcase.Case {
	labels := []struct{ tag, prefix string }{
		{"label:jp-strong", "生年月日："}, // "生年月日："
		{"label:jp-alt", "誕生日："},     // "誕生日："
		{"label:ascii", "DOB: "},
	}
	notations := []struct {
		tag  string
		full bool
	}{{"notation:halfwidth", false}, {"notation:fullwidth", true}}

	var cases []evalcase.Case
	for _, lbl := range labels {
		for _, f := range birthdateSamples {
			for _, w := range notations {
				value := f.value
				if w.full {
					value = toFullWidthAll(value)
				}
				line := lbl.prefix + value
				cases = append(cases, evalcase.Case{
					Line:  line,
					Want:  []string{"jp-birthdate"},
					Spans: expectedSpan(line, value, "jp-birthdate", "medium", 0),
					Tags:  []string{SourceTag, "rule:jp-birthdate", lbl.tag, f.tag, w.tag},
				})
			}
		}
	}
	return cases
}

// ---- jp-address ----

// AddressCases は形式（丁目/番/号マーカー付き番地・ダッシュ連結番地・漢数字番地）×
// 全角半角（漢数字番地は数字の全角/半角という概念が無いため対象外）のマトリクスを
// 返す。都道府県名・市区町村名をサンプリングする公開 dict API が無いため、実在する
// 組み合わせ（東京都渋谷区神南）を定数 1 つで使う。番地部分は架空（パターンが
// 要求する形状だけを満たす）。ドッグフード対象のソースへ実在住所＋番地の完全な
// 文字列を literal で書かないよう、都道府県+市区町村部分と番地部分は別々の値として
// 保持し、実行時に連結する。
func AddressCases() []evalcase.Case {
	const prefectureCity = "東京都渋谷区神南" // 実在（渋谷区神南）。番地は架空。

	type variant struct {
		tags   []string
		banchi string
	}
	asciiVariants := []variant{
		{[]string{"format:banchi-marker"}, "1丁目19番11号"},
		// 末尾のダッシュ連結が実在の暦日（YYYY-MM-DD、notCalendarDateBanchi）と
		// 解釈されないよう、先頭成分を 1900-2100 の範囲外にする。
		{[]string{"format:dash"}, "1-19-11"},
	}
	notations := []struct {
		tag  string
		full bool
	}{{"notation:halfwidth", false}, {"notation:fullwidth", true}}

	var cases []evalcase.Case
	for _, v := range asciiVariants {
		for _, w := range notations {
			banchi := v.banchi
			if w.full {
				banchi = toFullWidthAll(banchi)
			}
			line := prefectureCity + banchi
			tags := []string{SourceTag, "rule:jp-address"}
			tags = append(tags, v.tags...)
			tags = append(tags, w.tag)
			cases = append(cases, evalcase.Case{
				Line:  line,
				Want:  []string{"jp-address"},
				Spans: expectedSpan(line, line, "jp-address", "high", 0),
				Tags:  tags,
			})
		}
	}

	// 漢数字番地は全角/半角の概念が無いため単独ケース。
	kanjiLine := prefectureCity + "一丁目十九番十一号"
	cases = append(cases, evalcase.Case{
		Line:  kanjiLine,
		Want:  []string{"jp-address"},
		Spans: expectedSpan(kanjiLine, kanjiLine, "jp-address", "high", 0),
		Tags:  []string{SourceTag, "rule:jp-address", "format:kanji-banchi"},
	})

	// 陰性ケース: ISO 日付（YYYY-MM-DD）は番地のダッシュ連結と字面が似るが、市区
	// 町村直後の助詞「で」が番地とのギャップの許容文字集合に無いため、住所として
	// 検出されない（notCalendarDateBanchi に到達する前に regexp 自体が不一致になる。
	// hiraganaNoParticle のコメント参照）。
	cases = append(cases, evalcase.Case{
		Line: "東京都渋谷区で2025-07-02に開催",
		Tags: []string{SourceTag, "rule:jp-address", "polarity:negative"},
	})
	return cases
}

// ---- クロスライン昇格契約（jp-phone-number / jp-bank-account） ----

// CrossLinePromotionCases は、ラベル行と値行が別の行に分かれ、隣接行相関
// （ScanContent の2行ウィンドウ・ScanDiffHunk の文脈行相関、いずれも
// internal/detect.maxAdjacentLineGap まで）で RequireContext が成立する経路の
// 契約ケースを返す。jp-postal-code の既存クロスラインケース（本ファイル内、
// PostalCodeCases 末尾）の構造をそのまま踏襲し、区切りなし固定電話
// （jp-phone-number）と銀行口座番号（jp-bank-account）へ展開する。
//
// この2ルールの対象パターンはいずれも RequireContext: true のみで構成される
// （internal/rule/builtin.go の `0\d{9}`・`\d{7}`）。internal/detect の実装
// コメント（「RequireContext のパターンはキーワードの存在が検出の前提であり
// 昇格の根拠にならないため、Base の信頼度のまま報告する」）通り、ラベルが
// 同一行・隣接行いずれで見つかっても Medium から昇格しないことを、実際に
// ScanContent/ScanDiffHunk を呼んで確認した（ContextPromoted は立たず、
// FinalConfidence は常に medium）。そのため期待信頼度はすべて "medium"。
//
// 固定電話は市外局番辞書（dict.ValidAreaCode のシードデータ）に確実に存在する
// 03 を使う。口座番号は checksum を持たないため syntheticPhoneDigits を桁数
// だけ変えて流用する（口座番号の Validate は checksum.AllSame 棄却のみ）。
func CrossLinePromotionCases() []evalcase.Case {
	// 直接隣接（j-i=1、空行なし）用と、空行 1 つを挟む論理隣接（j-i=2、
	// maxAdjacentLineGap<=3 の契約）用に、それぞれ別の合成値を使う。
	phoneAdjacent := "03" + syntheticPhoneDigits(2, 8)
	phoneGapped := "03" + syntheticPhoneDigits(3, 8)
	bankAdjacent := syntheticPhoneDigits(4, 7)
	bankGapped := syntheticPhoneDigits(5, 7)

	var cases []evalcase.Case

	// jp-phone-number: ラベル行「電話番号:」+ 次行に区切りなし固定10桁。
	cases = append(cases,
		evalcase.Case{
			Content: "電話番号:\n" + phoneAdjacent,
			Want:    []string{"jp-phone-number"},
			Spans:   expectedSpan(phoneAdjacent, phoneAdjacent, "jp-phone-number", "medium", 2),
			Tags:    []string{SourceTag, "rule:jp-phone-number", "layout:cross-line", "format:bare", "sep:none", "type:landline"},
		},
		evalcase.Case{
			Diff: []evalcase.DiffLine{
				{Text: "電話番号:", Added: false},
				{Text: phoneAdjacent, Added: true},
			},
			Want:  []string{"jp-phone-number"},
			Spans: expectedSpan(phoneAdjacent, phoneAdjacent, "jp-phone-number", "medium", 2),
			Tags:  []string{SourceTag, "rule:jp-phone-number", "layout:cross-line", "format:bare", "sep:none", "type:landline"},
		},
		evalcase.Case{
			Content: "電話番号:\n\n" + phoneGapped,
			Want:    []string{"jp-phone-number"},
			Spans:   expectedSpan(phoneGapped, phoneGapped, "jp-phone-number", "medium", 3),
			Tags:    []string{SourceTag, "rule:jp-phone-number", "layout:cross-line-gap", "format:bare", "sep:none", "type:landline"},
		},
	)

	// jp-bank-account: ラベル行「口座番号:」+ 次行7桁。
	cases = append(cases,
		evalcase.Case{
			Content: "口座番号:\n" + bankAdjacent,
			Want:    []string{"jp-bank-account"},
			Spans:   expectedSpan(bankAdjacent, bankAdjacent, "jp-bank-account", "medium", 2),
			Tags:    []string{SourceTag, "rule:jp-bank-account", "layout:cross-line", "format:bare"},
		},
		evalcase.Case{
			Diff: []evalcase.DiffLine{
				{Text: "口座番号:", Added: false},
				{Text: bankAdjacent, Added: true},
			},
			Want:  []string{"jp-bank-account"},
			Spans: expectedSpan(bankAdjacent, bankAdjacent, "jp-bank-account", "medium", 2),
			Tags:  []string{SourceTag, "rule:jp-bank-account", "layout:cross-line", "format:bare"},
		},
		evalcase.Case{
			Content: "口座番号:\n\n" + bankGapped,
			Want:    []string{"jp-bank-account"},
			Spans:   expectedSpan(bankGapped, bankGapped, "jp-bank-account", "medium", 3),
			Tags:    []string{SourceTag, "rule:jp-bank-account", "layout:cross-line-gap", "format:bare"},
		},
	)

	return cases
}

// ---- CSV 列コンテキスト契約 ----

// CSVColumnContextCases は .csv/.tsv 専用の列コンテキスト機構
// （internal/detect/csv_context.go）の契約ケースを返す。ヘッダ行の列ラベルが
// 同一列の全データ行へ文脈を与える経路で、隣接±1行ウィンドウでは届かない
// 3行目以降のデータ行まで文脈が伝播する点が要点のため、データ行を3行用意する。
// Case.File を .csv 拡張子にした content ケースとして構成する
// （internal/detect.sourceKindForPath が拡張子で CSV 専用パーサへ分岐するため、
// File 未指定＝拡張子なしの既定 "dataset" では CSV 経路に入らない）。
//
// 高再現率専用の氏名列走査（scanCSVNameColumns。ヘッダが rule.CSVNameHeaderRe に
// 一致する列だけ rule.CSVNameValueRe + ValidCrossLineName で検証する経路）は
// --high-recall / [rules] high_recall=true のときだけ呼ばれる。fixturegen は
// internal/eval の既定オプション（low プロファイル、high_recall=false）で
// 評価する前提のため対象外とする。
func CSVColumnContextCases() []evalcase.Case {
	const header = "電話番号,金額" // 電話番号列 / 金額列
	phones := [3]string{
		"03" + syntheticPhoneDigits(6, 8),
		"03" + syntheticPhoneDigits(7, 8),
		"03" + syntheticPhoneDigits(8, 8),
	}
	// 金額列は電話番号列と同じ10桁（"同形"）の数字だが、jp-phone-number の
	// 全パターンが先頭 0 または +81 を要求するため、先頭を 0 以外にすることで
	// 文脈の有無に関わらず正規表現の時点で一致し得ない。列コンテキストの
	// 選択性（金額列には「電話」文脈が付与されないこと）を、隣接行ウィンドウの
	// 到達範囲やたまたまの負文脈語彙の有無に依存せず、構造的に保証するため。
	amounts := [3]string{
		"9" + syntheticPhoneDigits(16, 9),
		"9" + syntheticPhoneDigits(17, 9),
		"9" + syntheticPhoneDigits(18, 9),
	}

	dataLines := make([]string, len(phones))
	for i := range dataLines {
		dataLines[i] = phones[i] + "," + amounts[i]
	}

	// 正負ペア: 電話番号列の区切りなし固定10桁は（1行目のヘッダ直下だけでなく
	// 3行目以降も含めて）検出され、金額列の同形数字は検出されない。
	var spans []evalcase.Span
	for i, line := range dataLines {
		spans = append(spans, expectedSpan(line, phones[i], "jp-phone-number", "medium", i+2)...)
	}
	positive := evalcase.Case{
		File:    "synthetic.csv",
		Content: header + "\n" + strings.Join(dataLines, "\n"),
		Want:    []string{"jp-phone-number"},
		Spans:   spans,
		Tags:    []string{SourceTag, "rule:jp-phone-number", "layout:csv-column", "format:bare", "sep:none", "type:landline"},
	}

	// 陰性契約: 1行目が header-shaped でない（フィールドが数字多数）場合、
	// looksLikeCSVHeader が false を返し、列コンテキストはファイル全体で
	// 無効になる（安全側のデフォルト）。ヘッダを取り除いた同じデータ行だけを
	// 並べると、ラベルが存在しないため隣接行相関も効かず、電話番号列の値は
	// 一切検出されない。
	negative := evalcase.Case{
		File:    "synthetic-noheader.csv",
		Content: strings.Join(dataLines, "\n"),
		Tags:    []string{SourceTag, "rule:jp-phone-number", "layout:csv-column", "polarity:negative", "csv:non-header-first-row"},
	}

	return []evalcase.Case{positive, negative}
}

// ---- JSON 書き出し（cmd/pii-dataset-gen 用） ----

// File は internal/evalcase が読み込む JSON スキーマと互換の書き出し用構造体。
type File struct {
	SchemaVersion int             `json:"schema_version"`
	DatasetID     string          `json:"dataset_id"`
	Dataset       []evalcase.Case `json:"dataset"`
}

// GenerateFile はデータセット全体を File として返す（JSON マーシャルは
// 呼び出し側 / cmd/pii-dataset-gen に任せる）。
func GenerateFile() File {
	return File{SchemaVersion: 1, DatasetID: "synthetic-contract-v1", Dataset: Generate()}
}

// Summary はルール ID ごとの生成件数を人間可読な文字列で返す（CLI のログ用）。
func Summary(cases []evalcase.Case) string {
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
