// Package nemotron は、公開データセット Nemotron-PII-Japan（NVIDIA、CC BY 4.0、
// https://huggingface.co/datasets/nvidia/Nemotron-PII-Japan）の parquet を読み、
// internal/evalcase の評価ケースへ変換する。
//
// データセットは完全合成の日本語文書 10 万件で、文書全体に対する文字（コード
// ポイント）単位の PII スパンを持つ。評価ケースは行番号と行内ルーンオフセットで
// スパンを表すため、ここで変換する。ラベルは本検出器のルール ID へ対応づけ、
// 対応するルールがないラベル（日付・会社名・IP アドレス等）は正解に含めない。
// そのラベル上で検出器が何かを報告すれば、そのルールの誤検出として数える。
package nemotron

import (
	"fmt"
	"hash/fnv"
	"io"
	"sort"
	"strings"

	"github.com/parquet-go/parquet-go"

	"github.com/baneido/jp-pii-detector/internal/evalcase"
)

// Span は parquet の spans 列の 1 要素。Start/End は文書全体に対する
// コードポイント単位の半開区間。
type Span struct {
	Start int64  `parquet:"start"`
	End   int64  `parquet:"end"`
	Text  string `parquet:"text"`
	Label string `parquet:"label"`
}

// Row は parquet の 1 行のうち、変換に使う列。
type Row struct {
	UID            string `parquet:"uid"`
	Domain         string `parquet:"domain"`
	DocumentFormat string `parquet:"document_format"`
	Text           string `parquet:"text"`
	Spans          []Span `parquet:"spans,list"`
}

// SourceClass は変換した評価ケースの source_class。
const SourceClass = "nemotron-pii-japan"

// labelRule はデータセットのラベルから本検出器のルール ID への対応。氏名は
// last_name と first_name が分かれているため、convertSpans で隣接する姓名を
// 1 つのスパンへ結合する。
var labelRule = map[string]string{
	"my_number":                           "jp-my-number",
	"credit_debit_card":                   "credit-card",
	"email":                               "email-address",
	"phone_number":                        "jp-phone-number",
	"fax_number":                          "jp-phone-number",
	"previous_phone_number":               "jp-phone-number",
	"postcode":                            "jp-postal-code",
	"street_address":                      "jp-address",
	"account_number":                      "jp-bank-account",
	"date_of_birth":                       "jp-birthdate",
	"health_insurer_number":               "jp-health-insurance",
	"health_insurance_card_symbol_number": "jp-health-insurance",
	"last_name":                           "person-name",
	"first_name":                          "person-name",
}

// CoveredRuleIDs は、このデータセットに正解ラベルがあるルール ID を昇順で返す。
func CoveredRuleIDs() []string {
	seen := map[string]bool{}
	var ids []string
	for _, id := range labelRule {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// ReadParquet は r の parquet から全行を読む。
func ReadParquet(r io.ReaderAt, size int64) ([]Row, error) {
	f, err := parquet.OpenFile(r, size)
	if err != nil {
		return nil, fmt.Errorf("parquet を開けません: %w", err)
	}
	reader := parquet.NewGenericReader[Row](f)
	defer reader.Close()
	rows := make([]Row, f.NumRows())
	n, err := reader.Read(rows)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("parquet を読めません: %w", err)
	}
	if int64(n) != f.NumRows() {
		return nil, fmt.Errorf("parquet の行数が一致しません: %d / %d", n, f.NumRows())
	}
	return rows, nil
}

// Sampled は uid の FNV-1a ハッシュを modulus で割った余りが 0 の行かを返す。
// 全 10 万件の評価は 1 プロファイルに数分かかるため、uid だけで決まる抽出で
// 件数を絞る（行の並びや他の列に依存しないので、同じ revision なら常に同じ集合）。
func Sampled(uid string, modulus int) bool {
	if modulus <= 1 {
		return true
	}
	h := fnv.New32a()
	h.Write([]byte(uid))
	return h.Sum32()%uint32(modulus) == 0
}

// Convert は抽出対象の行を評価ケースへ変換する。スパンの位置が本文と食い違う
// 行があればエラーにする（revision の取り違えや変換の誤りを黙って評価しない）。
func Convert(rows []Row, modulus int) ([]evalcase.Case, error) {
	var cases []evalcase.Case
	for _, row := range rows {
		if !Sampled(row.UID, modulus) {
			continue
		}
		spans, err := convertSpans(row)
		if err != nil {
			return nil, err
		}
		cases = append(cases, evalcase.Case{
			ID:          "nemotron-" + row.UID,
			SourceClass: SourceClass,
			File:        "document.txt",
			Content:     row.Text,
			Spans:       spans,
			Tags:        []string{"domain:" + row.Domain, "format:" + row.DocumentFormat},
		})
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	return cases, nil
}

type docSpan struct {
	start, end int
	ruleID     string
	label      string
}

func convertSpans(row Row) ([]evalcase.Span, error) {
	runes := []rune(row.Text)
	var spans []docSpan
	for _, s := range row.Spans {
		start, end := int(s.Start), int(s.End)
		if start < 0 || end < start || end > len(runes) || string(runes[start:end]) != s.Text {
			return nil, fmt.Errorf("uid %s: スパン [%d,%d) が本文と一致しません", row.UID, start, end)
		}
		id, ok := labelRule[s.Label]
		if !ok {
			continue
		}
		spans = append(spans, docSpan{start: start, end: end, ruleID: id, label: s.Label})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	spans = mergeFullNames(spans, runes)

	lineStarts := []int{0}
	for i, r := range runes {
		if r == '\n' {
			lineStarts = append(lineStarts, i+1)
		}
	}
	out := make([]evalcase.Span, 0, len(spans))
	for _, s := range spans {
		line := sort.Search(len(lineStarts), func(i int) bool { return lineStarts[i] > s.start }) - 1
		if strings.ContainsRune(string(runes[s.start:s.end]), '\n') {
			return nil, fmt.Errorf("uid %s: スパン [%d,%d) が改行をまたいでいます", row.UID, s.start, s.end)
		}
		out = append(out, evalcase.Span{
			RuleID: s.ruleID,
			Line:   line + 1,
			Start:  s.start - lineStarts[line],
			End:    s.end - lineStarts[line],
		})
	}
	return out, nil
}

// mergeFullNames は、姓のスパンの直後に空白（半角・全角）だけを挟んで名の
// スパンが続く組を、1 つの person-name スパンへ結合する。検出器は「山田 太郎」を
// 1 件の氏名として報告するため、姓と名を別々の正解にすると完全一致の指標で
// 必ず食い違う。
func mergeFullNames(spans []docSpan, runes []rune) []docSpan {
	out := spans[:0]
	for i := 0; i < len(spans); i++ {
		s := spans[i]
		if s.label == "last_name" && i+1 < len(spans) && spans[i+1].label == "first_name" &&
			strings.Trim(string(runes[s.end:spans[i+1].start]), " 　") == "" {
			s.end = spans[i+1].end
			s.label = "full_name"
			i++
		}
		out = append(out, s)
	}
	return out
}
