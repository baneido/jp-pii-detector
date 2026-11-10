package nemotron

import (
	"bytes"
	"os"
	"reflect"
	"testing"

	"github.com/parquet-go/parquet-go"

	"github.com/baneido/jp-pii-detector/internal/evalcase"
)

// TestConvertSpans は、文書全体のコードポイント位置を行番号と行内位置へ変換し、
// 隣接する姓名を 1 つのスパンに結合し、対応ルールのないラベルを捨てることを
// 確認する。値はすべて架空。
func TestConvertSpans(t *testing.T) {
	text := "受付日: 令和6年7月22日\n申込者 山田　太郎 様\nTEL 090-0000-0000\n姓: 佐藤"
	row := Row{UID: "u1", Domain: "金融", DocumentFormat: "structured", Text: text, Spans: []Span{
		{Start: 5, End: 14, Text: "令和6年7月22日", Label: "date"},
		{Start: 19, End: 21, Text: "山田", Label: "last_name"},
		{Start: 22, End: 24, Text: "太郎", Label: "first_name"},
		{Start: 31, End: 44, Text: "090-0000-0000", Label: "phone_number"},
		{Start: 48, End: 50, Text: "佐藤", Label: "last_name"},
	}}
	cases, err := Convert([]Row{row}, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []evalcase.Span{
		{RuleID: "person-name", Line: 2, Start: 4, End: 9},
		{RuleID: "jp-phone-number", Line: 3, Start: 4, End: 17},
		{RuleID: "person-name", Line: 4, Start: 3, End: 5},
	}
	if len(cases) != 1 || !reflect.DeepEqual(cases[0].Spans, want) {
		t.Fatalf("spans = %+v, want %+v", cases, want)
	}
	if err := evalcase.Validate(cases); err != nil {
		t.Fatal(err)
	}
}

// TestConvertRejectsMismatchedSpan は、位置と本文が食い違うスパンをエラーにする
// （revision の取り違えを黙って評価しない）ことを確認する。
func TestConvertRejectsMismatchedSpan(t *testing.T) {
	row := Row{UID: "u1", Text: "山田", Spans: []Span{{Start: 0, End: 2, Text: "佐藤", Label: "last_name"}}}
	if _, err := Convert([]Row{row}, 1); err == nil {
		t.Fatal("食い違うスパンでエラーにならない")
	}
}

// TestReadParquetRoundTrip は、データセットと同じ列構成の parquet を読めることを確認する。
func TestReadParquetRoundTrip(t *testing.T) {
	rows := []Row{{UID: "u1", Domain: "医療", DocumentFormat: "unstructured", Text: "山田",
		Spans: []Span{{Start: 0, End: 2, Text: "山田", Label: "last_name"}}}}
	var buf bytes.Buffer
	if err := parquet.Write(&buf, rows); err != nil {
		t.Fatal(err)
	}
	got, err := ReadParquet(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, rows) {
		t.Fatalf("got %+v, want %+v", got, rows)
	}
}

// TestReadRealParquet は JP_PII_NEMOTRON_PARQUET に実データのパスがあるときだけ、
// 全行が変換できることを確認する。
func TestReadRealParquet(t *testing.T) {
	path := os.Getenv("JP_PII_NEMOTRON_PARQUET")
	if path == "" {
		t.Skip("JP_PII_NEMOTRON_PARQUET 未設定")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	rows, err := ReadParquet(f, st.Size())
	if err != nil {
		t.Fatal(err)
	}
	cases, err := Convert(rows, 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("rows=%d sampled=%d", len(rows), len(cases))
}
