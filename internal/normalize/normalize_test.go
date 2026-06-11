package normalize

import "testing"

func TestLine(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"全角数字", "０１２３４５６７８９", "0123456789"},
		{"全角英字と記号", "ＡＢｃ＠：＝", "ABc@:="},
		{"全角スペース", "山田　太郎", "山田 太郎"},
		{"全角ハイフン", "０９０－１２３４－５６７８", "090-1234-5678"},
		{"ハイフン類似文字", "03‐1234−5678", "03-1234-5678"},
		{"長音記号が数字に隣接", "090ー1234ー5678", "090-1234-5678"},
		{"カタカナ語の長音記号は保持", "サーバー", "サーバー"},
		{"郵便マークは保持", "〒150-0043", "〒150-0043"},
		{"ASCII はそのまま", "hello world 123", "hello world 123"},
		{"行頭の長音記号と数字", "ー123", "-123"},
		{"行末の数字と長音記号", "123ー", "123-"},
		{"数字に隣接しない長音記号は保持", "データー入力", "データー入力"},
		{"SMALL HYPHEN-MINUS", "03﹣1234﹣5678", "03-1234-5678"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Line(tt.in); got != tt.want {
				t.Errorf("Line(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestLineKeepsRuneCount(t *testing.T) {
	in := "〒１５０ー００４３　東京都渋谷区"
	if got, want := len([]rune(Line(in))), len([]rune(in)); got != want {
		t.Errorf("rune count changed: %d != %d", got, want)
	}
}

// 変換不要な行はアロケーションなしで同一文字列を返す（ファストパス）。
func TestLineASCIIFastPathReturnsSameString(t *testing.T) {
	in := "hello world 090-1234-5678"
	if got := Line(in); got != in {
		t.Errorf("Line(%q) = %q, want unchanged", in, got)
	}
	if testing.AllocsPerRun(10, func() { Line(in) }) != 0 {
		t.Error("ASCII fast path should not allocate")
	}
}

func BenchmarkLineASCII(b *testing.B) {
	line := `	if err := json.NewEncoder(w).Encode(resp); err != nil { return err }`
	b.ReportAllocs()
	for b.Loop() {
		Line(line)
	}
}

func BenchmarkLineJapanese(b *testing.B) {
	line := "電話番号：０９０ー１２３４ー５６７８（自宅）"
	b.ReportAllocs()
	for b.Loop() {
		Line(line)
	}
}
