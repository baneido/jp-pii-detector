package normalize

import (
	"testing"

	"github.com/baneido/jp-pii-detector/internal/piifixtures"
)

func TestLine(t *testing.T) {
	piifixtures.Require(t)
	tests := []struct {
		name, in, want string
	}{
		{"全角数字", "０１２３４５６７８９", "0123456789"},
		{"全角英字と記号", "ＡＢｃ＠：＝", "ABc@:="},
		{"全角スペース", piifixtures.MustGet(t, "normalize.name_fullwidth_in"), piifixtures.MustGet(t, "normalize.name_fullwidth_out")},
		{"全角ハイフン", piifixtures.MustGet(t, "normalize.fw_phone_in"), piifixtures.MustGet(t, "normalize.fw_phone_out")},
		{"ハイフン類似文字", piifixtures.MustGet(t, "normalize.hyphen_phone_in"), piifixtures.MustGet(t, "normalize.hyphen_phone_out")},
		{"長音記号が数字に隣接", piifixtures.MustGet(t, "normalize.lv_phone_in"), piifixtures.MustGet(t, "normalize.lv_phone_out")},
		{"カタカナ語の長音記号は保持", "サーバー", "サーバー"},
		{"郵便マークは保持", "〒150-0043", "〒150-0043"},
		{"ASCII はそのまま", "hello world 123", "hello world 123"},
		{"行頭の長音記号と数字", "ー123", "-123"},
		{"行末の数字と長音記号", "123ー", "123-"},
		{"数字に隣接しない長音記号は保持", "データー入力", "データー入力"},
		{"SMALL HYPHEN-MINUS", piifixtures.MustGet(t, "normalize.small_hyphen_phone_in"), piifixtures.MustGet(t, "normalize.small_hyphen_phone_out")},
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
	piifixtures.Require(t)
	in := piifixtures.MustGet(t, "normalize.postal_addr_in")
	if got, want := len([]rune(Line(in))), len([]rune(in)); got != want {
		t.Errorf("rune count changed: %d != %d", got, want)
	}
}

// 変換不要な行はアロケーションなしで同一文字列を返す（ファストパス）。
func TestLineASCIIFastPathReturnsSameString(t *testing.T) {
	piifixtures.Require(t)
	in := "hello world " + piifixtures.MustGet(t, "normalize.fw_phone_out")
	if got := Line(in); got != in {
		t.Errorf("Line(%q) = %q, want unchanged", in, got)
	}
	if testing.AllocsPerRun(10, func() { Line(in) }) != 0 {
		t.Error("ASCII fast path should not allocate")
	}
}

// 変換対象を含まない通常の日本語行もファストパスで割り当てなしに返す
// （漢字・かな・数字非隣接の長音記号だけの行）。フィクスチャ非依存。
func TestLineJapaneseNoConversionFastPath(t *testing.T) {
	for _, in := range []string{
		"これは普通の日本語の文章です。",
		"サーバーの設定を確認する", // 数字に隣接しない長音記号は保持
		"顧客の連絡先を控える",
	} {
		if got := Line(in); got != in {
			t.Errorf("Line(%q) = %q, want unchanged", in, got)
		}
		if testing.AllocsPerRun(10, func() { Line(in) }) != 0 {
			t.Errorf("変換不要な日本語行は割り当てなしで返すべき: %q", in)
		}
	}
}

func BenchmarkLineJapaneseNoConversion(b *testing.B) {
	line := "顧客の氏名と連絡先をサーバーで管理する設定について"
	b.ReportAllocs()
	for b.Loop() {
		Line(line)
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
	piifixtures.Require(b)
	line := "電話番号：" + piifixtures.MustGet(b, "normalize.fw_lv_phone_bench")
	b.ReportAllocs()
	for b.Loop() {
		Line(line)
	}
}
