package detect

import (
	"testing"

	"github.com/baneido/jp-pii-detecter/internal/config"
)

func benchDetector(b *testing.B) *Detector {
	b.Helper()
	d, err := New(config.Default())
	if err != nil {
		b.Fatal(err)
	}
	return d
}

// 典型的なソースコード行（マッチなし・純 ASCII）。フルスキャンの大半を占める。
func BenchmarkScanLineASCIINoMatch(b *testing.B) {
	d := benchDetector(b)
	line := `	if err := json.NewEncoder(w).Encode(resp); err != nil { return fmt.Errorf("encode: %w", err) }`
	b.ReportAllocs()
	for b.Loop() {
		d.ScanLine("f.go", 1, line)
	}
}

// 数字を含む ASCII 行（プリフィルタを通過して数字系ルールが走る）。
func BenchmarkScanLineASCIIDigitsNoMatch(b *testing.B) {
	d := benchDetector(b)
	line := `const maxRetries = 3; timeout := 250 * time.Millisecond // retry budget v1.2.3 build 4567`
	b.ReportAllocs()
	for b.Loop() {
		d.ScanLine("f.go", 1, line)
	}
}

// 日本語を含むがマッチしない行（正規化のスローパスを通る）。
func BenchmarkScanLineJapaneseNoMatch(b *testing.B) {
	d := benchDetector(b)
	line := "// サーバーへの接続がタイムアウトした場合はリトライする"
	b.ReportAllocs()
	for b.Loop() {
		d.ScanLine("f.go", 1, line)
	}
}

// 検出がヒットする行。
func BenchmarkScanLineHit(b *testing.B) {
	d := benchDetector(b)
	line := "電話番号：０９０－１２３４－５６７８"
	b.ReportAllocs()
	for b.Loop() {
		d.ScanLine("f.txt", 1, line)
	}
}
