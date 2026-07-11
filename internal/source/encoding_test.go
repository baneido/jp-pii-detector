package source

import (
	"encoding/binary"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/japanese"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/testfixtures"
)

// encodeLegacy は s を enc でエンコードする（テスト用ヘルパー。実ファイルを
// コミットせず実行時に生成する）。
func encodeLegacy(t *testing.T, enc encoding.Encoding, s string) []byte {
	t.Helper()
	b, err := enc.NewEncoder().Bytes([]byte(s))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

// utf16NoBOM は s を BOM の無い UTF-16（order で指定したバイト順）へ
// エンコードする（テスト用ヘルパー）。
func utf16NoBOM(s string, order binary.ByteOrder) []byte {
	units := utf16.Encode([]rune(s))
	buf := make([]byte, 2*len(units))
	for i, u := range units {
		order.PutUint16(buf[i*2:], u)
	}
	return buf
}

// ScanPaths がレガシーな日本語エンコーディング（Shift_JIS・EUC-JP・
// ISO-2022-JP）のファイルを透過的にデコードして検出できること
// （フル走査の end-to-end）。
func TestScanPathsDecodesLegacyJapaneseEncodings(t *testing.T) {
	phone := testfixtures.Phone(1, true)
	text := "電話番号: " + phone + "\n"

	tests := []struct {
		name string
		file string
		data []byte
	}{
		{"Shift_JIS", "sjis.txt", encodeLegacy(t, japanese.ShiftJIS, text)},
		{"EUC-JP", "eucjp.txt", encodeLegacy(t, japanese.EUCJP, text)},
		{"ISO-2022-JP", "iso2022jp.txt", encodeLegacy(t, japanese.ISO2022JP, text)},
	}

	tmp := t.TempDir()
	for _, tc := range tests {
		writeFile(t, filepath.Join(tmp, tc.file), tc.data)
	}

	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings, warnings, err := ScanPaths(d, cfg, []string{tmp})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if len(findings) != len(tests) {
		t.Fatalf("findings = %d 件 %+v, want %d", len(findings), findings, len(tests))
	}
	seen := map[string]bool{}
	for _, f := range findings {
		seen[filepath.Base(f.File)] = true
		if f.RuleID != "jp-phone-number" || f.Line != 1 {
			t.Errorf("finding = %+v, want jp-phone-number at line 1", f)
		}
	}
	for _, tc := range tests {
		if !seen[tc.file] {
			t.Errorf("%s (%s) からの検出が無い", tc.name, tc.file)
		}
	}
}

// ScanPaths が BOM 無し UTF-16（LE/BE）を検出できること（フル走査の
// end-to-end）。BOM 付き UTF-16 の TestScanPathsDecodesUTF16 と対になる。
func TestScanPathsDecodesUTF16NoBOM(t *testing.T) {
	tmp := t.TempDir()
	text := "口座番号: 1234567\n"
	writeFile(t, filepath.Join(tmp, "utf16le_nobom.txt"), utf16NoBOM(text, binary.LittleEndian))
	writeFile(t, filepath.Join(tmp, "utf16be_nobom.txt"), utf16NoBOM(text, binary.BigEndian))

	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings, warnings, err := ScanPaths(d, cfg, []string{tmp})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d 件 %+v, want 2", len(findings), findings)
	}
	for _, f := range findings {
		if f.RuleID != "jp-bank-account" || f.Line != 1 {
			t.Errorf("finding = %+v, want jp-bank-account at line 1", f)
		}
	}
}

// NUL を含むランダムなバイナリは、偶数/奇数オフセットへの偏りが無ければ
// BOM 無し UTF-16 と誤認されず、従来どおりバイナリとしてスキップされること。
func TestScanPathsRandomBinaryWithNULsStillSkipped(t *testing.T) {
	tmp := t.TempDir()
	// 0x00-0x3F を並べた決定的な「ランダム風」データ。NUL は 1 バイトのみ
	// 含み、偶数/奇数オフセットへの偏りが無いため BOM 無し UTF-16 の
	// しきい値（30%）を満たさない。
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i % 64)
	}
	writeFile(t, filepath.Join(tmp, "random.bin"), data)

	cfg := config.Default()
	d, err := detect.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	findings, warnings, err := ScanPaths(d, cfg, []string{tmp})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none（バイナリとしてスキップされるべき）", findings)
	}
}

// decodeLegacyJapanese の単体テスト（ISO-2022-JP らしさ判定、BOM 無し
// UTF-16 のエンディアン推定、Shift_JIS/EUC-JP の採否）。
func TestDecodeLegacyJapanese(t *testing.T) {
	phone := testfixtures.Phone(2, true)
	text := "電話番号: " + phone

	t.Run("Shift_JIS", func(t *testing.T) {
		data := encodeLegacy(t, japanese.ShiftJIS, text)
		got, ok := decodeLegacyJapanese(data)
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if got != text {
			t.Fatalf("got = %q, want %q", got, text)
		}
	})

	t.Run("EUC-JP", func(t *testing.T) {
		data := encodeLegacy(t, japanese.EUCJP, text)
		got, ok := decodeLegacyJapanese(data)
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if got != text {
			t.Fatalf("got = %q, want %q", got, text)
		}
	})

	t.Run("ISO-2022-JP", func(t *testing.T) {
		data := encodeLegacy(t, japanese.ISO2022JP, text)
		got, ok := decodeLegacyJapanese(data)
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if got != text {
			t.Fatalf("got = %q, want %q", got, text)
		}
	})

	// 正当な UTF-8（ASCII のみ、エスケープシーケンスも無い）は対象外。
	t.Run("正当なUTF-8はフォールバック", func(t *testing.T) {
		if _, ok := decodeLegacyJapanese([]byte("plain ascii text, no escapes")); ok {
			t.Fatal("ok = true, want false（既存の UTF-8 走査に委ねるべき）")
		}
	})

	// 不正な UTF-8 だが日本語文字を含まないゴミバイト列は、Shift_JIS/EUC-JP
	// いずれとしても誤認せずフォールバックすること。
	t.Run("日本語を含まないゴミバイト列はフォールバック", func(t *testing.T) {
		// 0xFF/0xFE は UTF-8 としても Shift_JIS の先行バイトとしても不正。
		garbage := []byte{0xFF, 0xFE, 0xFF, 0xFD, 0xFC, 0xFF, 0xFE, 0xFB, 0xFF, 0xFA}
		if _, ok := decodeLegacyJapanese(garbage); ok {
			t.Fatal("ok = true, want false（日本語文字が無いゴミバイト列を誤検出した）")
		}
	})

	// BOM 無し UTF-16（LE/BE）はエンディアンを推定してデコードできること。
	t.Run("BOM無しUTF16_LE", func(t *testing.T) {
		wide := "口座番号: 1234567"
		data := utf16NoBOM(wide, binary.LittleEndian)
		got, ok := decodeLegacyJapanese(data)
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if got != wide {
			t.Fatalf("got = %q, want %q", got, wide)
		}
	})

	t.Run("BOM無しUTF16_BE", func(t *testing.T) {
		wide := "口座番号: 1234567"
		data := utf16NoBOM(wide, binary.BigEndian)
		got, ok := decodeLegacyJapanese(data)
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if got != wide {
			t.Fatalf("got = %q, want %q", got, wide)
		}
	})
}
