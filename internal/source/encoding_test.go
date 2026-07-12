package source

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
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

// jsonEscapeAll は s の非 ASCII 文字をすべて \uXXXX（BMP 外は UTF-16
// サロゲートペアの 2 個組）でエスケープする。Python の
// json.dumps(..., ensure_ascii=True) が出力するエスケープ形式をテストで
// 再現するためのヘルパー（テスト専用。本体コードでは使わない）。
func jsonEscapeAll(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x80 {
			b.WriteRune(r)
			continue
		}
		if r > 0xFFFF {
			r1, r2 := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04x\u%04x`, r1, r2)
			continue
		}
		fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}

// decodeJSONUnicodeEscapes の単体テスト。復号規則を 1 つずつ確認する。
// 入力はテスト対象そのものである \uXXXX エスケープ表記（バックティック
// 文字列リテラルなので Go コンパイラによる解釈は受けず、そのままのバイト列
// が渡る）。復号先のサンプル値は検出対象にならない一般語（あ・@・絵文字等）
// のみを使い、dogfooding（jp-pii-detect scan .）に本ファイルが引っかから
// ないようにする。
func TestDecodeJSONUnicodeEscapes(t *testing.T) {
	t.Run("基本", func(t *testing.T) {
		got, ok := decodeJSONUnicodeEscapes("\\u3042")
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if got != "あ" {
			t.Fatalf("got = %q, want %q", got, "あ")
		}
	})

	t.Run("バックスラッシュ偶奇", func(t *testing.T) {
		// 2 連続バックスラッシュ + u0040 は、手前のバックスラッシュと
		// ペアになるリテラルの \ の続きであり、JSON のエスケープ規則上
		// そこから \u エスケープは始まらないため復号しない。
		if got, ok := decodeJSONUnicodeEscapes(`\\u0040`); ok {
			t.Fatalf("ok = true, got = %q, want false（2連続バックスラッシュは非復号のはず）", got)
		}
		// バックスラッシュ 1 個 + u0040 は復号する（0x40 は '@'）。
		got, ok := decodeJSONUnicodeEscapes("\\u0040")
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if got != "@" {
			t.Fatalf("got = %q, want %q", got, "@")
		}
	})

	t.Run("サロゲートペア合成", func(t *testing.T) {
		got, ok := decodeJSONUnicodeEscapes("\\uD83D\\uDE00")
		if !ok {
			t.Fatal("ok = false, want true")
		}
		want := string(rune(0x1F600)) // U+1F600（BMP 外、サロゲートペア必須）
		if got != want {
			t.Fatalf("got = %q, want %q", got, want)
		}
	})

	t.Run("孤立サロゲート非復号", func(t *testing.T) {
		// 対応する低位サロゲートが続かない孤立した上位サロゲート \uD83D は
		// 復号せずリテラルのまま残す。直後に無関係な あ を置き、
		// そちらは独立に復号されることで全体としては ok=true になることも
		// 合わせて確認する（1 箇所でも復号できれば復号後テキストを使う、
		// という規則の確認）。
		got, ok := decodeJSONUnicodeEscapes("\\uD83D\\u3042")
		if !ok {
			t.Fatal("ok = false, want true（後続の \\u3042 は復号されるはず）")
		}
		want := "\\uD83D" + "あ"
		if got != want {
			t.Fatalf("got = %q, want %q（孤立サロゲートはリテラルのまま残るはず）", got, want)
		}
	})

	t.Run("制御文字非復号", func(t *testing.T) {
		// 復号結果が U+0020 未満の制御文字（U+000A は改行文字）になる
		// エスケープは、行構造を壊さず行番号を原文と厳密に一致させるため
		// 復号しない。直後の あ は独立に復号される。
		got, ok := decodeJSONUnicodeEscapes("\\u000A\\u3042")
		if !ok {
			t.Fatal("ok = false, want true（後続の \\u3042 は復号されるはず）")
		}
		want := "\\u000A" + "あ"
		if got != want {
			t.Fatalf("got = %q, want %q（制御文字はリテラルのまま残るはず）", got, want)
		}
	})

	t.Run("不正hex非復号", func(t *testing.T) {
		// "g" は 16 進数として不正なため \u12g4 はエスケープとして復号しない。
		got, ok := decodeJSONUnicodeEscapes("\\u12g4\\u3042")
		if !ok {
			t.Fatal("ok = false, want true（後続の \\u3042 は復号されるはず）")
		}
		want := `\u12g4` + "あ"
		if got != want {
			t.Fatalf("got = %q, want %q（不正なエスケープはリテラルのまま残るはず）", got, want)
		}
	})

	t.Run("uなしは早期リターンし追加確保なし", func(t *testing.T) {
		text := "plain ascii text without any escapes at all, here to give the fast path something to scan."
		if _, ok := decodeJSONUnicodeEscapes(text); ok {
			t.Fatal("ok = true, want false（バックスラッシュ u を含まないので復号対象なしのはず）")
		}
		allocs := testing.AllocsPerRun(100, func() {
			decodeJSONUnicodeEscapes(text)
		})
		if allocs != 0 {
			t.Fatalf("allocs/op = %v, want 0（早期リターンで確保が発生しないこと）", allocs)
		}
	})
}

// ScanPaths が JSON の \uXXXX エスケープ（json.dumps(ensure_ascii=True) 等の
// 出力・.ipynb・各種ログに頻出）に隠れた日本語 PII を復号して検出できること
// （フル走査の end-to-end）。氏名（person-name）・住所（jp-address）の
// 双方が検出され、行番号が原文（1 行の JSON）と一致することを確認する。
func TestScanPathsDecodesJSONUnicodeEscapes(t *testing.T) {
	name := testfixtures.MustGet(t, "detect.name_sato_hanako")
	addr := testfixtures.MustGet(t, "detect.address_shibuya")
	// json.dumps({"customer_name": name, "addr": addr}, ensure_ascii=True) 相当
	// （インデント無しの 1 行出力）を手組みする。
	content := `{"customer_name": "` + jsonEscapeAll(name) + `", "addr": "` + jsonEscapeAll(addr) + `"}` + "\n"

	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "escaped.json"), []byte(content))

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

	var hasName, hasAddress bool
	for _, f := range findings {
		if f.Line != 1 {
			t.Errorf("finding = %+v, want line 1（原文どおり 1 行の JSON のため）", f)
		}
		switch f.RuleID {
		case "person-name":
			hasName = true
		case "jp-address":
			hasAddress = true
		}
	}
	if !hasName {
		t.Errorf("findings = %+v, want person-name の検出を含む", findings)
	}
	if !hasAddress {
		t.Errorf("findings = %+v, want jp-address の検出を含む", findings)
	}
}
