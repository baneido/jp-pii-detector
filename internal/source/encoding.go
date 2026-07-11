package source

// このファイルは、テキストとして読めない（＝素朴な isBinary/UTF-8 判定では
// 化けるかスキップされる）ファイルを、BOM 付き UTF-16 に加えて、日本語圏で
// 実際に使われるレガシーエンコーディング（BOM 無し UTF-16、ISO-2022-JP、
// Shift_JIS、EUC-JP）についても透過的に UTF-8 相当の Go 文字列へデコードする。
//
// いずれの判定も decodeUTF16（BOM 付き UTF-16）と同じ設計方針を踏襲する。
// 判定に少しでも疑いがあれば ok=false を返し、呼び出し側の既存判定
// （isBinary によるスキップ、または生バイトのままの走査）へフォールバック
// する。既に UTF-8 として正しく走査できているファイルの挙動を変えないことを
// 最優先する。

import (
	"encoding/binary"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/japanese"
)

// decodeUTF16 は UTF-16 の BOM（FF FE = リトルエンディアン、FE FF =
// ビッグエンディアン）を検出したときだけ UTF-8 へデコードする。BOM が無い
// 場合は ok=false を返し、呼び出し側は従来どおり isBinary 判定へ委ねる
// （UTF-16 は半角文字が 1 バイト置きに NUL を挟むため、BOM チェックより先に
// isBinary を通すと確実にバイナリ扱いされ完全に検出漏れになる。この関数を
// isBinary より前に呼ぶことでそれを避ける）。
//
// 奇数バイト長（BOM を除いた本体が 2 バイト単位にならない）や不正な
// サロゲートペアは ok=false を返し、呼び出し側は従来どおりのバイナリ判定
// （isBinary）にフォールバックする。
//
// 注意（呼び出し側・ドキュメントで明記が必要な既知の制約）:
//   - デコード後の Finding の行・列はルーン単位で正しいが、デコード後の
//     文字列上の位置であり、元ファイルの UTF-16 バイトオフセットとは
//     対応しない。
//   - git diff は UTF-16 ファイルをバイナリ扱いするため、この関数は
//     フルスキャン（ScanPaths）経由でのみ効き、--staged/--diff の
//     差分走査では UTF-16 ファイルはそもそも対象にならない。
func decodeUTF16(data []byte) (string, bool) {
	var order binary.ByteOrder
	switch {
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE:
		order = binary.LittleEndian
	case len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF:
		order = binary.BigEndian
	default:
		return "", false
	}
	return decodeUTF16Body(data[2:], order)
}

// decodeUTF16Body は order で指定したバイト順の UTF-16 本体（BOM を除いた
// 部分、または BOM 無し UTF-16 の全体）をデコードする。decodeUTF16 と
// decodeUTF16NoBOM で共有する。
func decodeUTF16Body(body []byte, order binary.ByteOrder) (string, bool) {
	if len(body)%2 != 0 {
		return "", false
	}
	units := make([]uint16, len(body)/2)
	for i := range units {
		units[i] = order.Uint16(body[i*2:])
	}
	if !validUTF16Surrogates(units) {
		return "", false
	}
	return string(utf16.Decode(units)), true
}

// validUTF16Surrogates は units が正しいサロゲートペアの並びかを検証する。
// utf16.Decode は不正なサロゲートを黙って置換文字（U+FFFD）に変換するため、
// 事前にここで検証し、不正な入力はデコード失敗としてバイナリ判定へ
// フォールバックさせる（置換文字での化けを防ぐ）。
func validUTF16Surrogates(units []uint16) bool {
	for i := 0; i < len(units); i++ {
		u := units[i]
		switch {
		case u >= 0xD800 && u <= 0xDBFF: // 上位サロゲート
			if i+1 >= len(units) {
				return false
			}
			next := units[i+1]
			if next < 0xDC00 || next > 0xDFFF {
				return false
			}
			i++ // ペアを消費
		case u >= 0xDC00 && u <= 0xDFFF: // 対応する上位サロゲートの無い下位サロゲート
			return false
		}
	}
	return true
}

// decodeLegacyJapanese は、UTF-8 でも BOM 付き UTF-16 でもないデータについて
// レガシーな日本語エンコーディングへの該当を推定し、デコードを試みる。
// 判定順は (a) ISO-2022-JP → (b) BOM 無し UTF-16 → (c) Shift_JIS/EUC-JP。
//
// 高速パス（要件）: 大多数を占める正当な UTF-8 ファイルに、(c) の
// デコード試行コストを一切払わせない。(a) は 7-bit データの 1 パス走査のみ
// （ESC の有無を見るだけ）で軽量なため常に行い、(b) は isBinary（NUL 含有）
// の場合だけ、(c) は !utf8.Valid の場合だけ試みる。
//
// 注意（decodeUTF16 と同様の既知の制約）:
//   - デコード後の Finding の行・列はデコード後の文字列上の位置であり、
//     元ファイルのバイトオフセット（Shift_JIS 等はマルチバイト文字が
//     混在するため UTF-16 以上に対応が取れない）とは対応しない。
//   - git diff はこれらのエンコーディングのファイルもバイナリ扱いするため、
//     この関数はフルスキャン（ScanPaths）経由でのみ効く。
func decodeLegacyJapanese(data []byte) (string, bool) {
	// (a) ISO-2022-JP.
	if text, ok := decodeISO2022JP(data); ok {
		return text, true
	}

	if isBinary(data) {
		// (b) NUL を含み従来ならバイナリ扱いされるデータは、BOM 無し
		// UTF-16 の可能性を疑う。
		return decodeUTF16NoBOM(data)
	}

	// (c) 正当な UTF-8 は Shift_JIS/EUC-JP のデコード試行が不要（高速パス）。
	if utf8.Valid(data) {
		return "", false
	}
	return decodeShiftJISOrEUCJP(data)
}

// decodeISO2022JP は ISO-2022-JP のエスケープシーケンス
// （ESC $ B・ESC $ @・ESC ( B・ESC ( J・ESC ( I）の有無で ISO-2022-JP
// らしさを判定し、該当する場合だけ golang.org/x/text/encoding/japanese で
// デコードする。
func decodeISO2022JP(data []byte) (string, bool) {
	if !looksLikeISO2022JP(data) {
		return "", false
	}
	// エスケープシーケンスの存在自体が強いシグナルのため、Shift_JIS/EUC-JP
	// と異なり日本語文字の含有は要求しない（本文が半角英数字のみの
	// ISO-2022-JP メールヘッダ等も正しくデコードできるようにする）。
	return decodeAndValidate(japanese.ISO2022JP, data, false)
}

// looksLikeISO2022JP は data が 7-bit（0x80 未満）のみで構成され、かつ
// ISO-2022-JP のエスケープシーケンス（ESC の直後に '$' または '('）を
// 少なくとも 1 つ含むかを返す。ISO-2022-JP は 7-bit クリーンな符号化のため、
// 8-bit バイトが 1 つでもあれば対象外とする。
func looksLikeISO2022JP(data []byte) bool {
	hasEscape := false
	for i, b := range data {
		if b >= 0x80 {
			return false
		}
		if b == 0x1B && i+1 < len(data) {
			switch data[i+1] {
			case '$', '(':
				hasEscape = true
			}
		}
	}
	return hasEscape
}

// nulRatioThreshold は decodeUTF16NoBOM で BOM 無し UTF-16 と推定する
// NUL バイト比率のしきい値。bomlessSampleWindow は isBinary と同じ先頭 8KB
// の窓でサンプリングする。
const (
	nulRatioThreshold   = 0.3
	bomlessSampleWindow = 8192
)

// decodeUTF16NoBOM は BOM の無い UTF-16 を、NUL バイトの偏りから推定して
// デコードする。半角英数字主体の UTF-16 テキストは、リトルエンディアンなら
// 2 バイト単位の奇数オフセット（上位バイトが後ろ＝0）に、ビッグエンディアン
// なら偶数オフセット（上位バイトが前＝0）に NUL が集中する。先頭 8KB
// （isBinary と同じ窓）でその偏りが nulRatioThreshold を超えたときだけ
// エンディアンを推定し、それ以外は ok=false でバイナリ判定に委ねる。
// サロゲート不正など decodeUTF16Body 側の検証に失敗した場合も同様。
func decodeUTF16NoBOM(data []byte) (string, bool) {
	if len(data) < 8 || len(data)%2 != 0 {
		return "", false
	}
	n := min(len(data), bomlessSampleWindow)
	n -= n % 2
	pairs := n / 2
	if pairs == 0 {
		return "", false
	}
	var evenNul, oddNul int
	for i := 0; i < n; i += 2 {
		if data[i] == 0 {
			evenNul++
		}
		if data[i+1] == 0 {
			oddNul++
		}
	}
	var order binary.ByteOrder
	switch {
	// 偶数オフセット（上位バイト）に NUL が偏る＝ビッグエンディアン。
	case float64(evenNul) > float64(pairs)*nulRatioThreshold && evenNul > oddNul:
		order = binary.BigEndian
	// 奇数オフセット（下位バイト）に NUL が偏る＝リトルエンディアン。
	case float64(oddNul) > float64(pairs)*nulRatioThreshold && oddNul > evenNul:
		order = binary.LittleEndian
	default:
		return "", false
	}
	return decodeUTF16Body(data, order)
}

// decodeShiftJISOrEUCJP は data が UTF-8 として不正なときにだけ呼ばれる
// （decodeLegacyJapanese 参照）。Shift_JIS・EUC-JP の両方でデコードを試み、
// 採用条件を満たした候補だけを比較する。両方採用できた場合は日本語らしい
// 文字数が多い方を、同数ならレガシー Windows 環境で広く使われる Shift_JIS
// を優先する。
func decodeShiftJISOrEUCJP(data []byte) (string, bool) {
	sjisText, sjisOK := tryLegacyDecode(japanese.ShiftJIS, data)
	eucText, eucOK := tryLegacyDecode(japanese.EUCJP, data)
	switch {
	case sjisOK && eucOK:
		if countJapaneseRunes(eucText) > countJapaneseRunes(sjisText) {
			return eucText, true
		}
		return sjisText, true
	case sjisOK:
		return sjisText, true
	case eucOK:
		return eucText, true
	default:
		return "", false
	}
}

// tryLegacyDecode は enc でのデコードが、エラーが無く置換文字（U+FFFD）も
// 含まず、かつ日本語の文字（ひらがな・カタカナ・漢字）を1文字以上含む場合
// にだけ成功として結果を返す。任意のバイナリを Shift_JIS/EUC-JP と誤認する
// のを避けるための条件。
func tryLegacyDecode(enc encoding.Encoding, data []byte) (string, bool) {
	return decodeAndValidate(enc, data, true)
}

// decodeAndValidate は enc.NewDecoder() でデコードし、エラーや置換文字
// （U+FFFD）が無いことを確認する。requireJapanese が true のときは、
// さらに日本語の文字（ひらがな・カタカナ・漢字）を1文字以上含むことも
// 要求する。
func decodeAndValidate(enc encoding.Encoding, data []byte, requireJapanese bool) (string, bool) {
	decoded, err := enc.NewDecoder().Bytes(data)
	if err != nil {
		return "", false
	}
	text := string(decoded)
	if strings.ContainsRune(text, utf8.RuneError) {
		return "", false
	}
	if requireJapanese && countJapaneseRunes(text) == 0 {
		return "", false
	}
	return text, true
}

// countJapaneseRunes は s に含まれるひらがな・カタカナ・漢字の文字数を返す。
func countJapaneseRunes(s string) int {
	n := 0
	for _, r := range s {
		if isJapaneseRune(r) {
			n++
		}
	}
	return n
}

// isJapaneseRune は r がひらがな・カタカナ・漢字（CJK 統合漢字を含む）かを
// 返す。
func isJapaneseRune(r rune) bool {
	return unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r) || unicode.Is(unicode.Han, r)
}
