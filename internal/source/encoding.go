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

// ---- エスケープ表記の復号ビュー ----
//
// json.dumps(ensure_ascii=True) の出力・.ipynb・各種ログでは、日本語を含む
// 文字列が "山田..." のように JSON の \uXXXX エスケープで ASCII 化
// される。同様に、URL クエリパラメータやアクセスログでは %XX%XX%XX...
// のようなパーセントエンコードが、HTML/XML を経由したデータでは
// &#十進数; / &#x十六進数; のような数値文字参照が、同じ非 ASCII 文字を
// 別方式で ASCII 化する。電話番号のような ASCII の値は既存ルールでそのまま
// 検出できるが、氏名・住所など非 ASCII の値はこれらのエスケープ表記の中に
// 隠れて正規表現から完全にすり抜ける。これは decodeUTF16/decodeLegacyJapanese
// が対象とするバイト列レベルの文字コードとは別種の問題（既に正当な UTF-8 の
// テキストの中の ASCII エスケープ表記）のため、それらの後段・最終的な
// UTF-8 テキストに対して独立に適用する。
//
// JSON \uXXXX・HTML 数値文字参照・URL パーセントエンコードの 3 種類は
// それぞれ独立した節で実装し、decodeEscapedViews がこの順に直列適用する
// （適用順の理由は decodeEscapedViews の doc コメントを参照）。いずれも
// decodeUTF16 と同じ「疑わしければ復号しない」設計方針を踏襲する。

// DecodeEscapedView は decodeEscapedViews（JSON \uXXXX エスケープ → HTML
// 数値文字参照 → URL パーセントエンコードの直列デコードチェーン）の薄い
// エクスポートラッパ。
//
// 用途: scan --stdin 経路（外部連携用、cmd/jp-pii-detect/main.go）から呼ぶ
// ためにエクスポートしている。フルスキャン（scanFiles）は同一パッケージ内
// なので decodeEscapedViews を直接呼ぶが、cmd パッケージから package 外の
// 非公開関数は呼べない。stdin はまさに JSON をそのままパイプで流し込む
// 用途（json.dumps(ensure_ascii=True) の出力や CI/エージェント連携）や、
// URL・HTML を経由したログの貼り付けが多く、これらのエスケープ表記に
// 隠れた氏名・住所等の PII を検出できる価値が高いため、フルスキャン専用
// だったこの復号ビューを stdin 経路にも広げる。
//
// 位置セマンティクス: decodeJSONUnicodeEscapes の doc comment を参照
// （decodeHTMLNumericEntities・decodePercentEncoding も同じ性質を持つ）。
// ok == true の場合、呼び出し側は以後の走査・オフセット計算（例:
// detect.ScanContent と detect.ComputeOffsets）を必ず戻り値の text（復号後
// テキスト）に対して行うこと。行番号は元テキストと一致するが、エスケープを
// 含む行の列・オフセットは復号後テキスト上の位置になり、元テキスト（stdin
// の生バイト列）上の位置とは対応しない。ok == false の場合は 1 箇所も
// 復号できなかったことを意味し、呼び出し側は元の text をそのまま使ってよい
// （decodeUTF16 と同じ「置き換え」方式で、変更なしを表す）。
//
// 復号を無効にする opt-out フラグは現時点では設けない（フルスキャン側にも
// 無く、両経路の対称性を保つため）。将来的に必要になれば、呼び出し側で
// フラグを追加し本関数の呼び出し自体を条件分岐でスキップさせる形で拡張
// できる。
func DecodeEscapedView(text string) (string, bool) {
	return decodeEscapedViews(text)
}

// decodeEscapedViews は decodeJSONUnicodeEscapes → decodeHTMLNumericEntities
// → decodePercentEncoding の順に、前段の出力を次段の入力として直列に適用
// する。フルスキャン（internal/source の scanFiles）と DecodeEscapedView
// （scan --stdin 経由、cmd/jp-pii-detect/main.go）の両方が本関数を通ることで、
// 2 つの呼び出し経路が常に同じ復号チェーンを持つことを保証する（どちらか
// 一方だけを更新して連鎖がずれる事故を防ぐ）。
//
// 段の順序には理由がある。JSON エスケープの中には、HTML 数値文字参照や
// パーセントエンコードを構成する文字（&・#・;・% はいずれも ASCII なので
// \uXXXX で表現しうる）がさらに隠れているケースがある。\uXXXX を最初に
// 展開しておくことで、そこで新たに現れた数値文字参照やパーセントエンコード
// を後段の HTML・パーセント段が発見できる。逆順では JSON エスケープの中に
// 隠れたそれらはそもそも文字列内に現れず、後段で見つけられない。同様の
// 理由で HTML 数値文字参照はパーセントエンコードより先に展開する（% 自体を
// 数値文字参照で表現した上でパーセントエンコードを組む、という二重の
// 難読化を想定する）。
//
// 各段は独立に「疑わしければ復号しない」判断をするため、ある段が 1 箇所も
// 復号できなくても後続の段は（その段にとっての）元のテキストに対してそのまま
// 試みる。1 段でも復号が成立すれば ok=true を返す（呼び出し側の契約は
// decodeJSONUnicodeEscapes 単体と同じ）。3 段とも復号箇所が無ければ ok=false
// を返し、呼び出し側は元のテキストをそのまま使う。
//
// 注意: 各段は 1 パスずつしか適用されない。後段が新たに生み出した \uXXXX ・
// 数値文字参照・パーセントエンコードを、さらに前段へ戻して再帰的に展開する
// ことはしない（多段ネストの徹底的な展開より、無限ループ回避と実装の単純さ
// を優先する割り切り）。
func decodeEscapedViews(text string) (string, bool) {
	decoded := false
	if unescaped, ok := decodeJSONUnicodeEscapes(text); ok {
		text = unescaped
		decoded = true
	}
	if unescaped, ok := decodeHTMLNumericEntities(text); ok {
		text = unescaped
		decoded = true
	}
	if unescaped, ok := decodePercentEncoding(text); ok {
		text = unescaped
		decoded = true
	}
	if !decoded {
		return "", false
	}
	return text, true
}

// decodeJSONUnicodeEscapes は text（正当な UTF-8 のテキストであることを
// 呼び出し側は問わないが、本関数内で確認する）に含まれる JSON の \uXXXX
// エスケープ（u は小文字、XXXX は 16 進数 4 桁）を実際の文字へ復号した
// ビューを返す。decodeUTF16 と同じ「疑わしければ復号しない」保守的な
// 方針に従う:
//
//   - 直前の連続バックスラッシュ数（このバックスラッシュ自身は含まない）が
//     偶数の \uXXXX だけを復号する。奇数（\\u0040 の 2 文字目の \ 等）は
//     手前のバックスラッシュとペアになるリテラルの \ であり、JSON の
//     エスケープ規則上そこから \u エスケープは始まらないため復号しない。
//   - 上位サロゲート（\uD800〜\uDBFF）は直後に低位サロゲート
//     （\uDC00〜\uDFFF）が続く場合だけ 1 文字へ合成する。ペアが揃わない
//     孤立サロゲートは復号せずリテラルのまま残す。
//   - 復号結果が U+0020 未満の制御文字（\n・\r・\t 等）になるエスケープは
//     復号せずリテラルのまま残す。
//   - 16 進数 4 桁が揃わない・非 16 進文字を含むなど構文として不正な
//     エスケープは、そのままリテラルとして残す。
//
// 位置セマンティクス（呼び出し側が前提としてよいこと）: 復号は改行文字
// （U+000A/U+000D 等、いずれも U+0020 未満）を新たに生み出さないため、
// 復号後テキストの行数・各行番号は元テキストと厳密に一致する
// （ScanContent は "\n" で行分割する）。一方、列（Column）は \uXXXX
// （6 ルーン）が復号後は 1〜2 ルーンに縮むため、エスケープを含む行では
// 復号後の文字列上の位置になり、元ファイルのバイト/ルーン位置とは
// 対応しない（decodeUTF16 の「デコード後の位置は元ファイルのオフセットに
// 対応しない」という既知の割り切りと同じ性質）。
//
// 1 箇所も復号できなければ ok=false を返し、呼び出し側は元のテキストを
// そのまま使う（decodeUTF16 と同じ「置き換え」方式）。各エスケープは
// 互いに独立に判定・復号され、復号対象にならない部分はバイト単位で一切
// 変更しないため、元テキストで（電話番号のように）ASCII のまま見えていた
// PII は復号後も変わらず見える。つまりこの層を追加しても既存の検出が
// 失われることはない。
//
// 適用条件・パフォーマンス: フルスキャン（scanFiles）・scan --stdin
// （cmd/jp-pii-detect/main.go）のいずれも decodeEscapedViews 経由で本関数を
// 呼ぶ（git diff はこれらのエスケープも普通の ASCII テキストとして扱う
// ため、既存のバイト列レベルのエンコーディング層と異なり技術的には diff
// 走査でも動作しうるが、位置セマンティクスの割り切りを diff 走査に持ち込ま
// ない設計とするため、呼び出しをフルスキャンと --stdin に限定する）。
// 大多数を占める \u を含まないファイルは、strings.Contains によるバイト
// 走査 1 回で早期リターンする（既存の valid UTF-8 fast path と同じ思想）。
func decodeJSONUnicodeEscapes(text string) (string, bool) {
	// 高速パス: \u（バックスラッシュ + 小文字 u）を含まないテキストは
	// 1 回のバイト走査で早期リターンする。
	if !strings.Contains(text, `\u`) {
		return "", false
	}
	// 疑わしければ復号しない: 正当な UTF-8 のテキストにのみ適用する
	// （decodeUTF16/decodeLegacyJapanese の出力は常に正当な UTF-8 だが、
	// バイナリ判定を通過しただけの生テキストはそうとは限らない）。
	if !utf8.ValidString(text) {
		return "", false
	}

	var b strings.Builder
	b.Grow(len(text))
	decoded := false
	backslashRun := 0 // 現在位置の直前まで連続するバックスラッシュの数
	for i := 0; i < len(text); {
		c := text[i]
		if c == '\\' && backslashRun%2 == 0 {
			if r, width, ok := decodeOneJSONEscape(text, i); ok {
				b.WriteRune(r)
				i += width
				decoded = true
				backslashRun = 0
				continue
			}
		}
		b.WriteByte(c)
		if c == '\\' {
			backslashRun++
		} else {
			backslashRun = 0
		}
		i++
	}
	if !decoded {
		return "", false
	}
	return b.String(), true
}

// decodeOneJSONEscape は text[i] を先頭とする \uXXXX（上位サロゲートの
// 場合は直後の低位サロゲート \uXXXX まで）を解釈する。呼び出し側は
// text[i] == '\\' であることと、この \ 自身の直前の連続バックスラッシュ数が
// 偶数（＝この \ がエスケープを開始しうる）であることを確認済みとする。
//
// 復号しない（ok=false）と判断するケースは decodeJSONUnicodeEscapes の
// doc コメントに記載の方針のとおり: 16 進数 4 桁が揃わない不正なエスケープ、
// 対応が揃わない孤立サロゲート、U+0020 未満の制御文字。
//
// 戻り値の width は消費した text のバイト数（単独エスケープなら 6、
// サロゲートペアなら 12）。
func decodeOneJSONEscape(text string, i int) (rune, int, bool) {
	high, ok := parseHex4Escape(text, i)
	if !ok {
		return 0, 0, false
	}
	switch {
	case high >= 0xD800 && high <= 0xDBFF: // 上位サロゲート
		low, ok := parseHex4Escape(text, i+6)
		if !ok || low < 0xDC00 || low > 0xDFFF {
			return 0, 0, false // 対応する低位サロゲートが無い孤立サロゲート
		}
		return utf16.DecodeRune(rune(high), rune(low)), 12, true
	case high >= 0xDC00 && high <= 0xDFFF: // 対応する上位サロゲートの無い孤立した低位サロゲート
		return 0, 0, false
	case high < 0x20: // 制御文字（行構造を壊さないため復号しない）
		return 0, 0, false
	default:
		return rune(high), 6, true
	}
}

// parseHex4Escape は text[i:i+6] が "\u" ＋ 16 進数 4 桁（大文字・小文字
// どちらも可）であることを確認し、コードユニット（0〜0xFFFF）を返す。
// u は小文字固定（JSON の \u エスケープに合わせる。大文字 \U は対象外）。
// 桁数不足や範囲外の文字があれば ok=false。
func parseHex4Escape(text string, i int) (uint16, bool) {
	if i+6 > len(text) || text[i] != '\\' || text[i+1] != 'u' {
		return 0, false
	}
	var v uint16
	for k := 0; k < 4; k++ {
		d, ok := hexDigitValue(text[i+2+k])
		if !ok {
			return 0, false
		}
		v = v<<4 | uint16(d)
	}
	return v, true
}

// hexDigitValue は 1 文字の 16 進数（大文字・小文字どちらも可）を 0〜15 の
// 値へ変換する。16 進数でなければ ok=false。
func hexDigitValue(c byte) (uint16, bool) {
	switch {
	case c >= '0' && c <= '9':
		return uint16(c - '0'), true
	case c >= 'a' && c <= 'f':
		return uint16(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return uint16(c-'A') + 10, true
	default:
		return 0, false
	}
}

// ---- HTML 数値文字参照の復号ビュー ----
//
// decodeJSONUnicodeEscapes と同じ「既に正当な UTF-8 のテキストの中の ASCII
// エスケープ表記」を対象にする独立した復号ビュー。decodeEscapedViews から
// decodeJSONUnicodeEscapes の後段として呼ばれる（適用順の理由は
// decodeEscapedViews の doc コメントを参照）。

// htmlEntityMaxDecimalDigits と htmlEntityMaxHexDigits は
// decodeOneHTMLNumericEntity が受理する最長の桁数。Unicode の最大コード
// ポイント U+10FFFF を表すのに十分な桁数（10 進 1114111 は 7 桁、16 進
// 10FFFF は 6 桁）に合わせてあり、これを超えて数字が続く参照は誤爆リスクの
// 高い長大な数字列とみなして対象外にする。
const (
	htmlEntityMaxDecimalDigits = 7
	htmlEntityMaxHexDigits     = 6
)

// decodeHTMLNumericEntities は text に含まれる HTML の数値文字参照
// （&#十進数; ・ &#x十六進数; 、x は大文字小文字どちらも可）を実際の文字へ
// 復号したビューを返す。
//
// 名前実体（&amp; ・ &nbsp; 等）は対象外とする。名前実体は HTML5 仕様上
// 数百種類あり、網羅すれば辞書の保守コストが高いうえ、セミコロン省略を
// 許すレガシー仕様もあって構文もあいまいなため、通常の英単語（&amp のような
// 途中経過等）を誤って実体の一部と誤認するリスクが数値文字参照より高い。
// 数値文字参照は構文が厳密（&# の直後が数字、セミコロン終端必須）で
// コードポイントを直接表すため、誤爆リスクが低く実装も単純である。この
// 費用対効果の差から数値文字参照だけを対象にする。
//
// decodeJSONUnicodeEscapes と同じ「疑わしければ復号しない」方針
// （decodeOneHTMLNumericEntity の doc コメント参照）に従う。
//
// 位置セマンティクス: 復号は U+0020 未満の文字（改行を含む）を新たに
// 生み出さないため、復号後テキストの行数・各行番号は元テキストと厳密に
// 一致する。列（Column）は参照を含む行でのみ復号後の文字列上の位置になる
// （decodeJSONUnicodeEscapes と同じ性質）。
//
// 1 箇所も復号できなければ ok=false を返し、呼び出し側は元のテキストを
// そのまま使う。大多数を占める "&#" を含まないテキストは、strings.Contains
// によるバイト走査 1 回で早期リターンする。
func decodeHTMLNumericEntities(text string) (string, bool) {
	if !strings.Contains(text, "&#") {
		return "", false
	}

	var b strings.Builder
	b.Grow(len(text))
	decoded := false
	for i := 0; i < len(text); {
		if text[i] == '&' {
			if r, width, ok := decodeOneHTMLNumericEntity(text, i); ok {
				b.WriteRune(r)
				i += width
				decoded = true
				continue
			}
		}
		b.WriteByte(text[i])
		i++
	}
	if !decoded {
		return "", false
	}
	return b.String(), true
}

// decodeOneHTMLNumericEntity は text[i] を先頭とする &#十進数; または
// &#x十六進数;（x は大文字小文字どちらも可）を解釈する。呼び出し側は
// text[i] == '&' であることを確認済みとする。名前実体（&amp; 等）は対象外
// （decodeHTMLNumericEntities の doc コメント参照）。
//
// 復号しない（ok=false）と判断するケース:
//   - "&#" の直後が 10 進数字でも 'x'/'X' でもない（名前実体・単なる & 等）
//   - 数字が 1 つも無い、または上限桁数（htmlEntityMaxDecimalDigits /
//     htmlEntityMaxHexDigits）を超えて数字が続く
//   - セミコロンで終端していない
//   - コードポイントが U+0020 未満（制御文字。行構造を壊さないため）
//   - コードポイントがサロゲート範囲（U+D800〜U+DFFF）または U+10FFFF 超
//
// 戻り値の width は '&' から ';' まで（';' を含む）消費したバイト数。
func decodeOneHTMLNumericEntity(text string, i int) (rune, int, bool) {
	if i+1 >= len(text) || text[i] != '&' || text[i+1] != '#' {
		return 0, 0, false
	}
	j := i + 2
	hex := j < len(text) && (text[j] == 'x' || text[j] == 'X')
	if hex {
		j++
	}
	maxDigits, base := htmlEntityMaxDecimalDigits, uint32(10)
	if hex {
		maxDigits, base = htmlEntityMaxHexDigits, uint32(16)
	}

	start := j
	var v uint32
	for j < len(text) && j-start < maxDigits {
		d, ok := htmlDigitValue(text[j], hex)
		if !ok {
			break
		}
		v = v*base + d
		j++
	}
	if j == start {
		return 0, 0, false // 数字が 1 つも無い
	}
	// 上限桁数ちょうどで打ち切った直後も同じ基数の数字が続く場合は、上限
	// 超過の数値列（誤爆リスクが高い）として非対象にする。
	if j < len(text) {
		if _, ok := htmlDigitValue(text[j], hex); ok {
			return 0, 0, false
		}
	}
	if j >= len(text) || text[j] != ';' {
		return 0, 0, false
	}
	if v < 0x20 || (v >= 0xD800 && v <= 0xDFFF) || v > 0x10FFFF {
		return 0, 0, false
	}
	return rune(v), j + 1 - i, true
}

// htmlDigitValue は c を、hex が真なら 16 進数、偽なら 10 進数の 1 桁として
// 解釈する。範囲外の文字であれば ok=false。10 進側は hexDigitValue を使わず
// 独立させることで、10 進コンテキストで 'a'〜'f' を桁として誤って受理しない
// ようにする。
func htmlDigitValue(c byte, hex bool) (uint32, bool) {
	if !hex {
		if c >= '0' && c <= '9' {
			return uint32(c - '0'), true
		}
		return 0, false
	}
	d, ok := hexDigitValue(c)
	return uint32(d), ok
}

// ---- URL パーセントエンコードの復号ビュー ----
//
// decodeJSONUnicodeEscapes・decodeHTMLNumericEntities と同じ「既に正当な
// UTF-8 のテキストの中の ASCII エスケープ表記」を対象にする独立した復号
// ビュー。decodeEscapedViews から HTML 数値文字参照の後段として呼ばれる
// （適用順の理由は decodeEscapedViews の doc コメントを参照）。

// percentEncodingMinTriplets は decodePercentEncoding が復号を検討する
// 連続 %XX 列の最小個数。単発の %XX を対象外にする理由は
// decodePercentEncoding の doc コメントを参照。
const percentEncodingMinTriplets = 2

// decodePercentEncoding は text に含まれる URL パーセントエンコード
// （%XX、16 進数は大文字小文字どちらも可）の連続列を実際の文字列へ復号
// したビューを返す。
//
// 対象にするのは「%XX が 2 個以上切れ目なく連続し、かつその連続列全体を
// まとめてデコードしたバイト列が正当な UTF-8 を成し、かつマルチバイト
// 文字（U+0080 以上、UTF-8 で 2 バイト以上になる文字）を 1 つ以上含む」
// 場合だけである。それ以外（連続列全体が不正な UTF-8、連続列が ASCII の
// みで構成される、%XX が単発）は一切復号しない。
//
// 単発の %XX（%20 の半角スペース、%2F の / 等）を意図的に対象外とする
// 理由: これらは URL/パスの構造文字であり ASCII なので、%XX に包まれて
// いなくても既存の正規表現ルールから隠れているわけではなく、復号する
// 検出価値が低い。一方、任意の位置の単発 %XX を無条件に復号してしまうと、
// URL 中の構造的な区切り文字を書き換えて本来別々だったトークンを結合・
// 分断し、無関係な文字列を誤って PII らしく見せる（あるいはその逆で本来
// 検出すべき値を隠す）リスクがある。%40（@ 単体）も同じ理由で対象外と
// する。マルチバイト文字を 1 つ以上含む連続列だけに対象を絞ることで、
// 「複数の %XX が組になってひとまとまりの非 ASCII 文字列を意図的に表現
// している」という誤爆リスクの低い強いシグナルがある場合だけ復号する。
//
// decodeJSONUnicodeEscapes・decodeHTMLNumericEntities と同じ「疑わしければ
// 復号しない」方針: 連続列をまとめて復号した結果に U+0020 未満の制御文字が
// 1 つでも含まれる場合は、その連続列全体を復号しない（行構造保存。一部だけ
// 復号し残りをリテラルに戻す、という中途半端なことはしない — 連続列の
// 途中の %XX から再走査して部分的に復号することも含めて避ける。詳細は
// decodePercentRun の doc コメントを参照）。
//
// 位置セマンティクス: 復号は U+0020 未満の文字を新たに生み出さないため、
// 復号後テキストの行数・各行番号は元テキストと厳密に一致する。列
// （Column）はパーセントエンコードを含む行でのみ復号後の文字列上の位置に
// なる（decodeJSONUnicodeEscapes と同じ性質）。
//
// 1 箇所も復号できなければ ok=false を返し、呼び出し側は元のテキストを
// そのまま使う。大多数を占める "%" を含まないテキストは、strings.Contains
// によるバイト走査 1 回で早期リターンする。
func decodePercentEncoding(text string) (string, bool) {
	if !strings.Contains(text, "%") {
		return "", false
	}

	var b strings.Builder
	b.Grow(len(text))
	decoded := false
	for i := 0; i < len(text); {
		if text[i] == '%' {
			repl, runLen, ok := decodePercentRun(text, i)
			if ok {
				b.WriteString(repl)
				i += runLen
				decoded = true
				continue
			}
			if runLen > 0 {
				// 連続列全体（非復号と判定された分も含む）を単位として
				// リテラルのままコピーする。runLen 未満の途中位置（連続列の
				// 内側の %XX）から再走査してしまうと、一度「全体として
				// 非復号」と判定した連続列の後半だけが独立に条件を満たして
				// 部分的に復号される事故が起きる（decodePercentRun の doc
				// コメント参照）。
				b.WriteString(text[i : i+runLen])
				i += runLen
				continue
			}
		}
		b.WriteByte(text[i])
		i++
	}
	if !decoded {
		return "", false
	}
	return b.String(), true
}

// decodePercentRun は text[i] を先頭に切れ目なく続く %XX の連続列を走査
// する。呼び出し側は text[i] == '%' を確認済みとする。
//
// 戻り値の runLen は、復号の成否によらず、連続列（%XX が 1 個以上、切れ目
// なく続く限り）が占める text のバイト数（%XX の個数 × 3）。呼び出し側は
// runLen 分をひとまとまりの単位として扱い、非復号時も i を必ず i+runLen
// まで一括で進めること。連続列の途中の %XX から再走査すると、例えば
// 「制御文字 + 日本語」の連続列（全体としては非復号のはず）で、制御文字を
// 含まない後半部分だけが独立に条件を満たしてしまい、「一部だけ復号し残りを
// リテラルに戻す」という中途半端な結果になる（decodePercentEncoding が
// 意図的に避けている挙動）。runLen == 0 は、text[i] は '%' だが有効な
// %XX が 1 つも続かない（末尾で桁が足りない・16 進数として不正）ことを
// 意味し、呼び出し側は通常どおり 1 バイトだけ進める。
//
// decoded（3 番目の戻り値）が false になるケースは decodePercentEncoding
// の doc コメントのとおり: 連続列が 2 個未満、連続列全体が不正な UTF-8、
// マルチバイト文字を 1 つも含まない、制御文字（U+0020 未満）を含む。
// decoded が true のとき repl に復号後の文字列が入る。
func decodePercentRun(text string, i int) (repl string, runLen int, decoded bool) {
	raw := make([]byte, 0, (len(text)-i)/3)
	j := i
	for j+3 <= len(text) && text[j] == '%' {
		hi, ok1 := hexDigitValue(text[j+1])
		lo, ok2 := hexDigitValue(text[j+2])
		if !ok1 || !ok2 {
			break
		}
		raw = append(raw, byte(hi<<4|lo))
		j += 3
	}
	runLen = j - i
	if len(raw) < percentEncodingMinTriplets {
		return "", runLen, false
	}
	if !utf8.Valid(raw) {
		return "", runLen, false
	}
	decodedStr := string(raw)
	hasMultibyte := false
	for _, r := range decodedStr {
		if r < 0x20 {
			return "", runLen, false // 制御文字は連続列全体を非復号
		}
		if r > 0x7F {
			hasMultibyte = true
		}
	}
	if !hasMultibyte {
		return "", runLen, false
	}
	return decodedStr, runLen, true
}
