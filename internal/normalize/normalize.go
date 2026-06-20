// Package normalize は日本語テキスト特有の表記ゆれを正規化する。
//
// 正規化はルーン単位の 1:1 変換に限定している。これにより正規化後の
// ルーン位置が常に元テキストのルーン位置と一致し、検出位置の逆引きが
// 不要になる。
package normalize

// hyphens は「-」に正規化するハイフン類似文字。
// 全角ハイフンマイナス (U+FF0D) は ASCII オフセット変換で処理される。
var hyphens = map[rune]bool{
	'‐': true, // ‐ HYPHEN
	'‑': true, // ‑ NON-BREAKING HYPHEN
	'‒': true, // ‒ FIGURE DASH
	'–': true, // – EN DASH
	'—': true, // — EM DASH
	'―': true, // ― HORIZONTAL BAR
	'−': true, // − MINUS SIGN
	'﹣': true, // ﹣ SMALL HYPHEN-MINUS
}

const prolongedSoundMark = 'ー' // ー（長音記号。数字に隣接する場合のみハイフン扱い）

func mapRune(r rune) rune {
	switch {
	case r >= '！' && r <= '～': // 全角 ASCII → 半角
		return r - 0xFEE0
	case r == '　': // 全角スペース
		return ' '
	case hyphens[r]:
		return '-'
	}
	return r
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

// isConvTarget は mapRune が別の文字へ写像する文字（全角 ASCII・全角スペース・
// ハイフン類）かを返す。長音記号「ー」は数字隣接時のみ変換するため、ここには
// 含めず needsConversion 側で隣接判定する。
func isConvTarget(r rune) bool {
	return (r >= '！' && r <= '～') || r == '　' || hyphens[r]
}

// needsConversion は s に変換対象が 1 つでも含まれるかを 1 パスで判定する
// （割り当てなし）。全角 ASCII・全角スペース・ハイフン類のいずれか、または
// 数字に隣接する長音記号があれば true。漢字・かな・数字非隣接の長音記号だけの
// 行（通常の日本語文）は false となり、Line のファストパスで元文字列を返せる。
//
// 旧実装は「U+2010 以上の文字があれば変換が要る」と広く判定していたため、
// 漢字・かな（いずれも U+2010 以上）を含むほぼ全ての日本語行が遅いパスへ入り、
// 変換が不要でも []rune を 2 本割り当てていた。
func needsConversion(s string) bool {
	prev := rune(-1)
	for _, r := range s {
		switch {
		case isConvTarget(r):
			return true
		case r == prolongedSoundMark && isDigit(prev):
			return true
		case isDigit(r) && prev == prolongedSoundMark:
			return true
		}
		prev = r
	}
	return false
}

// Line は 1 行を正規化する。ルーン数は変化しない。
//   - 全角英数字・記号 → 半角
//   - 全角スペース → 半角スペース
//   - ハイフン類似文字 → '-'
//   - 長音記号「ー」は数字に隣接する場合のみ '-'（カタカナ語は保持）
func Line(s string) string {
	// 変換対象を厳密に判定する。対象がなければ（純 ASCII でも、変換対象を
	// 含まない通常の日本語文でも）割り当てなしで元文字列をそのまま返す。
	if !needsConversion(s) {
		return s
	}
	// 変換が必要な場合のみ []rune を 1 回だけ確保し、その場で書き換える。
	// 入力用と出力用に 2 本のルーン列を持たない（割り当てを 2→1 に削減）。
	rs := []rune(s)
	for i, r := range rs {
		rs[i] = mapRune(r)
	}
	// \u9577\u97f3\u8a18\u53f7\u306e\u6570\u5b57\u96a3\u63a5\u5224\u5b9a\u306f\u5199\u50cf\u5f8c\u306e\u5024\u3067\u884c\u3046\u3002mapRune \u306f\u300c\u30fc\u300d\u3092\u5909\u3048\u306a\u3044
	// \u305f\u3081\u5199\u50cf\u5f8c\u3082\u4f4d\u7f6e\u306f\u305d\u306e\u307e\u307e\u6b8b\u308a\u3001\u5168\u89d2\u6570\u5b57\u306f\u65e2\u306b\u534a\u89d2\u5316\u6e08\u307f\u3067\u3042\u308b\u3002
	for i, r := range rs {
		if r != prolongedSoundMark {
			continue
		}
		prevDigit := i > 0 && isDigit(rs[i-1])
		nextDigit := i+1 < len(rs) && isDigit(rs[i+1])
		if prevDigit || nextDigit {
			rs[i] = '-'
		}
	}
	return string(rs)
}
