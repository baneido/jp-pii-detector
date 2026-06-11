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

// Line は 1 行を正規化する。ルーン数は変化しない。
//   - 全角英数字・記号 → 半角
//   - 全角スペース → 半角スペース
//   - ハイフン類似文字 → '-'
//   - 長音記号「ー」は数字に隣接する場合のみ '-'（カタカナ語は保持）
func Line(s string) string {
	// 変換対象の文字（ハイフン類 U+2010〜U+2015・U+2212・U+FE63、
	// 全角 ASCII U+FF01〜、全角スペース U+3000、長音記号 U+30FC）は
	// すべて U+2010 以上。それ未満だけの行（純 ASCII 等）は無変換で返す。
	needsMap := false
	for _, r := range s {
		if r >= '\u2010' {
			needsMap = true
			break
		}
	}
	if !needsMap {
		return s
	}
	rs := []rune(s)
	out := make([]rune, len(rs))
	for i, r := range rs {
		out[i] = mapRune(r)
	}
	for i, r := range rs {
		if r != prolongedSoundMark {
			continue
		}
		prevDigit := i > 0 && isDigit(out[i-1])
		nextDigit := i+1 < len(out) && isDigit(out[i+1])
		if prevDigit || nextDigit {
			out[i] = '-'
		}
	}
	return string(out)
}
