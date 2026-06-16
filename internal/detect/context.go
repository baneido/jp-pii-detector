package detect

import "strings"

func (d *Detector) containsAnyContext(haystack string, kws []string) bool {
	return len(d.matchingContexts(haystack, kws)) > 0
}

func (d *Detector) matchingContexts(haystack string, kws []string) []string {
	lower := strings.ToLower(haystack)
	// 識別子トークンは ASCII キーワードが単語境界で見つからなかった
	// 場合のみ必要になるため、最初に要求されるまで分割を遅延する。
	var tokens []string
	tokenized := false
	var out []string
	for _, kw := range kws {
		if containsWord(lower, kw) {
			out = append(out, kw)
			continue
		}
		// 日本語など非 ASCII 語は部分一致（containsWord）が正しいので
		// トークナイザは適用しない。ASCII 語のみ camelCase / snake_case /
		// kebab-case の識別子に分割して照合する。
		if !asciiOnly(kw) {
			continue
		}
		// キーワード側のトークンは New で事前計算済み。未登録の場合のみ分割する。
		kwTokens, ok := d.ctxTokens[kw]
		if !ok {
			kwTokens = tokenizeIdentifiers(kw)
		}
		if !tokenized {
			// camelCase の境界を保つため小文字化前の元文字列を分割する。
			tokens = tokenizeIdentifiers(haystack)
			tokenized = true
		}
		if containsTokenSubsequence(tokens, kwTokens) {
			out = append(out, kw)
		}
	}
	return out
}

// tokenizeIdentifiers は文字列を識別子の構成語トークン列に分割する。
// ASCII 英数字の連なりを、大文字小文字の切れ目（camelCase）・英字と数字の
// 切れ目・非英数字（_ - 空白など）の区切りで分割し、小文字化して返す。
// 例: "bankAccountNo" -> ["bank", "account", "no"]、
//
//	"driver_license_no" -> ["driver", "license", "no"]。
//
// 単語境界（containsWord）では取りこぼす camelCase / snake_case /
// kebab-case のラベルを、誤検出を増やさずにコンテキストとして拾うために使う。
func tokenizeIdentifiers(s string) []string {
	var tokens []string
	var cur []byte
	flush := func() {
		if len(cur) > 0 {
			tokens = append(tokens, string(cur))
			cur = cur[:0]
		}
	}
	classOf := func(c byte) byte {
		switch {
		case c >= 'A' && c <= 'Z':
			return 'U'
		case c >= 'a' && c <= 'z':
			return 'L'
		case c >= '0' && c <= '9':
			return 'D'
		}
		return 0 // 区切り文字
	}
	// prev は直前に取り込んだ文字の元の字種（U=大文字 / L=小文字 / D=数字）。
	var prev byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		cc := classOf(c)
		if cc == 0 {
			flush()
			prev = 0
			continue
		}
		if len(cur) > 0 {
			switch {
			// camelCase / 数字→語: 小文字・数字の直後の大文字は新しい語。
			case cc == 'U' && (prev == 'L' || prev == 'D'):
				flush()
			// 連続大文字（頭字語）の末尾: 直後が小文字なら、この大文字から
			// 新しい語が始まる（例: HTTPServer→["http","server"]、APIKey→["api","key"]）。
			case cc == 'U' && prev == 'U' && i+1 < len(s) && classOf(s[i+1]) == 'L':
				flush()
			// 英字と数字の境界で区切る（例: abc123→["abc","123"]）。
			case cc == 'L' && prev == 'D', cc == 'D' && prev == 'L':
				flush()
			}
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		cur = append(cur, c)
		prev = cc
	}
	flush()
	return tokens
}

// containsTokenSubsequence は kwTokens（キーワードを分割したトークン列）が
// tokens の中に連続部分列として現れるかを返す。
func containsTokenSubsequence(tokens, kwTokens []string) bool {
	if len(kwTokens) == 0 || len(kwTokens) > len(tokens) {
		return false
	}
	for i := 0; i+len(kwTokens) <= len(tokens); i++ {
		match := true
		for j, kt := range kwTokens {
			if tokens[i+j] != kt {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func containsWord(haystack, kw string) bool {
	if kw == "" {
		return true
	}
	if !asciiOnly(kw) || !isASCIIAlnum(kw[0]) || !isASCIIAlnum(kw[len(kw)-1]) {
		return strings.Contains(haystack, kw)
	}
	for offset := 0; offset <= len(haystack); {
		i := strings.Index(haystack[offset:], kw)
		if i < 0 {
			return false
		}
		start := offset + i
		end := start + len(kw)
		if !hasASCIIAlnumBefore(haystack, start) && !hasASCIIAlnumAfter(haystack, end) {
			return true
		}
		offset = start + 1
	}
	return false
}

func asciiOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func hasASCIIAlnumBefore(s string, pos int) bool {
	return pos > 0 && isASCIIAlnum(s[pos-1])
}

func hasASCIIAlnumAfter(s string, pos int) bool {
	return pos < len(s) && isASCIIAlnum(s[pos])
}

func isASCIIAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func contextWindow(s string, start, end, radius int, runes *[]rune) string {
	if radius <= 0 {
		return s
	}
	if *runes == nil {
		*runes = []rune(s)
	}
	rs := *runes
	runeStart := len([]rune(s[:start]))
	runeEnd := runeStart + len([]rune(s[start:end]))
	from := runeStart - radius
	if from < 0 {
		from = 0
	}
	to := runeEnd + radius
	if to > len(rs) {
		to = len(rs)
	}
	return string(rs[from:to])
}
