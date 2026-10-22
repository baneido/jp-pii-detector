package rule

import "strings"

// 数字列ルール（電話番号・口座番号・マイナンバー・クレジットカード）に共通で
// かける、周辺文脈による偽陽性の棄却（ValidateLine）。社内の Go 製サーバー
// リポジトリでの実測で、これらのルールの偽陽性は「数字列が番号ではなく、
// より大きな数値・識別子・URL の一部」である形に集中していた:
//
//   - 小数の一部（"0.1234567"、mtime の "1712345678.1234567"）
//   - 16 進トークンの一部（"3fa1234567bd"、"deadbeef" + 11 桁の数字）
//   - URL のパス・クエリ中の ID（"https://support.example.com/answer/1234567"）
//   - Firebase のアプリ ID（"1:123456789012:android:0a1b2c3d4e5f6789"）
//
// 個々のルールの境界ガード（dg / dgNoAlnumHyphen 等）を厳しくすると、
// ルールごとに意図して許している表記（"smartphone<11 桁の携帯番号>" 等）の再現率まで
// 落ちるため、ここでは「周辺が明らかに番号以外の構造である」場合だけを棄却する。
// withNumericContextGuard が Builtin の最後に対象ルールの全パターンへ合成する。

// numericContextGuardRuleIDs は numericContextGuard を合成するルール ID。
var numericContextGuardRuleIDs = map[string]bool{
	"jp-phone-number": true,
	"jp-bank-account": true,
	"jp-my-number":    true,
	"credit-card":     true,
}

// withNumericContextGuard は numericContextGuardRuleIDs の各ルールの全パターンに
// numericContextGuard を AND 合成する。既存の ValidateLine は先に評価する。
func withNumericContextGuard(rules []Rule) []Rule {
	for i := range rules {
		r := &rules[i]
		if !numericContextGuardRuleIDs[r.ID] {
			continue
		}
		guard := numericContextGuard(r.Context)
		pats := make([]Pattern, len(r.Patterns))
		copy(pats, r.Patterns)
		for j := range pats {
			if prev := pats[j].ValidateLine; prev != nil {
				pats[j].ValidateLine = allValidateLine(prev, guard)
			} else {
				pats[j].ValidateLine = guard
			}
		}
		r.Patterns = pats
	}
	return rules
}

// numericContextGuard は rejectDecimalFraction・rejectHexTokenPart・
// rejectURLNumericID・rejectFirebaseAppID をまとめた ValidateLine を返す。
// context はルールのコンテキスト語で、URL クエリのキー名がこれを含む場合
// （"?tel=..."）は URL 中でも棄却しない。
func numericContextGuard(context []string) func(string, int, int) bool {
	return allValidateLine(
		rejectDecimalFraction,
		rejectHexTokenPart,
		rejectURLNumericID(context),
		rejectFirebaseAppID,
	)
}

// rejectDecimalFraction は、数字列が小数の一部である場合に棄却する。直前が
// 「数字 + .」（小数部: "0.1234567"、"1712345678.1234567"）、または直後が
// 「. + 数字」（整数部: "1234567.25"）のとき。ドット区切りの携帯番号のような
// ドット区切りの番号そのものはマッチ範囲の内側にドットがあるので影響しない。
func rejectDecimalFraction(line string, start, end int) bool {
	if start > 1 && line[start-1] == '.' && isASCIIDigit(line[start-2]) {
		return false
	}
	if end+1 < len(line) && line[end] == '.' && isASCIIDigit(line[end+1]) {
		return false
	}
	return true
}

// hexTokenMinLen は rejectHexTokenPart が 16 進トークンとみなす最小の長さ。
// "a1234567" のような短いトークンは型番・会員番号とも区別できないため棄却しない。
const hexTokenMinLen = 12

func isASCIIAlnum(c byte) bool {
	return isASCIIDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// rejectHexTokenPart は、数字列が英字 a-f と地続きの 16 進トークン
// （ハッシュ・トークン・バイナリのダンプ等: "3fa1234567bd"、
// "deadbeef" + 11 桁の数字）の一部である場合に棄却する。マッチを含む ASCII
// 英数字の連続が hexTokenMinLen 文字以上で、16 進数字だけからなり、マッチの外側に
// 英字 a-f を 1 文字以上含むときだけ棄却する。16 進以外の英字を含む連結
// （"smartphone<11 桁の携帯番号>"、"No1234567"）は従来どおり各ルールの境界ガードに任せる。
func rejectHexTokenPart(line string, start, end int) bool {
	l, r := start, end
	for l > 0 && isASCIIAlnum(line[l-1]) {
		l--
	}
	for r < len(line) && isASCIIAlnum(line[r]) {
		r++
	}
	if l == start && r == end {
		return true
	}
	if r-l < hexTokenMinLen {
		return true
	}
	letter, ok := hexToken(line[l:r])
	if !ok || !letter {
		return true
	}
	if l < start {
		if lt, _ := hexToken(line[l:start]); lt {
			return false
		}
	}
	if r > end {
		if lt, _ := hexToken(line[end:r]); lt {
			return false
		}
	}
	return true
}

// urlTokenStart は line[:start] の末尾から、空白・引用符・括弧等で区切られた
// トークンの先頭位置を返す。
func urlTokenStart(line string, start int) int {
	i := start
	for i > 0 {
		switch line[i-1] {
		case ' ', '\t', '"', '\'', '`', '(', '<', '[', '{', ',', '|':
			return i
		}
		i--
	}
	return i
}

// rejectURLNumericID は、区切りを含まない数字だけのマッチが URL のパスの
// セグメント（直前が "/"）またはクエリの値（直前が "=" で、"?" か "&" 以降）
// である場合に棄却する（"https://support.example.com/answer/1234567"、
// "?id=1234567"）。URL はトークン中のマッチより前に "://" があるものに限る。
// クエリのキー名が context の語を含む場合（"?tel=<11 桁の携帯番号>"）は、値が番号
// そのものである可能性が高いので棄却しない。区切り付きの番号（"/" + ハイフン区切りの携帯番号）は
// URL の ID とまず衝突しないので対象外。
func rejectURLNumericID(context []string) func(string, int, int) bool {
	return func(line string, start, end int) bool {
		if start == 0 {
			return true
		}
		for i := start; i < end; i++ {
			if !isASCIIDigit(line[i]) {
				return true
			}
		}
		prev := line[start-1]
		if prev != '/' && prev != '=' {
			return true
		}
		ts := urlTokenStart(line, start)
		tok := line[ts:start]
		scheme := strings.Index(tok, "://")
		if scheme < 0 {
			return true
		}
		if prev == '/' {
			return false
		}
		q := strings.LastIndexAny(tok, "?&;")
		if q < scheme {
			return true
		}
		key := strings.ToLower(tok[q+1 : len(tok)-1])
		for _, c := range context {
			if strings.Contains(key, strings.ToLower(c)) {
				return true
			}
		}
		return false
	}
}

// firebaseAppIDPlatforms は Firebase のアプリ ID
// （"<バージョン>:<プロジェクト番号>:<プラットフォーム>:<16 進>"）のプラットフォーム部。
var firebaseAppIDPlatforms = []string{":android:", ":ios:", ":web:"}

// rejectFirebaseAppID は、数字列が Firebase のアプリ ID
// （"1:123456789012:android:0a1b2c3d4e5f6789"）のプロジェクト番号部である場合に
// 棄却する。直前が「数字 + :」、直後が ":android:" / ":ios:" / ":web:" のとき。
func rejectFirebaseAppID(line string, start, end int) bool {
	if start < 2 || line[start-1] != ':' || !isASCIIDigit(line[start-2]) {
		return true
	}
	rest := line[end:]
	for _, p := range firebaseAppIDPlatforms {
		if strings.HasPrefix(rest, p) {
			return false
		}
	}
	return true
}
