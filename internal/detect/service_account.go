package detect

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Google Cloud のサービスアカウントのメールアドレス（ドメインが gserviceaccount.com
// またはそのサブドメイン）は、個人ではなくワークロード（VM・Cloud Build・Pub/Sub 等）の
// ID であり、どのモードでも個人情報として報告しない。
//
//   - <名前>@<プロジェクト>.iam.gserviceaccount.com
//   - <プロジェクト番号>-compute@developer.gserviceaccount.com
//   - service-<プロジェクト番号>@gcp-sa-<サービス>.iam.gserviceaccount.com
//   - <プロジェクト>@appspot.gserviceaccount.com
//   - <プロジェクト番号>@cloudbuild.gserviceaccount.com
//
// email-address ルール自体は rule.validEmail（emailNonPersonalDomains）で棄却して
// いるが、ローカル部の数字列（プロジェクト番号）がマイナンバー等の数値ルールや
// モデルの数値スパンとして一致することがある。そこで、検出候補がサービスアカウントの
// アドレスの内部に完全に収まる場合は、ルールを問わず棄却する（insideUUIDToken と同じ考え方）。
//
// ドメインは末尾一致で厳密に判定する（大文字小文字は区別しない）。
// gserviceaccount.com.evil.example（後ろに続く）、xgserviceaccount.com（ラベルの途中）、
// gserviceaccount.co（TLD 違い）のような似たドメインは対象外で、通常どおり検出する。

const serviceAccountDomain = "gserviceaccount.com"

// insideServiceAccountEmail は s（正規化済みの行）の [start,end)（バイト位置）が
// サービスアカウントのメールアドレスの内部に完全に含まれるかを返す。
func insideServiceAccountEmail(s string, start, end int) bool {
	if start < 0 || end < start || end > len(s) || strings.IndexByte(s, '@') < 0 {
		return false
	}
	for _, sp := range serviceAccountEmailSpans(s) {
		if sp[0] <= start && end <= sp[1] {
			return true
		}
	}
	return false
}

// serviceAccountEmailSpans は s に含まれるサービスアカウントのメールアドレスの
// バイト範囲 [start,end) を返す。"gserviceaccount" を含まない行は割り当てなしで返す。
func serviceAccountEmailSpans(s string) [][2]int {
	var spans [][2]int
	for from := 0; from < len(s); {
		i := indexFoldASCII(s[from:], serviceAccountDomain)
		if i < 0 {
			break
		}
		ds := from + i
		de := ds + len(serviceAccountDomain)
		from = ds + 1
		// ドメインの末尾: 直後にラベル文字や「.<ラベル文字>」が続けば、より長い別の
		// ドメイン（gserviceaccount.com.evil.example、gserviceaccount.comx）。
		if de < len(s) && (isDomainLabelByte(s[de]) ||
			(s[de] == '.' && de+1 < len(s) && isDomainLabelByte(s[de+1]))) {
			continue
		}
		// ドメインの先頭: 直前は '@'（gserviceaccount.com そのもの）か、サブドメインの
		// 区切りの '.'。xgserviceaccount.com のようにラベルの途中なら対象外。
		at := ds - 1
		if at < 0 {
			continue
		}
		if s[at] == '.' {
			// サブドメインのラベル（英数字・ハイフン・ドット）をさかのぼって '@' を探す。
			for at >= 0 && (isDomainLabelByte(s[at]) || s[at] == '.') {
				at--
			}
		}
		if at <= 0 || s[at] != '@' || s[at+1] == '.' {
			continue
		}
		// ローカル部（英数字と . _ % + -、高再現率の email-address-eai と同じく
		// 漢字・ひらがな・カタカナも含む）をさかのぼる。
		ls := at
		for ls > 0 {
			if isEmailLocalByte(s[ls-1]) {
				ls--
				continue
			}
			r, size := utf8.DecodeLastRuneInString(s[:ls])
			if !isJapaneseLocalRune(r) {
				break
			}
			ls -= size
		}
		if ls == at {
			continue
		}
		spans = append(spans, [2]int{ls, de})
	}
	return spans
}

func isDomainLabelByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-'
}

func isEmailLocalByte(c byte) bool {
	return isDomainLabelByte(c) || c == '.' || c == '_' || c == '%' || c == '+'
}

func isJapaneseLocalRune(r rune) bool {
	return unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana) || r == 'ー'
}

// indexFoldASCII は ASCII の大文字小文字を区別せずに substr（小文字）を s から探す。
func indexFoldASCII(s, substr string) int {
	n := len(substr)
	for i := 0; i+n <= len(s); i++ {
		if c := s[i] | 0x20; c != substr[0] {
			continue
		}
		if strings.EqualFold(s[i:i+n], substr) {
			return i
		}
	}
	return -1
}
