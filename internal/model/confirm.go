package model

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/baneido/jp-pii-detector/internal/dict"
	"github.com/baneido/jp-pii-detector/internal/external"
	"github.com/baneido/jp-pii-detector/internal/normalize"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// 確認器（docs/design-ai-detection.md §6.5）。モデルが挙げたスパンを、組み込み
// ルールと同じ書式検証（正規表現 + Validate）に通し、ルール ID を決める。
//
// 書式で真偽を決められる種別（数字列とメールアドレス）は、組み込みルールの
// パターンが「値全体」に一致し、その Validate を通ったときだけ残す。数字列については
// Sumi の種別ラベルを信用しない（PoC でカード番号や国際表記の電話番号に別の種別を
// 付けたため。§13.3）。どの数字系ルールに通るかで種別を付け直す。
//
// 書式で真偽を決められない種別（氏名・住所・生年月日）は、最低限の形だけを見て
// モデルの判断を採る。

// numericRuleIDs は数字列のスパンを付け直す先の候補。先に書いたものを優先する
// （検査用数字のある種別を先に置き、7 桁の数字はモデルの種別で郵便番号と口座番号を
// 分ける）。
var numericRuleIDs = []string{"jp-my-number", "credit-card", "jp-phone-number"}

// sevenDigitRuleIDs は 7 桁の数字に対して、モデルの種別ごとに試すルール。
var sevenDigitRuleIDs = map[string]string{
	"POSTAL_CODE":  "jp-postal-code",
	"BANK_ACCOUNT": "jp-bank-account",
}

var numericTypes = map[string]bool{
	"PHONE": true, "BANK_ACCOUNT": true, "CREDIT_CARD": true, "MYNUMBER": true, "POSTAL_CODE": true,
}

// builtinByID は組み込みルールを ID ごとにまとめたもの（同じ ID のエントリが
// 複数ある）。高再現率ルールは含めない（rule.Builtin() は既定のルール一覧）。
var builtinByID = func() map[string][]rule.Rule {
	m := map[string][]rule.Rule{}
	for _, r := range rule.Builtin() {
		m[r.ID] = append(m[r.ID], r)
	}
	return m
}()

// matchesRule は value（正規化済み）全体が ruleID のいずれかのパターンに一致し、
// そのパターンとルールの検証を通るかを返す。パターンの捕捉グループ 1 があれば
// それを値の本体として扱う（dg()/ag() の境界ガードは捕捉の外にある）。
func matchesRule(ruleID, value string) bool {
	for _, r := range builtinByID[ruleID] {
		for _, p := range r.Patterns {
			for _, m := range p.Re.FindAllStringSubmatchIndex(value, -1) {
				s, e := m[0], m[1]
				if len(m) >= 4 && m[2] >= 0 {
					s, e = m[2], m[3]
				}
				if s != 0 || e != len(value) {
					continue
				}
				body := value[s:e]
				if (r.Validate == nil || r.Validate(body)) &&
					(p.Validate == nil || p.Validate(body)) &&
					(p.ValidateLine == nil || p.ValidateLine(value, s, e)) {
					return true
				}
			}
		}
	}
	return false
}

// confirm はスパンの値 value（原文）とモデルの種別 typ から、報告するルール ID を
// 返す。報告しないなら ok=false。
func confirm(typ, value string) (ruleID string, ok bool) {
	norm := normalize.Line(value)
	switch {
	case typ == "MEMBER_ID":
		return "", false // 会員番号は本ツールの対象外
	case numericTypes[typ]:
		if !numericShape(norm) {
			return "", false
		}
		for _, id := range numericRuleIDs {
			if matchesRule(id, norm) {
				return id, true
			}
		}
		if id, ok := sevenDigitRuleIDs[typ]; ok && matchesRule(id, norm) {
			return id, true
		}
		return "", false
	case typ == "EMAIL":
		return "email-address", matchesRule("email-address", norm)
	case typ == "DOB":
		// 年・月・日の 3 つの数が揃っていない断片（「昭和」「1」など）は落とす。
		return "jp-birthdate", countDigitRuns(norm) >= 3
	case typ == "ADDRESS":
		// 番地のない地名だけのスパンは落とす（地名の一覧で大量に誤検出するため。§11）。
		return "jp-address", banchiRe.MatchString(norm)
	case typ == "NAME":
		return "person-name", nameShape(norm)
	}
	return "", false
}

// banchiRe は番地らしい数字（算用数字、または「丁目」「番」「号」が続く漢数字）。
// 漢数字だけを見ると「一乗寺」「三鷹」のような地名で一致してしまうため、後続を要求する。
var banchiRe = regexp.MustCompile(`[0-9]|[一二三四五六七八九十]+(?:丁目|番|号)`)

// numericShape は数字と区切り記号だけでできているかを返す（UUID のような英字混じりや、
// 「商事 | 1234567」のように語を含むスパンを落とす）。
func numericShape(s string) bool {
	digits := 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case strings.ContainsRune("-+()./ ", r):
		default:
			return false
		}
	}
	return digits > 0
}

func countDigitRuns(s string) int {
	n, in := 0, false
	for _, r := range s {
		d := r >= '0' && r <= '9'
		if d && !in {
			n++
		}
		in = d
	}
	return n
}

// nameShape は 2 文字以上で、文字（漢字・かな・英字）を含み、数字や記号だけで
// できていないかを返す。
func nameShape(s string) bool {
	letters := 0
	for _, r := range s {
		switch {
		case unicode.IsLetter(r):
			letters++
		case unicode.IsSpace(r), r == '・':
		default:
			return false
		}
	}
	return letters >= 2
}

// confidence はスパン確率を 3 段階へ写す。氏名は姓名辞書に一致すれば medium を
// 下限にする（辞書にない氏名を拾うのがモデルを使う目的なので、不一致でも棄却しない）。
func confidence(ruleID, value string, prob float64) string {
	c := rule.Low
	switch {
	case prob >= highProb:
		c = rule.High
	case prob >= mediumProb:
		c = rule.Medium
	}
	if ruleID == "person-name" && c < rule.Medium && dict.IsPersonName(strings.ReplaceAll(normalize.Line(value), " ", "")) {
		c = rule.Medium
	}
	return c.String()
}

// toCandidates はスパンを行ごとに切り、前後の空白を除いて確認器に通し、候補へ変換する。
func toCandidates(runes []rune, spans []span) []external.Candidate {
	lineStart := []int{0}
	for i, r := range runes {
		if r == '\n' {
			lineStart = append(lineStart, i+1)
		}
	}
	lineOf := func(pos int) int { // 0 始まり
		lo, hi := 0, len(lineStart)-1
		for lo < hi {
			mid := (lo + hi + 1) / 2
			if lineStart[mid] <= pos {
				lo = mid
			} else {
				hi = mid - 1
			}
		}
		return lo
	}
	var out []external.Candidate
	for _, sp := range spans {
		if sp.prob < spanThreshold {
			continue
		}
		// スパンが改行をまたぐときは行ごとに分けて別々に確かめる（候補は 1 行に収まる形式）。
		for s := sp.start; s < sp.end; {
			e := s
			for e < sp.end && runes[e] != '\n' {
				e++
			}
			ps, pe := s, e
			for ps < pe && unicode.IsSpace(runes[ps]) {
				ps++
			}
			for pe > ps && unicode.IsSpace(runes[pe-1]) {
				pe--
			}
			if ps < pe {
				value := string(runes[ps:pe])
				if id, ok := confirm(sp.typ, value); ok {
					line := lineOf(ps)
					out = append(out, external.Candidate{
						RuleID:     id,
						Line:       line + 1,
						Column:     ps - lineStart[line] + 1,
						Length:     pe - ps,
						Confidence: confidence(id, value, sp.prob),
					})
				}
			}
			s = e + 1
		}
	}
	return out
}
