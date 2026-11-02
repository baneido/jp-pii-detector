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

// confirmSpan は 1 行に収まったスパン runes[ps:pe] を確かめ、報告するルール ID と
// （必要なら狭めた）区間を返す。confirm（値だけを見る確認）に加え、次を補う。
//
//   - 口座番号: Sumi は「見本銀行 架空支店 普通 （7 桁の番号）」のように銀行名・支店・種別まで
//     含めて BANK_ACCOUNT とすることが多く、数字列だけでないため confirm では落ちる。
//     スパン自体が銀行の語を含み、確率が highProb 以上なら、スパン内の最後の数字列を
//     口座番号の書式で確かめて報告する（モデルのスパンを周辺語の代わりに使う）。
//   - 1 文字の姓: 「森さん」の「森」は nameShape（2 文字以上）で落ちる。直後に敬称が
//     続き、確率が highProb 以上のときだけ残す（「森の中を歩いて」のような地の文は
//     敬称が続かないので残らない）。
//   - 組織名: Sumi は振込先の「フリーギンコウ」のような片仮名の銀行名・会社名を
//     NAME とすることがある。銀行・会社を表す語を含む NAME は報告しない。
//   - 語の一部: 「フリーギンコウ」の「ギン」のように、片仮名語や英字の識別子の途中だけを
//     NAME としたスパンは報告しない（前後が同じ種類の文字に続いている）。
//   - ローマ字の氏名: Sumi は「Taro Yamada」を EMAIL と付けることがある。@ を含まず、
//     2 語がローマ字の姓・名の辞書に一致するときだけ氏名として報告する。
//
// 英字だけの氏名スパン（コード中の識別子 os, def など）は、ローマ字辞書に一致するか、
// 確率が highProb 以上で「John Smith」のように大文字始まりの 2 語以上のときだけ報告する。
func confirmSpan(sp span, runes []rune, ps, pe int) (ruleID string, start, end int, ok bool) {
	if sp.typ == "NAME" {
		pe = trimHonorificTail(runes, ps, pe)
	}
	value := string(runes[ps:pe])
	switch {
	case sp.typ == "DOB" && (foundingDateBefore(runes, ps) || foundingLabelPrevLine(runes, ps) || dateRangeBound(runes, ps, pe)):
		return "", 0, 0, false
	case sp.typ == "ADDRESS" && pe-ps == 1:
		// 「錦ケ丘８丁目バス停」の「８」のような 1 文字だけの住所は、番地の断片で
		// 住所として読めないので落とす。
		return "", 0, 0, false
	case sp.typ == "BANK_ACCOUNT" && !numericShape(normalize.Line(value)):
		if sp.prob < highProb || !bankWordRe.MatchString(value) {
			return "", 0, 0, false
		}
		locs := digitRunRe.FindAllStringIndex(value, -1)
		if len(locs) == 0 {
			return "", 0, 0, false
		}
		last := locs[len(locs)-1]
		ds := ps + len([]rune(value[:last[0]]))
		de := ds + len([]rune(value[last[0]:last[1]]))
		if !matchesRule("jp-bank-account", normalize.Line(string(runes[ds:de]))) {
			return "", 0, 0, false
		}
		return "jp-bank-account", ds, de, true
	case sp.typ == "NAME" && (orgWordRe.MatchString(value) || embeddedInWord(runes, ps, pe)):
		return "", 0, 0, false
	case sp.typ == "NAME" && pe-ps == 1:
		if sp.prob >= highProb && unicode.Is(unicode.Han, runes[ps]) && honorificAt(runes, pe) {
			return "person-name", ps, pe, true
		}
		return "", 0, 0, false
	case sp.typ == "NAME" && isASCII(value):
		if romajiName(value) || (sp.prob >= highProb && capitalizedWords(value)) {
			return "person-name", ps, pe, true
		}
		return "", 0, 0, false
	case sp.typ == "EMAIL" && !strings.Contains(value, "@") && romajiName(value):
		return "person-name", ps, pe, true
	}
	id, ok := confirm(sp.typ, value)
	return id, ps, pe, ok
}

// trimHonorificTail は氏名スパンが「<姓><名>さんが」のように敬称から後ろまで
// 含んでしまったとき、敬称の手前で切った終端を返す。先頭が敬称のスパンは触らない。
func trimHonorificTail(runes []rune, ps, pe int) int {
	for i := ps + 1; i < pe; i++ {
		if honorificAt(runes, i) && i+honorificLen(runes, i) <= pe {
			return i
		}
	}
	return pe
}

func honorificLen(runes []rune, pos int) int {
	rest := string(runes[pos:min(len(runes), pos+3)])
	for _, h := range honorifics {
		if strings.HasPrefix(rest, h) {
			return len([]rune(h))
		}
	}
	return 0
}

// foundingDateRe は日付の直前（同じ行の 8 文字以内）にあると、その日付が生年月日ではなく
// 団体の設立日や記入例であることを示す語。「設立：昭和<年>」「設立認可 <年>」
// 「会社設立日 <年>」「創立」「開局」「例：<年>」を想定する。
var foundingDateRe = regexp.MustCompile(`(?:設立|創立|創業|開局|開校|開設|例)[^\n]{0,3}$`)

// foundingLabelRe は、会社概要の表で日付の前の行に単独で置かれる設立日・創業日のラベル。
var foundingLabelRe = regexp.MustCompile(`^(?:会社|法人)?(?:設立|創立|創業|開業|開局|開校|開設)(?:年月日|日|年)?[:：]?$`)

// foundingLabelPrevLine は、日付が行頭にあり、その前の行（空行は 2 行まで飛ばす）が設立・創業の
// ラベルだけのとき true を返す。「設立\n平成<年>…」「創業\n<年>…」のように表のラベルが前の行に
// 分かれた形を、モデルが生年月日にする誤検出を 2026-11-02 08:00 に実測した（標本の 8 件中 6 件）。
func foundingLabelPrevLine(runes []rune, ps int) bool {
	i := ps
	for i > 0 && runes[i-1] != '\n' {
		i--
		if runes[i] != ' ' && runes[i] != '　' && runes[i] != '\t' {
			return false
		}
	}
	for blank := 0; i > 0 && blank <= 2; {
		end := i - 1 // 前の行の改行
		s := end
		for s > 0 && runes[s-1] != '\n' {
			s--
		}
		line := strings.Trim(string(runes[s:end]), " 　\t\r")
		if line == "" {
			blank++
			i = s
			continue
		}
		return foundingLabelRe.MatchString(line)
	}
	return false
}

// dateRangeBound は、日付が「<日付>以降に生まれた者」「<日付>以前」のように応募資格・対象期間の
// 端であるとき true を返す（2026-11-02 08:00 に募集要項で実測したモデルの生年月日の誤検出）。
// モデルのスパンが「以降」まで含む場合と、スパンの直後に続く場合の両方を扱う。
func dateRangeBound(runes []rune, ps, pe int) bool {
	v := strings.TrimRight(string(runes[ps:pe]), " 　")
	after := strings.TrimLeft(string(runes[pe:min(len(runes), pe+4)]), " 　")
	for _, w := range []string{"以降", "以前", "以後"} {
		if strings.HasSuffix(v, w) || strings.HasPrefix(after, w) {
			return true
		}
	}
	return false
}

func foundingDateBefore(runes []rune, ps int) bool {
	s := ps
	for s > 0 && ps-s < 8 && runes[s-1] != '\n' {
		s--
	}
	return foundingDateRe.MatchString(strings.TrimRight(string(runes[s:ps]), " 　"))
}

// bankWordRe は口座のスパンが銀行の情報を含むことを示す語。
var bankWordRe = regexp.MustCompile(`銀行|信金|信用金庫|信用組合|労働金庫|農協|ゆうちょ|支店|出張所|普通|当座|貯蓄|口座`)

// embeddedInWord は runes[ps:pe] が片仮名語または英数字の識別子の途中にあるかを返す。
// 漢字は「佐藤様」のように氏名の直後に漢字が続くのが普通なので対象にしない。
func embeddedInWord(runes []rune, ps, pe int) bool {
	same := func(a, b rune) bool {
		switch {
		case isKatakana(a):
			return isKatakana(b)
		case a < unicode.MaxASCII && (unicode.IsLetter(a) || unicode.IsDigit(a) || a == '_'):
			return b < unicode.MaxASCII && (unicode.IsLetter(b) || unicode.IsDigit(b) || b == '_')
		}
		return false
	}
	return (ps > 0 && same(runes[ps], runes[ps-1])) || (pe < len(runes) && same(runes[pe-1], runes[pe]))
}

func isKatakana(r rune) bool { return unicode.Is(unicode.Katakana, r) || r == 'ー' }

// orgWordRe は NAME のスパンが人名ではなく組織名であることを示す語（片仮名表記を含む）。
var orgWordRe = regexp.MustCompile(`銀行|信用金庫|信用組合|株式会社|有限会社|合同会社|支店|ギンコウ|シンキン|シンヨウ|ロウキン|カブシキ|ユウゲン|ゴウドウ|ガイシヤ|ガイシャ|シテン|バンク`)

// digitRunRe は数字列（全角を含む。区切りのハイフンは口座番号の書式側で確かめる）。
var digitRunRe = regexp.MustCompile(`[0-9０-９][0-9０-９-]*[0-9０-９]`)

// honorifics は 1 文字の姓の直後に続く敬称。
var honorifics = []string{"さん", "様", "さま", "氏", "君", "くん", "ちゃん", "先生", "殿"}

func honorificAt(runes []rune, pos int) bool {
	rest := string(runes[pos:min(len(runes), pos+3)])
	for _, h := range honorifics {
		if strings.HasPrefix(rest, h) {
			return true
		}
	}
	return false
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// capitalizedWords は s が大文字で始まる 2 文字以上の英単語 2〜4 語だけからなるかを返す。
func capitalizedWords(s string) bool {
	f := strings.Fields(s)
	if len(f) < 2 || len(f) > 4 {
		return false
	}
	for _, w := range f {
		if len(w) < 2 || !unicode.IsUpper(rune(w[0])) {
			return false
		}
		for _, r := range w[1:] {
			if !unicode.IsLower(r) {
				return false
			}
		}
	}
	return true
}

// romajiName は s が「姓 名」または「名 姓」の 2 語で、両方がローマ字の姓・名の辞書に
// 一致するかを返す（先頭は大文字でも小文字でもよい）。
func romajiName(s string) bool {
	f := strings.Fields(s)
	if len(f) != 2 {
		return false
	}
	a, b := strings.ToLower(f[0]), strings.ToLower(f[1])
	for _, w := range f {
		for _, r := range w {
			if !unicode.IsLetter(r) {
				return false
			}
		}
	}
	return (dict.IsRomajiGivenName(a) && dict.IsRomajiSurname(b)) ||
		(dict.IsRomajiSurname(a) && dict.IsRomajiGivenName(b))
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
				if id, cs, ce, ok := confirmSpan(sp, runes, ps, pe); ok {
					ps, pe := cs, ce
					value := string(runes[ps:pe])
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
