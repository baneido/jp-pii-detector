package detect

import (
	"strings"

	"github.com/baneido/jp-pii-detector/internal/normalize"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

const negativeContextWindowRunes = 20

// lineIdx は隣接行相関で検出された finding が乗る行（0 始まり）。前後の
// 論理隣接行（間が空白のみで最大 maxAdjacentLineGap 行差までの非空白行）を
// 見て負コンテキストを判定する。ScanContent の隣接行相関（scanAdjacentLines）が
// 空行を挟んだラベルまで届くようになったのに合わせ、ここも同じ規則で空行を
// スキップしないと、口座番号の直後に空行を挟んだ先に金額の単位（円）が
// 続くようなケースで、負コンテキストによる抑制を取りこぼす。
func (d *Detector) hasCrossLineNegativeContext(f Finding, lines []string, lineContexts []lineContext, lineIdx int) bool {
	if f.negativeContextMode == rule.NegativeContextIgnore || lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}
	var negCtx, posCtx []string
	for _, r := range d.rules {
		if r.ID == f.RuleID {
			negCtx = r.NegativeContext
			posCtx = r.Context
			break
		}
	}
	if len(negCtx) == 0 {
		return false
	}

	var parts []string
	offset := 0
	if p := prevNonBlankIndex(lines, lineIdx, maxAdjacentLineGap); p >= 0 {
		prev := normalize.Line(lines[p])
		parts = append(parts, prev)
		offset = len(prev) + 1 // 改行 1 バイト分
	}
	curr := normalize.Line(lines[lineIdx])
	currRunes := []rune(curr)
	if f.start > len(currRunes) || f.end > len(currRunes) {
		return false
	}
	byteStart := len(string(currRunes[:f.start]))
	byteEnd := len(string(currRunes[:f.end]))

	// 同一文に（負文脈語を伴わない）このルール自身の正ラベルが明示されている
	// 場合は、隣接行にある一般的な負文脈語（金額単位・件数等）で誤って棄却
	// しない（正ラベル優先。issue #68 段階1(a)）。値自身のラベルが id/count 等の
	// 負文脈語を伴う場合は対象外で、この経路に到達する前に呼び出し側
	// （scanLineNoIgnoreWithContext の hasNegativeNear）で既に棄却されている。
	if lineIdx < len(lineContexts) {
		st := lineContexts[lineIdx].statementFor(byteStart, byteEnd)
		if d.statementHasCleanPositiveLabel(st, posCtx) {
			return false
		}
	}

	parts = append(parts, curr)
	if n := nextNonBlankIndex(lines, lineIdx, maxAdjacentLineGap); n >= 0 {
		parts = append(parts, normalize.Line(lines[n]))
	}

	combined := strings.Join(parts, "\n")
	// 隣接行を同一視してチェックするため改行を空白に置き換える。
	// 改行と空白は両方とも 1 バイトなのでオフセットは変わらない。
	combined = strings.ReplaceAll(combined, "\n", " ")
	var runes []rune
	return d.hasNegativeContextNear(combined, offset+byteStart, offset+byteEnd, negativeContextWindowRunes, &runes, negCtx, posCtx, f.negativeContextMode)
}

// statementHasCleanPositiveLabel は st がこのルール自身の Context キーワードに
// 一致する正ラベルを持ち、かつ負文脈語（NegativeText、例: id・count 等）を
// 伴わないかを返す。true の場合、呼び出し側は近傍の一般的な負文脈語（金額単位・
// 件数等）で値を誤って棄却しないでよい（正ラベル優先）。
//
// bankAccountId のように正ラベルの語（account 等）を含みつつも id 等の負文脈語を
// 伴うラベルは対象外とし、その場合は従来通り NegativeText による棄却を優先する
// （呼び出し側で個別にチェックする）。
func (d *Detector) statementHasCleanPositiveLabel(st *statementContext, ctx []string) bool {
	if st == nil || st.PositiveText == "" || st.NegativeText != "" {
		return false
	}
	return len(d.matchingContexts(st.PositiveText, ctx)) > 0
}

// hasNegativeContextNear は kws（ルールの NegativeContext）を近接判定クラス
// ごとに評価する。posCtx はこのルール自身の正文脈語（Rule.Context）で、
// NegativeKeywordLabelPrefix の語が 1 つでも kws に含まれる場合、明示語彙の
// 一致とは別に 1 回だけ実行する「採番ラベル接尾辞ヒューリスティック」
// （hasNumberingSuffixBefore）の保護規則判定に使う。
//
// mode が NegativeContextAdjacentLabelOnly の場合は
// hasNegativeContextNearAdjacentLabelOnly に委譲し、採番ラベル接頭クラスの
// 明示語彙が値に直接隣接する場合だけを判定する（汎用窓語・通貨・カウンタ・
// 接尾辞ヒューリスティックは適用しない）。それ以外（NegativeContextAll。
// NegativeContextIgnore は呼び出し側で既にこの関数を呼ばない前提）は
// 従来どおり全クラスを評価する。
func (d *Detector) hasNegativeContextNear(s string, start, end, radius int, runes *[]rune, kws []string, posCtx []string, mode rule.NegativeContextMode) bool {
	if *runes == nil {
		*runes = []rune(s)
	}
	rs := *runes
	runeStart := len([]rune(s[:start]))
	runeEnd := runeStart + len([]rune(s[start:end]))

	if mode == rule.NegativeContextAdjacentLabelOnly {
		return hasNegativeContextNearAdjacentLabelOnly(rs, runeStart, radius, kws)
	}

	var generic []string
	sawLabelPrefix := false
	for _, kw := range kws {
		switch rule.ClassifyNegativeKeyword(kw) {
		case rule.NegativeKeywordCurrencyPrefix:
			// 通貨記号（¥100）は値の直前に厳密隣接する場合のみ抑制する
			// （空白・タブ以外は挟まない。hasUnitBefore）。
			if hasUnitBefore(rs, runeStart, radius, []rune(kw)) {
				return true
			}
		case rule.NegativeKeywordLabelPrefix:
			sawLabelPrefix = true
			// 採番ラベル（伝票番号 100... 等）は値の直前隣接で抑制するが、
			// 助詞・コロン等の「グルー」を挟んだ表記ゆれも許容する
			// （hasLabelBefore、hasUnitBefore とは別関数）。
			if hasLabelBefore(rs, runeStart, radius, []rune(kw)) {
				return true
			}
		case rule.NegativeKeywordCurrencySuffix:
			if hasUnitAfter(rs, runeEnd, radius, []rune(kw), false) {
				return true
			}
		case rule.NegativeKeywordCounterSuffix:
			if hasUnitAfter(rs, runeEnd, radius, []rune(kw), true) {
				return true
			}
		default:
			generic = append(generic, kw)
		}
	}
	// 明示語彙のどれとも一致しなかった場合でも、このルールが採番ラベル
	// 接頭クラスの語を語彙に持つなら、語彙にない未知の採番風ラベル
	// （「ジョブID:」「受付ID」等）を接尾辞形状だけで拾う。1 回限りの判定。
	if sawLabelPrefix && d.hasNumberingSuffixBefore(rs, runeStart, radius, posCtx) {
		return true
	}
	if len(generic) == 0 {
		return false
	}
	return d.containsAnyContext(contextWindow(s, start, end, radius, runes), generic)
}

// hasNegativeContextNearAdjacentLabelOnly は NegativeContextAdjacentLabelOnly
// 用の制限版判定。kws のうち採番ラベル接頭クラス
// （rule.NegativeKeywordLabelPrefix）に分類される**明示語彙**だけを対象に、
// 値への直接隣接（hasLabelBefore。助詞・コロン・イコールのグルーは許容）を
// 判定する。汎用窓語・通貨接頭/接尾・カウンタ接尾の各クラスと、採番ラベル
// 接尾辞ヒューリスティック（hasNumberingSuffixBefore）は一切呼ばない。
//
// 接尾辞ヒューリスティックを呼ばない理由: 「お客様番号 090-XXXX-XXXX」の
// ような正当な電話番号のラベルは「番号」で終わるため、接尾辞判定を適用すると
// 実電話番号が誤って棄却（FN 化）される。明示語彙（sku・型番等）への直接
// 隣接に限定すれば、電話番号のような肯定文脈が必須ではないルールでも安全に
// 適用できる。
func hasNegativeContextNearAdjacentLabelOnly(rs []rune, runeStart, radius int, kws []string) bool {
	for _, kw := range kws {
		if rule.ClassifyNegativeKeyword(kw) != rule.NegativeKeywordLabelPrefix {
			continue
		}
		if hasLabelBefore(rs, runeStart, radius, []rune(kw)) {
			return true
		}
	}
	return false
}

func hasUnitBefore(rs []rune, start, radius int, unit []rune) bool {
	if len(unit) == 0 {
		return false
	}
	i := start - 1
	from := start - radius
	if from < 0 {
		from = 0
	}
	for i >= from && (rs[i] == ' ' || rs[i] == '\t') {
		i--
	}
	unitStart := i - len(unit) + 1
	if unitStart < from {
		return false
	}
	return runesEqual(rs[unitStart:i+1], unit)
}

// labelGlueMaxCount は hasLabelBefore が値の直前で読み飛ばす「グルー文字」
// （助詞・区切り）の最大個数。連続する別の語や文全体を読み飛ばさないよう
// 小さく抑える。
const labelGlueMaxCount = 2

// labelGlueMaxSkipRunes は hasLabelBefore / hasNumberingSuffixBefore が値の
// 直前から後方に読み飛ばす空白・タブ・グルー文字の合計ルーン数の上限。
// negativeContextWindowRunes（20）より小さく取り、離れた場所の別のラベルまで
// 誤って隣接とみなさないようにする。
const labelGlueMaxSkipRunes = 8

// isLabelGlueRune は hasLabelBefore が空白・タブに加えて読み飛ばす「グルー
// 文字」かどうかを返す。助詞（は/が/の/を/も）と区切り（: =）が対象。
// normalize.Line が全角コロン・イコールを半角化済みのため ASCII だけで足りる。
func isLabelGlueRune(r rune) bool {
	switch r {
	case 'は', 'が', 'の', 'を', 'も', ':', '=':
		return true
	}
	return false
}

// skipLabelGlue は値の直前（start-1）から後方へ、空白・タブは任意個、
// グルー文字（isLabelGlueRune）は最大 labelGlueMaxCount 個まで読み飛ばした
// 位置を返す。数字はスキップ対象に含まれないため、別の値をまたいで
// ラベルを探すことはない。合計スキップ数は labelGlueMaxSkipRunes で
// 打ち切り、radius（from）も超えない。hasLabelBefore と
// hasNumberingSuffixBefore（採番ラベル接尾辞ヒューリスティック）が共有する。
func skipLabelGlue(rs []rune, start, from int) int {
	i := start - 1
	glueUsed := 0
	for n := 0; i >= from && n < labelGlueMaxSkipRunes; n++ {
		if rs[i] == ' ' || rs[i] == '\t' {
			i--
			continue
		}
		if glueUsed < labelGlueMaxCount && isLabelGlueRune(rs[i]) {
			glueUsed++
			i--
			continue
		}
		break
	}
	return i
}

// hasLabelBefore は採番ラベル接頭クラス（伝票番号・受付番号・型番 等）専用の
// 隣接判定。hasUnitBefore（空白・タブしか読み飛ばさない厳密隣接）と異なり、
// skipLabelGlue で助詞・コロン・イコールも読み飛ばしてから比較するため、
// 「受付番号は123456000007です」（助詞「は」で途切れる）や「ジョブID: …」
// （ASCII 語 ID とコロンで途切れる…もっともこちらは "ジョブ" と "ID" の間に
// グルーがないため一致せず、接尾辞ヒューリスティック側に委ねられる）、
// 「型番: TK1234567」（コロン+空白）のような表記ゆれもラベルとして認識する。
// ASCII ラベル（sku/version/ver）は runesEqualASCIIFold で大小文字を区別
// しない（"SKU:" も一致させる）。
func hasLabelBefore(rs []rune, start, radius int, unit []rune) bool {
	if len(unit) == 0 {
		return false
	}
	from := start - radius
	if from < 0 {
		from = 0
	}
	i := skipLabelGlue(rs, start, from)
	unitStart := i - len(unit) + 1
	if unitStart < from {
		return false
	}
	return runesEqualASCIIFold(rs[unitStart:i+1], unit)
}

// numberingSuffixMaxTokenRunes は接尾辞ヒューリスティックが後方に読む
// ラベルトークンの最大ルーン数。
const numberingSuffixMaxTokenRunes = 12

// numberingSuffixMinTokenRunes 未満のトークンは不成立とする。裸の
// 「ID:」「No.」のような 2 ルーンだけのラベルで抑制しないための下限。
const numberingSuffixMinTokenRunes = 3

// numberingSuffixesJA / numberingSuffixesASCII はトークン末尾に現れれば
// 採番ラベルとみなす接尾辞。ASCII 側は大小文字を区別しない。
var (
	numberingSuffixesJA    = []string{"番号", "コード", "キー"}
	numberingSuffixesASCII = []string{"id", "code", "key", "sku", "no"}
)

// hasNumberingSuffixBefore は「採番ラベル接尾辞ヒューリスティック」。ルールの
// NegativeContext に採番ラベル接頭クラスの語が 1 つでもある場合、明示語彙に
// 完全一致しない未知のラベル（「ジョブID:」「受付ID」等、ASCII 語や省略形が
// 挟まって数値番/文脈語の直接一致に届かないもの）も、ラベルの「形」だけで
// 拾って抑制する。誤って正当なラベル（郵便番号・口座番号・免許証番号 等）
// まで抑制しないよう、保護規則（d.containsAnyContext による posCtx 判定）を
// 必ず通す。
func (d *Detector) hasNumberingSuffixBefore(rs []rune, start, radius int, posCtx []string) bool {
	from := start - radius
	if from < 0 {
		from = 0
	}
	i := skipLabelGlue(rs, start, from)
	if i < from {
		return false
	}

	// 接尾辞判定・境界規則は「空白で途切れる」厳格なトークンで行う
	// （「Zip code」の "code" のように、直前の別単語まで結合して誤判定
	// しないようにするため）。
	tokenStart := readTokenBackward(rs, i, from, numberingSuffixMaxTokenRunes, isNumberingTokenRune)
	token := rs[tokenStart : i+1]
	if len(token) < numberingSuffixMinTokenRunes {
		return false
	}
	suffixLen, isASCIISuffix, ok := numberingSuffixMatch(token)
	if !ok {
		return false
	}
	if isASCIISuffix && !asciiSuffixBoundaryOK(token, suffixLen) {
		return false
	}

	// 保護規則（最重要）: ラベル自体にこのルール本来の正しい肯定文脈語
	// （posCtx = Rule.Context）が含まれる場合は抑制しない。「免許証番号」
	// （免許）・「郵便番号」（郵便）・「口座番号」（口座）・「在留カード番号」
	// （在留）・「パスポート番号」（パスポート）・「被保険者番号」（被保険者）
	// のように、接尾辞ヒューリスティックは「番号」「id」等の形だけでラベルを
	// 判定するため、これらの正当なラベルまで誤って抑制してしまう副作用が
	// 大きい。これを防ぐガード。
	//
	// 判定の走査は空白・タブも跨いで良い（isNumberingProtectionScanRune）。
	// 「要介護認定 被保険者番号」「Zip code」のように、値の正当なラベルが
	// 複数語からなり空白で区切られている場合に、その空白でラベルが分断され
	// て保護規則を素通りしてしまわないようにするための拡張スキャンで、
	// 抑制方向にしか効かない（保護されるケースが広がるだけで、新たに抑制
	// されることはない）。d.containsAnyContext（matchingContexts 経由）を
	// 再利用することで、日本語の部分一致だけでなく "bankAccountNo" のような
	// camelCase 識別子が "account_no"/"bank account" 等のトークン化された
	// 正文脈語を含む場合も正しく保護できる（素朴な部分文字列一致では
	// 見逃す）。
	//
	// 走査幅は numberingSuffixMaxTokenRunes（12、ラベル自体を切り出す語彙側の
	// 判定用）ではなく radius（呼び出し元は negativeContextWindowRunes=20）を
	// 使う。12 だと、正文脈語がラベルの直近ではなく地の文を挟んで少し手前に
	// 来る自然な日本語の文（例:「介護保険の…に記載された被保険者番号は…です」で
	// jp-kaigo-insurance の正文脈語「介護保険」が直近のラベル「被保険者番号」から
	// 12 ルーンを超えて離れる）で保護が届かず、この接尾辞ヒューリスティック自体が
	// 新規に追加するまで検出できていた値を誤って抑制する回帰になる
	// （jp-kaigo-insurance は Context に「被保険者」を持たないため、「被保険者
	// 番号」という値直前のラベルだけでは保護規則がそもそも成立しない）。この
	// 関数は保護方向にしか働かないため（上記コメント参照）、走査幅を radius まで
	// 広げても新たな誤抑制は生まない。回帰再現・固定は
	// TestNumberingSuffixHeuristicProtectionReachesDistantOwnLabel
	// （detect_test.go）参照。
	protScanStart := readTokenBackward(rs, i, from, max(radius, numberingSuffixMaxTokenRunes), isNumberingProtectionScanRune)
	if d.containsAnyContext(string(rs[protScanStart:i+1]), posCtx) {
		return false
	}
	return true
}

// readTokenBackward は位置 i（含む）から後方へ、allowed を満たすルーンが
// 連続する限り最大 maxRunes 個読み取り、その先頭位置（含む）を返す。
// from（radius 由来の下限）を超えては読まない。
func readTokenBackward(rs []rune, i, from, maxRunes int, allowed func(rune) bool) int {
	limitFrom := i - maxRunes + 1
	if limitFrom < from {
		limitFrom = from
	}
	j := i
	for j >= limitFrom && allowed(rs[j]) {
		j--
	}
	return j + 1
}

// isNumberingTokenRune は接尾辞ヒューリスティックがラベルトークンの構成
// 文字とみなす文字種か（漢字[拡張Aを含む U+3400-9FFF]・〇・ひらがな・
// カタカナ[長音ー含む]・ASCII 英数字・アンダースコア）を返す。空白は
// 含まないため、複数語からなるラベルの末尾の単語だけがトークンになる。
func isNumberingTokenRune(r rune) bool {
	switch {
	case r == '〇':
		return true
	case isKanji(r):
		return true
	case r >= 0x3041 && r <= 0x3096: // ひらがな
		return true
	case (r >= 0x30A1 && r <= 0x30FA) || r == 0x30FC: // カタカナ（長音ー含む）
		return true
	case r == '_':
		return true
	case r >= '0' && r <= '9', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		return true
	}
	return false
}

// isNumberingProtectionScanRune は保護規則専用の走査で使う、
// isNumberingTokenRune に空白・タブを加えた文字種。接尾辞・境界の判定には
// 使わず、保護規則（hasNumberingSuffixBefore 内の d.containsAnyContext
// 判定）にのみ使う。
func isNumberingProtectionScanRune(r rune) bool {
	return isNumberingTokenRune(r) || r == ' ' || r == '\t'
}

// numberingSuffixMatch は token が採番ラベル接尾辞（numberingSuffixesJA /
// numberingSuffixesASCII）のいずれかで終わるかを判定し、一致した接尾辞の
// ルーン数と、それが ASCII 接尾辞かどうかを返す。ASCII 側は大小文字を
// 区別しない。
func numberingSuffixMatch(token []rune) (suffixLen int, isASCIISuffix bool, ok bool) {
	for _, s := range numberingSuffixesJA {
		sr := []rune(s)
		if len(sr) <= len(token) && runesEqual(token[len(token)-len(sr):], sr) {
			return len(sr), false, true
		}
	}
	for _, s := range numberingSuffixesASCII {
		sr := []rune(s)
		if len(sr) <= len(token) && runesEqualASCIIFold(token[len(token)-len(sr):], sr) {
			return len(sr), true, true
		}
	}
	return 0, false, false
}

// asciiSuffixBoundaryOK は ASCII 接尾辞（id/code/key/sku/no）の直前境界を
// 判定する。直前が ASCII 小文字の場合、接尾辞自体が大文字始まりの
// camelCase 境界（orderNo, orderId, ジョブID 等）でない限り不成立とする
// （casino/piano の "no"、userid の "id" を採番ラベルと誤認しないため）。
// 直前が `_`・数字・非 ASCII・トークン先頭の場合は常に成立する
// （shipment_id、受付id 等）。
func asciiSuffixBoundaryOK(token []rune, suffixLen int) bool {
	prevIdx := len(token) - suffixLen - 1
	if prevIdx < 0 {
		return true // トークン先頭
	}
	prev := token[prevIdx]
	if prev < 'a' || prev > 'z' {
		return true
	}
	first := token[len(token)-suffixLen]
	return first >= 'A' && first <= 'Z' // camelCase 境界
}

// runesEqualASCIIFold は runesEqual と同じだが ASCII 英字の大小差を無視する。
// sku/version/ver のような ASCII ラベルを大文字表記（SKU 等）でも
// 一致させるために使う。
func runesEqualASCIIFold(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if asciiFold(a[i]) != asciiFold(b[i]) {
			return false
		}
	}
	return true
}

// asciiFold は ASCII 英大文字だけを小文字に変換する（他の文字はそのまま）。
func asciiFold(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

func hasUnitAfter(rs []rune, end, radius int, unit []rune, requireBoundary bool) bool {
	if len(unit) == 0 {
		return false
	}
	i := end
	to := end + radius
	if to > len(rs) {
		to = len(rs)
	}
	for i < to && (rs[i] == ' ' || rs[i] == '\t') {
		i++
	}
	unitEnd := i + len(unit)
	if unitEnd > to || !runesEqual(rs[i:unitEnd], unit) {
		return false
	}
	// requireBoundary はカウンタ接尾語（件・人 等）専用。直後が漢字なら
	// 「件名」「名義」のような漢字複合語の一部とみなし、単位としては
	// 扱わない（境界不成立）。ひらがな（件に/件が/件を のような助詞続き）や
	// 記号・行末は単位として独立しているとみなし、抑制を適用する。
	return !requireBoundary || unitEnd == len(rs) || !isKanji(rs[unitEnd])
}

func runesEqual(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// isKanji は CJK 統合漢字（拡張 A を含む）かどうかを返す。ひらがな・
// カタカナはここに含めない（hasUnitAfter の requireBoundary が、助詞続き
// （件に/件が 等）と漢字複合語（件名 等）を区別するために使う）。
func isKanji(r rune) bool {
	return r >= 0x3400 && r <= 0x9fff
}
