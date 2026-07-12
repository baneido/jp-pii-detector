// Package corpusv2 は非公開評価コーパスv1を、Issue #128の品質要件を満たす
// v2へ決定的に拡充する。生成値は収集データではなく、由来をsource_class/tagsで
// 明示する。出力本文はGCSだけに保存し、このパッケージは件数と構築ロジックだけを持つ。
package corpusv2

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/checksum"
	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/dict"
	"github.com/baneido/jp-pii-detector/internal/evalcase"
	"github.com/baneido/jp-pii-detector/internal/normalize"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

const MinPositiveCasesPerRule = 10

// Summary は本文を含まないv2構築結果。
type Summary struct {
	BaseCases       int
	TotalCases      int
	PositiveCases   int
	NegativeCases   int
	AddedPositives  int
	AddedNegatives  int
	SpanlessPairs   int
	PerRulePositive map[string]int
}

// Build はv1ケースをコピーし、span補完・陽性不足補完・hard negative追加を行う。
func Build(base []evalcase.Case) ([]evalcase.Case, Summary, error) {
	low, err := newDetector(false)
	if err != nil {
		return nil, Summary{}, err
	}
	high, err := newDetector(true)
	if err != nil {
		return nil, Summary{}, err
	}

	cases := cloneCases(base)
	seed := corpusSeed(base)
	for i := range cases {
		if cases[i].SourceClass == "" {
			cases[i].SourceClass = "legacy-curated"
		}
		cases[i].Tags = appendUnique(cases[i].Tags, "source:"+cases[i].SourceClass)
		reclassifyKnownTestPAN(&cases[i])
		if err := annotateCase(low, high, &cases[i]); err != nil {
			return nil, Summary{}, fmt.Errorf("既存case %s: %w", safeID(cases[i]), err)
		}
	}

	addedPositive, err := fillPositiveCoverage(&cases, seed, allRuleIDs(), low, high)
	if err != nil {
		return nil, Summary{}, err
	}

	hard := hardNegativeCases(seed)
	for i := range hard {
		hard[i].ID = fmt.Sprintf("v2-hard-negative-%03d", i+1)
		hard[i].SourceClass = "hard-negative"
		hard[i].Tags = appendUnique(hard[i].Tags, "source:hard-negative", "polarity:negative")
	}
	cases = append(cases, hard...)

	if err := ensureUnique(cases); err != nil {
		return nil, Summary{}, err
	}
	if err := evalcase.Validate(cases); err != nil {
		return nil, Summary{}, err
	}
	spanless := spanlessPairs(cases)
	if spanless != 0 {
		return nil, Summary{}, fmt.Errorf("span未付与の陽性(rule,case)が%d件残っています", spanless)
	}
	positive := 0
	for _, c := range cases {
		if len(c.Want) > 0 || len(c.Spans) > 0 {
			positive++
		}
	}
	return cases, Summary{
		BaseCases:       len(base),
		TotalCases:      len(cases),
		PositiveCases:   positive,
		NegativeCases:   len(cases) - positive,
		AddedPositives:  addedPositive,
		AddedNegatives:  len(hard),
		SpanlessPairs:   spanless,
		PerRulePositive: positiveCounts(cases),
	}, nil
}

// UpgradePublishedV2 は、旧v2で正例扱いだった公知sandbox PANを陰性へ
// 再分類し、jp-address第3エントリ追加後にWant帰属が古くなったケースを
// jp-addressへ読み替え（reassignLabeledNoPrefectureAddressWant参照）、
// 後から追加した高再現率ルールを含む不足正例を既存の決定的合成器で補う。
// GCS objectを更新せずに固定generationを現行ルールの評価契約へ読み替える
// 互換migrationで、
// 入力を変更せず、同じ入力からは常に同じ出力を返す。
func UpgradePublishedV2(input []evalcase.Case) ([]evalcase.Case, error) {
	low, err := newDetector(false)
	if err != nil {
		return nil, err
	}
	high, err := newDetector(true)
	if err != nil {
		return nil, err
	}

	cases := cloneCases(input)
	seed := corpusSeed(input)
	for i := range cases {
		reclassifyKnownTestPAN(&cases[i])
		reassignLabeledNoPrefectureAddressWant(&cases[i])
	}
	// この互換migrationで不足しうるルールだけを補い、他ルールの
	// データ品質不備を暗黙に修復しない。jp-address-high-recallは、上の
	// reassignLabeledNoPrefectureAddressWantでnative陽性の一部をjp-addressへ
	// 帰属し直した分だけ不足しうるため、他の互換migration対象と同様にここへ
	// 加える（合成陽性は既にラベルなし形のため、この読み替えとは衝突しない。
	// positiveCandidatesの"jp-address-high-recall"節を参照）。既にMinPositiveCasesPerRule
	// 以上あるコーパスに対してはfillPositiveCoverageが何も追加しないため、
	// このルールを常にidsへ含めても既存の合成陽性件数は変わらない。
	upgradeRuleIDs := []string{"credit-card", "email-address-confusable", "email-address-eai", "jp-address-high-recall"}
	if _, err := fillPositiveCoverage(&cases, seed, upgradeRuleIDs, low, high); err != nil {
		return nil, err
	}
	if err := ensureUnique(cases); err != nil {
		return nil, err
	}
	if err := evalcase.Validate(cases); err != nil {
		return nil, err
	}
	if spanless := spanlessPairs(cases); spanless != 0 {
		return nil, fmt.Errorf("span未付与の陽性(rule,case)が%d件残っています", spanless)
	}
	return cases, nil
}

// reassignLabeledNoPrefectureAddressWant は、旧 jp-address-high-recall 単独陽性
// ケースのうち、PR #148 で jp-address に追加された第 3 エントリ（都道府県なし・
// ラベル必須住所）が新たに検出するようになった値を、jp-address の陽性へ
// 帰属し直す（true を返す）。対象外なら false を返し、c は変更しない。
//
// なぜコーパス本体を書き換えず、コードで読み替えるのか:
// private-eval-v2（このリポジトリの外、GCS 管理下の固定 generation）には
// 「ラベル付き・都道府県なし住所」の陽性ケースが実在し、PR #148 より前は
// この形を検出できる組み込みルールが jp-address-high-recall（high-recall
// 限定）しかなかったため、Want はそのルールに固定されていた。PR #148 で
// jp-address に第 3 エントリが入り、既定プロファイルでも同じ値を検出できる
// ようになった結果、resolveOverlaps は同一スパンで prior の無い jp-address 側を
// 常に優先するようになった（internal/rule/builtin.go の jp-address 第 3
// エントリのコメント参照）。検出そのものの変化は意図どおりだが、コーパス側の
// Want 帰属が旧ルールのまま古くなっているため、low/medium/high-recall の
// 全プロファイルで jp-address の FindingFP と jp-address-high-recall の FN が
// 対になって発生してしまう（帰属衝突であって精度劣化ではない）。コーパス本体は
// 非公開かつ GCS 管理の固定 generation のため本リポジトリから直接編集できず、
// また編集すべきでもない（オプションな dataset_id を固定したまま評価契約を
// 変えないため）。UpgradePublishedV2 はまさにこの「コード側で決定的に
// コーパスを読み替える」ための互換migration層であり、この関数はその 1 ステップ。
//
// 述語（すべて満たす場合だけ書き換える）:
//  1. c.Want がちょうど 1 要素で "jp-address-high-recall"
//     （複数ルールへの陽性ケースは、他ルールの帰属まで巻き添えで変えないよう
//     安全側で対象外にする）。
//  2. c が Line 入力（Content/Diff ケースは対象外）。ScanContent /
//     ScanDiffHunk は隣接行昇格・CSV 列文脈・diff の追加行限定報告など
//     Line 単体の判定では再現できない経路を持つため、この移行が想定する
//     「単純な 1 行、ラベル+値」の形に安全側で絞る。
//  3. normalize.Line(c.Line) が rule.MatchesLabeledNoPrefectureAddress
//     （jp-address 第 3 エントリと同一の正規表現・Validate を再利用した
//     判定。internal/rule/builtin.go 参照）を満たす。判定ロジック自体は
//     internal/rule 側を単一の情報源とし、ここでは再実装しない。
//
// 書き換え内容: Want を ["jp-address"] に差し替え、既存 Spans のうち
// RuleID == "jp-address-high-recall" のものだけを "jp-address" に書き換える
// （Start/End/Line/Tags/WantConfidence 等、RuleID 以外のフィールドは不変）。
//
// 決定性: 乱数・時刻を使わず、c の既存フィールド（Want/Line/Content/Diff/
// Spans）だけを見て判定するため、同じ入力からは常に同じ結果になる。
func reassignLabeledNoPrefectureAddressWant(c *evalcase.Case) bool {
	if len(c.Want) != 1 || c.Want[0] != "jp-address-high-recall" {
		return false
	}
	if c.Line == "" || c.Content != "" || len(c.Diff) > 0 {
		return false
	}
	if !rule.MatchesLabeledNoPrefectureAddress(normalize.Line(c.Line)) {
		return false
	}
	c.Want = []string{"jp-address"}
	for i := range c.Spans {
		if c.Spans[i].RuleID == "jp-address-high-recall" {
			c.Spans[i].RuleID = "jp-address"
		}
	}
	return true
}

func fillPositiveCoverage(cases *[]evalcase.Case, seed int, ids []string, low, high *detect.Detector) (int, error) {
	counts := positiveCounts(*cases)
	usedIDs := make(map[string]bool, len(*cases))
	usedInputs := make(map[string]bool, len(*cases))
	for _, c := range *cases {
		usedIDs[c.ID] = true
		usedInputs[caseInputKey(c)] = true
	}

	added := 0
	for _, id := range ids {
		nextOrdinal := counts[id] + 1
		for _, candidate := range positiveCandidates(id, seed) {
			if counts[id] >= MinPositiveCasesPerRule {
				break
			}
			if usedInputs[caseInputKey(candidate)] {
				continue
			}
			for {
				candidate.ID = fmt.Sprintf("v2-%s-%03d", id, nextOrdinal)
				nextOrdinal++
				if !usedIDs[candidate.ID] {
					break
				}
			}
			candidate.SourceClass = "curated-v2"
			candidate.Tags = appendUnique(candidate.Tags,
				"source:curated-v2", "polarity:positive", "rule:"+id)
			if err := annotateCase(low, high, &candidate); err != nil {
				continue // 候補語彙が辞書と合わない場合は次の決定的候補を試す。
			}
			*cases = append(*cases, candidate)
			usedIDs[candidate.ID] = true
			usedInputs[caseInputKey(candidate)] = true
			counts[id]++
			added++
		}
		if counts[id] < MinPositiveCasesPerRule {
			return 0, fmt.Errorf("rule %s の陽性候補が%d件しか成立しません（必要%d件）",
				id, counts[id], MinPositiveCasesPerRule)
		}
	}
	return added, nil
}

// reclassifyKnownTestPAN はcredit-cardの期待spanが公知sandbox PANに一致する
// 場合だけ、その期待を陰性へ読み替える。他ルールの期待や未知のLuhn妥当値は
// 変更しない。
func reclassifyKnownTestPAN(c *evalcase.Case) bool {
	hadCreditSpan := false
	hasRemainingCreditSpan := false
	changed := false
	spans := c.Spans[:0]
	for _, span := range c.Spans {
		if span.RuleID != "credit-card" {
			spans = append(spans, span)
			continue
		}
		hadCreditSpan = true
		value, ok := caseSpanText(*c, span)
		if ok && checksum.KnownTestPAN(digitsOnly(value)) {
			changed = true
			continue
		}
		hasRemainingCreditSpan = true
		spans = append(spans, span)
	}
	c.Spans = spans

	removeWant := changed && !hasRemainingCreditSpan
	if !hadCreditSpan && hasWant(*c, "credit-card") && caseContainsKnownTestPAN(*c) {
		removeWant = true
		changed = true
	}
	if removeWant {
		want := c.Want[:0]
		for _, id := range c.Want {
			if id != "credit-card" {
				want = append(want, id)
			}
		}
		c.Want = want
	}
	if changed {
		c.Tags = appendUnique(c.Tags, "scenario:known-test-pan")
		if len(c.Want) == 0 && len(c.Spans) == 0 {
			c.Tags = removeTag(c.Tags, "polarity:positive")
			c.Tags = appendUnique(c.Tags, "polarity:negative")
		}
	}
	return changed
}

func hasWant(c evalcase.Case, id string) bool {
	for _, got := range c.Want {
		if got == id {
			return true
		}
	}
	return false
}

func caseSpanText(c evalcase.Case, span evalcase.Span) (string, bool) {
	lines := caseLines(c)
	line := span.Line
	if line == 0 {
		line = 1
	}
	if line < 1 || line > len(lines) {
		return "", false
	}
	runes := []rune(lines[line-1])
	if span.Start < 0 || span.End < span.Start || span.End > len(runes) {
		return "", false
	}
	return string(runes[span.Start:span.End]), true
}

func caseContainsKnownTestPAN(c evalcase.Case) bool {
	for _, line := range caseLines(c) {
		digits := digitsOnly(line)
		for width := 13; width <= 19; width++ {
			for start := 0; start+width <= len(digits); start++ {
				if checksum.KnownTestPAN(digits[start : start+width]) {
					return true
				}
			}
		}
	}
	return false
}

func caseLines(c evalcase.Case) []string {
	switch {
	case len(c.Diff) > 0:
		lines := make([]string, len(c.Diff))
		for i, line := range c.Diff {
			lines[i] = line.Text
		}
		return lines
	case c.Content != "":
		return strings.Split(c.Content, "\n")
	default:
		return []string{c.Line}
	}
}

func digitsOnly(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func caseInputKey(c evalcase.Case) string {
	input := struct {
		File    string
		Line    string
		Content string
		Diff    []evalcase.DiffLine
	}{c.File, c.Line, c.Content, c.Diff}
	b, _ := json.Marshal(input)
	return string(b)
}

func removeTag(tags []string, remove string) []string {
	out := tags[:0]
	for _, tag := range tags {
		if tag != remove {
			out = append(out, tag)
		}
	}
	return out
}

func newDetector(highRecall bool) (*detect.Detector, error) {
	cfg, err := config.Parse(fmt.Sprintf("min_confidence = %q\n[rules]\nhigh_recall = %t\n", "low", highRecall))
	if err != nil {
		return nil, err
	}
	return detect.New(cfg)
}

func annotateCase(low, high *detect.Detector, c *evalcase.Case) error {
	expected := map[string]bool{}
	for _, id := range c.Want {
		expected[id] = true
	}
	for i := range c.Spans {
		expected[c.Spans[i].RuleID] = true
		if c.Spans[i].WantConfidence == "" {
			c.Spans[i].WantConfidence = "medium"
		}
	}
	if len(expected) == 0 {
		return nil
	}
	highIDs := map[string]bool{}
	for _, id := range rule.HighRecallRuleIDs() {
		highIDs[id] = true
	}
	d := low
	for id := range expected {
		if highIDs[id] {
			d = high
			break
		}
	}
	findings := scanCase(d, *c)
	hasSpan := map[string]bool{}
	for _, span := range c.Spans {
		hasSpan[span.RuleID] = true
	}
	for id := range expected {
		if hasSpan[id] {
			continue
		}
		found := 0
		for _, finding := range findings {
			if finding.RuleID != id {
				continue
			}
			start := finding.Column - 1
			c.Spans = append(c.Spans, evalcase.Span{
				RuleID:         id,
				Line:           finding.Line,
				Start:          start,
				End:            start + utf8.RuneCountInString(finding.Match),
				WantConfidence: "medium",
			})
			found++
		}
		if found == 0 {
			return fmt.Errorf("期待rule %sの検出がなくspanを補完できません", id)
		}
	}
	sort.Slice(c.Spans, func(i, j int) bool {
		if c.Spans[i].Line != c.Spans[j].Line {
			return c.Spans[i].Line < c.Spans[j].Line
		}
		if c.Spans[i].Start != c.Spans[j].Start {
			return c.Spans[i].Start < c.Spans[j].Start
		}
		return c.Spans[i].RuleID < c.Spans[j].RuleID
	})
	return nil
}

func scanCase(d *detect.Detector, c evalcase.Case) []detect.Finding {
	file := c.File
	if file == "" {
		file = "dataset.txt"
	}
	switch {
	case len(c.Diff) > 0:
		lines := make([]detect.DiffLine, len(c.Diff))
		for i, line := range c.Diff {
			lines[i] = detect.DiffLine{Text: line.Text, Added: line.Added}
		}
		return d.ScanDiffHunk(file, lines)
	case c.Content != "":
		return d.ScanContent(file, c.Content)
	default:
		return d.ScanLine(file, 1, c.Line)
	}
}

func allRuleIDs() []string {
	seen := map[string]bool{}
	var ids []string
	for _, r := range rule.Builtin() {
		if !seen[r.ID] {
			seen[r.ID] = true
			ids = append(ids, r.ID)
		}
	}
	for _, id := range rule.HighRecallRuleIDs() {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func positiveCandidates(id string, seed int) []evalcase.Case {
	var out []evalcase.Case
	postalCodes := dict.SamplePostalCodes(30)
	romanizedNames := romajiNames()
	for i := 0; i < 30; i++ {
		d := digitRun(seed+i+17, 20)
		// 公開テストでも使われる代表的な合成名。ケース識別子を値の外へ置き、
		// コーパス内の完全重複を避ける。
		name := syntheticFullName()
		casePrefix := fmt.Sprintf("case_id=%02d ", i+1)
		switch id {
		case "jp-my-number":
			switch i {
			case 0:
				// ドット区切り6-6（区切り表記ゆれ新パターンの合成ポジティブ）。
				num := myNumber(seed + i)
				out = append(out, lineCase("マイナンバー: "+num[:6]+"."+num[6:]))
			default:
				out = append(out, lineCase("マイナンバー: "+myNumber(seed+i)))
			}
		case "jp-phone-number":
			value := "090-" + d[:4] + "-" + d[4:8]
			switch i {
			case 0:
				out = append(out, evalcase.Case{File: "added.txt", Diff: []evalcase.DiffLine{{Text: "TEL: " + value, Added: true}}, Tags: []string{"layout:diff"}})
			case 1:
				out = append(out, evalcase.Case{File: "user.json", Content: "{\n  \"phone\": \"" + value + "\"\n}", Tags: []string{"file-format:json", "layout:content"}})
			case 2:
				// 保護系ポジティブ（NegativeContextAdjacentLabelOnly の保護規則
				// 固定）。「お客様番号」は「番号」で終わるが numberingLabelPrefixes
				// の明示語彙のどれとも完全一致しないため、採番ラベル接尾辞
				// ヒューリスティックを適用しない AdjacentLabelOnly では誤って
				// 抑制されない、採番風だが電話の実値。
				out = append(out, lineCase("お客様番号 "+value))
			default:
				out = append(out, lineCase("TEL: "+value))
			}
		case "jp-postal-code":
			if len(postalCodes) > i {
				code := postalCodes[i]
				out = append(out, lineCase("郵便番号: "+code[:3]+"-"+code[3:]))
			}
		case "jp-address":
			switch i {
			case 0:
				// ラベル付き都道府県なし形（jp-address 第 3 エントリの合成ポジティブ）。
				// 神南は実在町字（dict.MunicipalityThenTownMatch）のため High twin が
				// 成立するはず。
				out = append(out, lineCase("住所: 渋谷区神南1-2-3")) // jp-pii-detector:ignore
			case 1:
				// 同じくラベル付き都道府県なし形だが、市区町村直後が ABR 町字マスターに
				// 存在しない語（架空坂。TestPromotionContextWindowBoundary と同じ、
				// 町字マスターに前方一致しない架空の町名）で、町字辞書昇格 twin ではなく
				// 市区町村レベルの辞書ゲートだけに依存する形をあわせて確認する。
				out = append(out, lineCase("住所: 渋谷区架空坂1-2-3")) // jp-pii-detector:ignore
			default:
				out = append(out, lineCase(fmt.Sprintf("住所: 東京都渋谷区神南%d丁目%d番%d号", i%9+1, i%20+1, i%15+1)))
			}
		case "email-address":
			out = append(out, lineCase("連絡先: corpusv2-"+digitRun(seed+i+90, 8)+"@baneido.com"))
		case "email-address-eai":
			// 文字列を分割し、dogfood がコーパス構築コード自体を PII として
			// 報告しないようにする。実行時には日本語ローカル部の EAI になる。
			out = append(out, lineCase("連絡先: 利用者"+digitRun(seed+i+90, 4)+"@"+"baneido.com"))
		case "email-address-confusable":
			// キリル小文字 s（U+0455）を ASCII 中心ローカル部へ 1 文字だけ混入。
			out = append(out, lineCase("連絡先: u"+"ѕ"+"er"+digitRun(seed+i+90, 4)+"@"+"baneido.com"))
		case "credit-card":
			out = append(out, lineCase("カード番号: "+group(cardNumber(seed+i), []int{4, 4, 4, 4}, "-")))
		case "jp-drivers-license":
			out = append(out, lineCase("免許証番号: "+strconv.Itoa(30+i%20)+d[:10]))
		case "jp-passport":
			out = append(out, lineCase("パスポート番号: AB"+d[:7]))
		case "jp-pension-number":
			out = append(out, lineCase("基礎年金番号: "+d[:4]+"-"+d[4:10]))
		case "jp-residence-card":
			out = append(out, lineCase("在留カード番号: AB"+d[:8]+"CD"))
		case "jp-bank-account":
			switch i {
			case 0:
				// 空白区切り（3+4、区切り表記ゆれ新パターンの合成ポジティブ）。
				out = append(out, lineCase("口座番号: "+d[:3]+" "+d[3:7]))
			default:
				out = append(out, lineCase("口座番号: "+d[:7]))
			}
		case "jp-yucho-account":
			number := d[4:10] + "1"
			symbol := yuchoSymbol("1"+d[:2], number)
			out = append(out, lineCase("ゆうちょ銀行 記号"+symbol+"-"+number))
		case "jp-birthdate":
			out = append(out, lineCase(fmt.Sprintf("生年月日: %d年%d月%d日", 1970+i%35, i%12+1, i%27+1)))
		case "jp-health-insurance":
			out = append(out, lineCase("健康保険 保険者番号: "+d[:8]))
		case "jp-employment-insurance":
			out = append(out, lineCase("雇用保険被保険者番号: "+d[:4]+"-"+d[4:10]+"-"+d[10:11]))
		case "jp-kaigo-insurance":
			out = append(out, lineCase("介護保険 被保険者証番号: "+d[:10]))
		case "jp-juminhyo-code":
			out = append(out, lineCase("住民票コード: "+d[:11]))
		case "jp-invoice-number":
			out = append(out, lineCase("インボイス登録番号: T"+corporateNumber(d[:12])))
		case "person-name":
			out = append(out, lineCase(casePrefix+"氏名: "+name))
		case "jp-address-high-recall":
			// ラベルなし形（jp-address 第 3 エントリはラベル必須のため、この形には
			// 発火しない）。ラベル付きのまま（旧「住所: 渋谷区神南N-N-N」）だと、
			// 新しい jp-address 第 3 エントリが同じ値を検出し、high-recall
			// プロファイルで Want=jp-address-high-recall のケースに jp-address が
			// 帰属して row FP/FN が発生する（internal/rule/builtin.go の jp-address
			// 第 3 エントリのコメント参照）。
			out = append(out, lineCase(fmt.Sprintf("渋谷区神南%d-%d-%d", i%9+1, i%20+1, i%15+1)))
		case "person-name-high-recall":
			out = append(out, lineCase(casePrefix+"担当: "+name))
		case "person-name-structured":
			switch i % 3 {
			case 0:
				out = append(out, evalcase.Case{File: "form.txt", Content: casePrefix + "\n氏名:\n" + name, Tags: []string{"layout:content"}})
			case 1:
				out = append(out, evalcase.Case{File: "people.csv", Content: "氏名,メモ\n" + name + "," + casePrefix, Tags: []string{"file-format:csv", "layout:content"}})
			case 2:
				out = append(out, evalcase.Case{File: "dump.sql", Content: "INSERT INTO users (氏名, memo) VALUES ('" + name + "', '" + casePrefix + "');", Tags: []string{"file-format:sql", "layout:content"}})
			}
		case "person-name-romaji":
			romaji := romanizedNames[i%len(romanizedNames)]
			if i%3 == 0 {
				out = append(out, evalcase.Case{File: "person.json", Content: fmt.Sprintf("{\"case_id\": %d, \"full_name\": \"%s\"}", i+1, romaji), Tags: []string{"file-format:json", "layout:content"}})
			} else {
				out = append(out, lineCase(casePrefix+"full_name: "+romaji))
			}
		}
	}
	for i := range out {
		out[i].Want = []string{id}
	}
	return out
}

// yuchoSymbol は先頭 3 桁と末尾固定 0 から、公式式を満たす検査数字を
// 4 桁目へ付与する。評価値は収集した実値ではなく決定的に合成する。
func yuchoSymbol(first3, number string) string {
	for check := byte('0'); check <= '9'; check++ {
		symbol := first3 + string(check) + "0"
		if checksum.YuchoAccount(symbol, number) {
			return symbol
		}
	}
	panic("ゆうちょ記号の検査数字を生成できません")
}

func hardNegativeCases(seed int) []evalcase.Case {
	out := make([]evalcase.Case, 0, 40)
	add := func(family, text string) {
		out = append(out, evalcase.Case{Line: text, Tags: []string{"scenario:hard-negative-" + family}})
	}
	for i, label := range []string{"受注ID", "受付番号", "トランザクション", "shipment_id=", "管理キー"} {
		// 12桁業務IDが偶然マイナンバーの検査数字を満たす既知FP系統。
		add("business-id", label+" "+myNumber(seed+500+i)+" を処理")
	}
	// 負文脈「隣接ラベル」判定のグルー許容（hasLabelBefore）と採番ラベル
	// 接尾辞ヒューリスティック（hasNumberingSuffixBefore）が対象とする
	// 表記ゆれ（助詞・コロン・イコールでラベルと値が途切れる形）を、上の
	// 空白区切り系統に加えて評価コーパスにも反映する。
	add("business-id", "受付番号は"+myNumber(seed+920)+"です")
	add("business-id", "ジョブID: "+myNumber(seed+921))
	add("business-id", "発注コード="+myNumber(seed+922))
	add("business-id", "管理キー: "+myNumber(seed+923))
	add("model", "海外パスポート対応 型番: TK"+digitRun(seed+924, 7))
	testPANs := wellKnownTestPANs()
	for i, label := range []string{"決済sandboxのテストカード", "payment fixture", "QA用PAN", "テスト決済", "カードブランド試験"} {
		add("test-pan", label+" "+testPANs[i])
	}
	for i, label := range []string{"リビジョン", "リリース"} {
		add("revision", fmt.Sprintf("%s %d-%s-%d をデプロイ", label, 2024+i, digitRun(seed+800+i, 6), i+3))
	}
	for i, label := range []string{"部品ロット", "製造ロット"} {
		add("lot", fmt.Sprintf("%s %s-%s-%d", label, digitRun(seed+820+i, 4), digitRun(seed+830+i, 6), i+4))
	}
	add("model", "在留カード対応リーダー 型番 AB"+digitRun(seed+840, 8)+"CD")
	add("model", "パスポート対応ケース 製品コード TK"+digitRun(seed+841, 7))
	add("money", "売上は"+digitRun(seed+850, 7)+"円です")
	add("money", "保険料"+digitRun(seed+851, 10)+"円を集計")
	add("count", "総件数は"+digitRun(seed+860, 8)+"件")
	add("count", "利用者"+digitRun(seed+861, 10)+"人の統計")
	add("date", fmt.Sprintf("処理日: %d-%02d-%02d", 2024, 4, 1))
	add("date", fmt.Sprintf("build %d-%s-%d", 2024, digitRun(seed+870, 6), 7))
	add("phone-like", "電話機SKU: 090-"+digitRun(seed+880, 4)+"-"+digitRun(seed+881, 4)+" (test model)")
	add("phone-like", "電話API version: 03-"+digitRun(seed+882, 4)+"-"+digitRun(seed+883, 4)+" (alpha)")
	postalCodes := dict.SamplePostalCodes(2)
	for i, label := range []string{"商品コード", "章番号"} {
		code := postalCodes[i]
		add("postal-like", "郵便発送の"+label+" "+code[:3]+"-"+code[3:]+"-REV")
	}
	add("account-like", "連番ID "+digitRun(seed+890, 7))
	add("account-like", "注文番号 "+digitRun(seed+891, 7))
	add("insurance-like", "ハッシュ "+digitRun(seed+900, 10)+"abcdef")
	add("insurance-like", "sequence="+digitRun(seed+901, 10))
	invoice := "T" + corporateNumber(digitRun(seed+910, 12))
	add("invoice-like", "型番 "+invoice+"X")
	add("invoice-like", "sample invoice "+invoice)
	name := syntheticFullName()
	romaji := strings.Join([]string{"Yamada", "Tarou"}, " ")
	add("name-like", "project_name: "+name)
	add("name-like", "商品名: "+name+"モデル")
	add("name-like", "filename: "+romaji)
	add("name-like", "project-name: "+romaji)
	add("address-like", fmt.Sprintf("通学区域%d丁目%d番%d号", 1, 2, 3))
	add("address-like", fmt.Sprintf("バージョン東京都版%d-%d-%d", 1, 2, 3))
	add("reserved-email", "連絡先 "+"user@"+"example.com")
	add("reserved-email", "メール "+"user@"+"foo.invalid")
	// #46 と同型の区切り表記ゆれ追加対応（本タスク）で導入した新パターンに
	// 対応する hard negative。RequireContext・NegativeContext・ValidateLine の
	// いずれかで正しく非検出になることを固定する。
	add("phone-url-slash", "https://example.com/090/"+digitRun(seed+940, 4)+"/"+digitRun(seed+941, 4))
	add("phone-url-slash", "api/v2/090/"+digitRun(seed+942, 4)+"/"+digitRun(seed+943, 4))
	add("phone-date-slash", fmt.Sprintf("更新日: %d/%02d/%02d", 2024, 4, 1))
	add("phone-version-mixed", "バージョン 0."+digitRun(seed+944, 4)+"-"+digitRun(seed+945, 4))
	add("mynumber-decimal", "value = "+digitRun(seed+946, 6)+"."+digitRun(seed+947, 6))
	add("mynumber-decimal", "個人番号"+digitRun(seed+948, 6)+"."+digitRun(seed+949, 6)+"円")
	add("bank-space-chain", "口座番号 "+digitRun(seed+950, 3)+" "+digitRun(seed+951, 4)+" "+digitRun(seed+952, 4))
	add("health-insurance-space-chain", "保険者番号 "+digitRun(seed+953, 4)+" "+digitRun(seed+954, 4)+" "+digitRun(seed+955, 4))
	return out
}

func lineCase(line string) evalcase.Case {
	return evalcase.Case{Line: line, Tags: []string{"layout:line"}}
}

func digitRun(seed, n int) string {
	var b strings.Builder
	for counter := 0; b.Len() < n; counter++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("jp-pii-private-corpus-v2:%d:%d", seed, counter)))
		for _, v := range sum {
			if b.Len() == n {
				break
			}
			b.WriteByte('0' + v%10)
		}
	}
	return b.String()
}

func corpusSeed(base []evalcase.Case) int {
	b, _ := json.Marshal(base)
	sum := sha256.Sum256(b)
	return int(binary.BigEndian.Uint32(sum[:4]) % 1_000_003)
}

func myNumber(seed int) string {
	base := digitRun(seed+71, 11)
	sum := 0
	for n := 1; n <= 11; n++ {
		p := int(base[11-n] - '0')
		q := n + 1
		if n >= 7 {
			q = n - 5
		}
		sum += p * q
	}
	check := 11 - sum%11
	if check >= 10 {
		check = 0
	}
	return base + strconv.Itoa(check)
}

func cardNumber(seed int) string {
	payload := "4" + digitRun(seed+101, 14)
	return payload + strconv.Itoa(luhnCheckDigit(payload))
}

func luhnCheckDigit(payload string) int {
	sum := 0
	double := true
	for i := len(payload) - 1; i >= 0; i-- {
		d := int(payload[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return (10 - sum%10) % 10
}

func corporateNumber(base12 string) string {
	sum := 0
	for n := 1; n <= 12; n++ {
		p := int(base12[12-n] - '0')
		q := 1
		if n%2 == 0 {
			q = 2
		}
		sum += p * q
	}
	return strconv.Itoa(9-sum%9) + base12
}

func group(value string, widths []int, sep string) string {
	parts := make([]string, 0, len(widths))
	start := 0
	for _, width := range widths {
		parts = append(parts, value[start:start+width])
		start += width
	}
	return strings.Join(parts, sep)
}

func romajiNames() []string {
	pairs := [][2]string{
		{"Yamada", "Tarou"}, {"Tarou", "Yamada"}, {"Suzuki", "Hanako"},
		{"Satou", "Ichirou"}, {"Tanaka", "Kenta"}, {"Takahashi", "Misaki"},
		{"Itou", "Sakura"}, {"Watanabe", "Yuuki"}, {"Yamamoto", "Naoki"},
		{"Nakamura", "Akira"}, {"Kobayashi", "Haruka"}, {"Katou", "Megumi"},
		{"Yoshida", "Tsubasa"}, {"Yamaguchi", "Nanami"}, {"Matsumoto", "Satoshi"},
	}
	out := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		out = append(out, strings.Join(pair[:], " "))
	}
	return out
}

func syntheticFullName() string {
	return strings.Join([]string{"山田", "太郎"}, "")
}

// wellKnownTestPANs は決済事業者のsandboxで公知の非稼働番号だけを返す。
// 任意のLuhn妥当値を陰性扱いすると、偶然実在する番号を「偽陽性」と誤ラベルするため、
// hard negativeではこの集合に限定する。完全な番号リテラルはソースへ置かない。
func wellKnownTestPANs() []string {
	parts := [][]string{
		{"4111", "1111", "1111", "1111"},
		{"4242", "4242", "4242", "4242"},
		{"5555", "5555", "5555", "4444"},
		{"3782", "8224", "6310", "005"},
		{"3530", "1113", "3330", "0000"},
	}
	out := make([]string, 0, len(parts))
	for _, item := range parts {
		out = append(out, strings.Join(item, ""))
	}
	return out
}

func positiveCounts(cases []evalcase.Case) map[string]int {
	counts := map[string]int{}
	for _, c := range cases {
		ids := map[string]bool{}
		for _, id := range c.Want {
			ids[id] = true
		}
		for _, span := range c.Spans {
			ids[span.RuleID] = true
		}
		for id := range ids {
			counts[id]++
		}
	}
	return counts
}

func spanlessPairs(cases []evalcase.Case) int {
	n := 0
	for _, c := range cases {
		has := map[string]bool{}
		for _, span := range c.Spans {
			has[span.RuleID] = true
		}
		for _, id := range c.Want {
			if !has[id] {
				n++
			}
		}
	}
	return n
}

func ensureUnique(cases []evalcase.Case) error {
	ids := map[string]bool{}
	content := map[string]bool{}
	for i, c := range cases {
		if c.ID == "" || ids[c.ID] {
			return fmt.Errorf("dataset[%d]のIDが空または重複しています", i)
		}
		ids[c.ID] = true
		copy := c
		copy.ID = ""
		b, _ := json.Marshal(copy)
		key := string(b)
		if content[key] {
			return fmt.Errorf("dataset[%d]が完全重複しています", i)
		}
		content[key] = true
	}
	return nil
}

func cloneCases(in []evalcase.Case) []evalcase.Case {
	b, _ := json.Marshal(in)
	var out []evalcase.Case
	_ = json.Unmarshal(b, &out)
	return out
}

func appendUnique(dst []string, values ...string) []string {
	seen := map[string]bool{}
	for _, value := range dst {
		seen[value] = true
	}
	for _, value := range values {
		if value != "" && !seen[value] {
			dst = append(dst, value)
			seen[value] = true
		}
	}
	return dst
}

func safeID(c evalcase.Case) string {
	if c.ID == "" {
		return "idなし"
	}
	return c.ID
}
