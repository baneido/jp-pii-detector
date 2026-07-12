package detect

import (
	"fmt"
	"slices"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/external"
	"github.com/baneido/jp-pii-detector/internal/normalize"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// 新規ファイル。既存の ScanContent 等（detect.go）は変更しない
// （DetectReason.External フィールドの追加のみが detect.go への変更）。
// MergeExternalFindings は ScanContent が返した findings を受け取り、
// internal/external.Run が集めた候補（外部レコグナイザ由来）を検証・変換したうえで、
// 通常の検出と同じ resolveOverlapsPerLine / allowlist / min_confidence の決着規則に
// 通してから統合する「ScanContent の後段フック」として動作する。呼び出し側は
// internal/source（フルスキャン）・cmd/jp-pii-detect（--stdin）のみを想定し、
// git diff 経路（ScanDiffHunk）・eval ハーネスは対象外（設計メモ・CLAUDE.md 参照）。

// externalRuleIDSuffix は外部レコグナイザが返す rule_id に必須の接尾辞
// （internal/external のプロトコル仕様）。組み込みルール ID の偽装を防ぐ。
const externalRuleIDSuffix = "-external"

// MergeExternalFindings は file の外部レコグナイザ候補（internal/external.Run が
// 返した Candidate のうち、この file 分。File が一致しないものは無視する）を検証・
// 変換し、findings（通常の検出。呼び出し側が d.ScanContent(file, content) で
// 得たもの）と統合して返す。candidates が空なら findings をそのまま返す
// （呼び出し側のホットパス最適化用。外部レコグナイザ未設定時はこの関数自体が
// 呼ばれないため、無効時のコストはゼロ）。
//
// ScanContent が内部で行う cooccurrence_boost（近傍の高信頼 PII との共起昇格）と
// path_demotion（testdata/ 等の信頼度降格）は、この関数を呼ぶ時点で ScanContent が
// 既に完了しているため、外部候補には適用されない（意図的な v1 のスコープ外。
// 外部候補に適用するのは下記の allowlist・ignore マーカー・min_confidence・
// 重複解決のみ）。
//
// 各候補は次の順で検証し、いずれかで落ちれば「この候補だけ」を破棄する
// （internal/external.Run 自体が返す「この走査回の候補をすべて破棄」判定とは別の、
// 候補単位の意味検証）:
//
//  1. rule_id が externalRuleIDSuffix を持たない候補は破棄する。internal/external は
//     JSON の構造検証のみを行い、この意味検証はしないため、ここが唯一の強制点になる。
//  2. rule_id が [rules] disabled に含まれる候補は破棄する。通常ルールと同じ無効化
//     手段を外部ルールにも適用できるようにするため。
//  3. line・column・length が content の範囲内に収まらない候補は破棄する
//     （子の自己申告位置を信用しない）。
//  4. 値そのものは content から親側で切り出す（プロトコルは値を運ばない）。値が乗る
//     行に ignore マーカー（jp-pii-detector:ignore / 旧 pii-allow）があれば破棄する。
//  5. allowlist（stopword・正規表現）に一致すれば破棄する。
//  6. confidence は受信値をパースし、不正・空なら Low として扱う（破棄はしない）。
//     パース後の値が min_confidence 未満なら破棄する。
//
// 生存した候補は findings と合わせて resolveOverlapsPerLine で重複解決する
// （同一箇所に通常の検出と外部候補が重なった場合、既存の信頼度・範囲優先の決着規則
// がそのまま適用される。外部候補だから優先/劣後するという特別扱いはしない）。
func (d *Detector) MergeExternalFindings(file, content string, findings []Finding, candidates []external.Candidate) []Finding {
	if len(candidates) == 0 {
		return findings
	}
	var lines []string
	for line := range strings.SplitSeq(content, "\n") {
		lines = append(lines, strings.TrimSuffix(line, "\r"))
	}
	var extFindings []Finding
	for _, c := range candidates {
		if c.File != file {
			continue
		}
		if f, ok := d.externalCandidateToFinding(file, lines, c); ok {
			extFindings = append(extFindings, f)
		}
	}
	if len(extFindings) == 0 {
		return findings
	}
	combined := make([]Finding, 0, len(findings)+len(extFindings))
	combined = append(combined, findings...)
	combined = append(combined, extFindings...)
	resolved := resolveOverlapsPerLine(combined)
	d.recordOverlapLosses(combined, resolved)
	return dedupAndSortFindings(resolved)
}

// externalCandidateToFinding は 1 件の external.Candidate を検証し、通過すれば
// Finding へ変換する。MergeExternalFindings のドキュメントコメントに列挙した
// 検証順をそのまま実装する。
func (d *Detector) externalCandidateToFinding(file string, lines []string, c external.Candidate) (Finding, bool) {
	if !strings.HasSuffix(c.RuleID, externalRuleIDSuffix) {
		return Finding{}, false
	}
	if slices.Contains(d.cfg.Rules.Disabled, c.RuleID) {
		return Finding{}, false
	}
	if c.Line < 1 || c.Line > len(lines) {
		return Finding{}, false
	}
	lineText := lines[c.Line-1]
	if c.Column < 1 || c.Length <= 0 {
		return Finding{}, false
	}
	runes := []rune(lineText)
	start := c.Column - 1
	// end := start + c.Length は書かない: c.Length は子プロセスの自己申告値
	// （JSON 由来で任意の int）であり、math.MaxInt 近辺の値を渡されると
	// 加算がオーバーフローして負数に wrap し、後続の「end > len(runes)」チェックを
	// すり抜けたうえで runes[start:end] がスライス境界パニックを起こす
	// （検出器全体をクラッシュさせる DoS になり、「この候補だけを破棄する」という
	// 設計を破る）。加算せずに減算で比較することで、start が既に len(runes) 以下と
	// 分かっている状態からオーバーフローの心配なく検証できる。
	if start > len(runes) || c.Length > len(runes)-start {
		return Finding{}, false
	}
	end := start + c.Length
	// ignore マーカーは値が乗る行（value-bearing line）ごとに判定する。行全体を
	// 対象にする ignoredLine を使うため、ラベルだけの隣接行にマーカーがあっても
	// この判定には影響しない（scanAdjacentLines 等、他の cross-line 経路と同じ原則）。
	if ignoredLine(lineText) {
		return Finding{}, false
	}
	match := string(runes[start:end])
	// allowlist 判定は、切り出した部分文字列を単独で正規化するのではなく、行全体を
	// 正規化してから同じ [start:end] で切り出す（internal/detect の通常の検出経路
	// （scanLineNoIgnoreWithContext 等）が norm := normalize.Line(line) の後に
	// norm[start:end] を使うのと同じ順序に揃える）。normalize.Line の長音記号
	// （ー→-）変換は数字隣接という文脈に依存するため、スパン境界がその文脈を
	// 断ち切る位置にあると、単独正規化では変換されない文字が、行全体正規化では
	// 変換される（またはその逆）ことがある。normalize.Line は 1 ルーン→1 ルーンの
	// 変換が不変条件（CLAUDE.md）なので、正規化後の文字列でも同じ [start:end] が
	// そのまま対応する。
	normEntity := string([]rune(normalize.Line(lineText))[start:end])
	if d.allowlisted(normEntity) {
		return Finding{}, false
	}
	conf, err := rule.ParseConfidence(c.Confidence)
	if err != nil {
		conf = rule.Low
	}
	if conf < d.minConf {
		return Finding{}, false
	}
	finding := Finding{
		RuleID:      c.RuleID,
		Description: externalFindingDescription(c.RuleID),
		File:        file,
		Line:        c.Line,
		Column:      c.Column,
		Match:       match,
		Confidence:  conf,
		Reason: DetectReason{
			FinalConfidence: conf.String(),
			External:        true,
		},
		start: start,
		end:   end,
	}
	finalizeFindingScore(&finding)
	return finding, true
}

// externalFindingDescription は report 出力用の説明文を組み立てる。rule_id から
// externalRuleIDSuffix を取り除いた部分を、子プロセス側が付けた意味のある名前
// （例: "person-name-external" → "person-name"）として表示に添える。
func externalFindingDescription(ruleID string) string {
	base := strings.TrimSuffix(ruleID, externalRuleIDSuffix)
	return fmt.Sprintf("外部レコグナイザによる検出（%s）", base)
}
