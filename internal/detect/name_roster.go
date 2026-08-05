package detect

import (
	"strings"

	"github.com/baneido/jp-pii-detector/internal/normalize"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// ラベルも敬称も無く、氏名だけが改行区切りで並ぶファイル（名簿・宛名リスト）は、
// 行単位の手がかりを 1 つも持たないため、他のどの経路でも検出できない。
// person-name 系のルールはすべてラベルか敬称をアンカーにしており、姓名辞書の
// 照合は「アンカーがあったときの絞り込み」としてしか使われていないためである。
//
// ここでは行ではなくファイル全体を単位に判定する。「行全体が氏名の形をしていて、
// かつ姓名辞書で姓+名に分割できる行」が、非空行の中で一定割合を超えたときだけ、
// そのファイルを名簿とみなして該当行を報告する。
//
// この割合の閾値が、辞書ファイルのような「氏名と同形の語が少数混ざる大きな
// リスト」との切り分けになる。実測では internal/dict/towns.txt（非空 95,007 行の
// 町字名）で氏名行として成立するのは 184 行（約 0.19%）にとどまるため、50% の
// 閾値では名簿と判定されない。
//
// 行単位の根拠がゼロである以上、既定でも --high-recall でも有効にはしない。
// 専用の opt-in（[rules] name_roster / --name-roster）でのみ動く。

const (
	// rosterMinNames は名簿とみなすのに必要な、姓名辞書を通った行の最小数。
	// 1〜2 行では「たまたま氏名と同形の語が並んだ」ケースと区別できない。
	rosterMinNames = 3
	// rosterMinRatioNumerator / rosterMinRatioDenominator は、非空行に占める
	// 氏名行の割合の下限（= 1/2）。整数演算で比較するために分子・分母で持つ。
	rosterMinRatioNumerator   = 1
	rosterMinRatioDenominator = 2
)

// rosterNameLine は 1 行が名簿の氏名行として成立するかを判定し、成立するなら
// 正規化済みの行と値のバイト範囲を返す。行全体が氏名であることを要求するため、
// 判定には CrossLineNameValueRe（行全体アンカー）をそのまま使う。
// 行末コメント（jp-pii-detector:ignore を含む）が付いた行はこのアンカーに
// 一致しないため、抑制は自動的に効く（scanCrossLineNames と同じ設計）。
func rosterNameLine(line string) (norm string, m []int, ok bool) {
	norm = normalize.Line(line)
	m = rule.CrossLineNameValueRe.FindStringSubmatchIndex(norm)
	if m == nil || m[2] < 0 {
		return "", nil, false
	}
	if !rule.ValidRosterName(norm[m[2]:m[3]]) {
		return "", nil, false
	}
	return norm, m, true
}

// scanNameRosterFile はファイル全体を名簿とみなせる場合に限り、氏名行を
// person-name-roster として報告する。nameRoster が有効なとき（opt-in）だけ
// 呼ばれる。
func (d *Detector) scanNameRosterFile(file string, lines []string) []Finding {
	if rule.Medium < d.scanMinConf {
		return nil
	}
	if d.nameRoster == nil {
		return nil
	}
	type rosterHit struct {
		line int
		norm string
		m    []int
	}
	var hits []rosterHit
	nonBlank := 0
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		nonBlank++
		norm, m, ok := rosterNameLine(line)
		if !ok {
			continue
		}
		hits = append(hits, rosterHit{line: i, norm: norm, m: m})
	}
	if len(hits) < rosterMinNames {
		return nil
	}
	// 割合の判定は allowlist 適用前の hits で行う。allowlist は「この値は
	// 報告しない」という指定であって「この行は氏名ではない」ではないため、
	// 除外された行のぶんだけ名簿らしさが下がるのは筋が通らない。
	if len(hits)*rosterMinRatioDenominator < nonBlank*rosterMinRatioNumerator {
		return nil
	}
	var out []Finding
	for _, h := range hits {
		entity := h.norm[h.m[2]:h.m[3]]
		if d.allowlisted(entity) {
			continue
		}
		// 正規化は 1:1（ルーン数保存）のため、norm 上のルーン位置は元行と一致する。
		rs := len([]rune(h.norm[:h.m[2]]))
		re := rs + len([]rune(entity))
		origRunes := []rune(lines[h.line])
		finding := Finding{
			RuleID:      d.nameRoster.ID,
			Description: d.nameRoster.Description,
			File:        file,
			Line:        h.line + 1,
			Column:      rs + 1,
			Match:       string(origRunes[rs:re]),
			Confidence:  rule.Medium,
			Reason: DetectReason{
				BaseConfidence:  rule.Medium.String(),
				FinalConfidence: rule.Medium.String(),
				Validated:       true,
			},
			start:         rs,
			end:           re,
			scoreEvidence: confidenceScoreEvidence{structuredPair: true},
		}
		finalizeFindingScore(&finding)
		out = append(out, finding)
	}
	return out
}
