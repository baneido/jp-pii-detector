package detect

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/rule"
)

// testPathDirs はダミーデータが集中しやすいディレクトリ名（パス区切り単位の
// 完全一致で判定する）。部分一致にすると "despecial" のような無関係な
// ディレクトリを誤って拾うため、セグメント単位で比較する。
var testPathDirs = map[string]bool{
	"testdata":  true,
	"fixtures":  true,
	"__tests__": true,
	"spec":      true,
	"mocks":     true,
	"seed":      true,
	"seeds":     true,
}

// testPathFileRe はテスト専用ファイルのファイル名パターン（*_test.go /
// *.spec.* / *.test.*）。
var testPathFileRe = regexp.MustCompile(`(?:_test\.go$|\.spec\.|\.test\.)`)

// isTestPath はパスがテストデータ・テストコード専用の場所を指しているかを
// 返す。testdata/ 配下や *_test.go のように、実運用データが載る可能性が低い
// パスを識別するための**シグナル**であり、除外（除外は allowlist /
// jp-pii-detector:ignore の役目）ではない点に注意する。この判定結果は
// 特定ルールの信頼度を 1 段階下げる用途にのみ使い、検出そのものを消さない
// （テストフィクスチャに実在の PII が誤って貼られた場合でも --min-confidence
// low を指定すれば見える）。
func isTestPath(path string) bool {
	clean := filepath.ToSlash(path)
	for _, seg := range strings.Split(clean, "/") {
		if testPathDirs[seg] {
			return true
		}
	}
	return testPathFileRe.MatchString(filepath.Base(clean))
}

// pathDemotionEligible は f がテスト経路信頼度降格の対象になり得るかを返す。
//
// 対象は「RequireContext: true かつ Base（=昇格しない Confidence）が Medium」の
// パターンに限定する（internal/rule/builtin.go の jp-postal-code の桁のみ
// パターン・jp-bank-account・jp-health-insurance が該当）。RequireContext の
// パターンはコンテキストキーワードがあっても昇格しない（scanLineNoIgnoreWithContext
// 参照）ため、f.Confidence は常に Base と一致し、この判定で Base を直接見なくて済む。
//
// Base が High 固定のルール（credit-card・jp-my-number・jp-drivers-license 等）は
// 対象外にする。実データが誤ってテストパスに混入した際の検出力を落とさないためで、
// これは意図的な安全側の判断。
func pathDemotionEligible(f Finding) bool {
	return f.Reason.RequireContext && f.Confidence == rule.Medium
}

// applyPathDemotion はテスト経路の Medium 系検出を Low へ 1 段階だけ降格する
// （既定の min_confidence=medium 運用で非表示になる）。無効化されていれば
// 何もしない。降格後に scanMinConf を下回った finding はここで除外し、
// report 用 minConf だけを下回る場合は --fail-on 判定用として保持する。
func (d *Detector) applyPathDemotion(findings []Finding) []Finding {
	if !d.cfg.Rules.PathDemotion {
		return findings
	}
	out := findings[:0]
	for _, f := range findings {
		if pathDemotionEligible(f) && isTestPath(f.File) {
			f.Confidence = rule.Low
			f.Reason.FinalConfidence = rule.Low.String()
			f.Reason.PathDemoted = true
			finalizeFindingScore(&f)
		}
		if f.Confidence < d.scanMinConf {
			d.recordDropped(f.RuleID, f.File, f.Line, f.Column, DropReasonPathDemotionBelowMin, f.Confidence)
			continue
		}
		if f.Confidence < d.minConf {
			f.failOnly = true
		}
		out = append(out, f)
	}
	return out
}
