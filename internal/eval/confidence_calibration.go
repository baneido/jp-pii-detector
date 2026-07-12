package eval

import (
	"fmt"
	"math"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
)

// ConfidenceCalibration は最終 Confidence ごとの検出単位の実測適合率。
// Lower95 は二項比率の Wilson 95% 信頼区間下限で、少数標本時の過信を避ける。
type ConfidenceCalibration struct {
	Confidence string
	TP         int
	FP         int
	Precision  float64
	Lower95    float64
}

// confidenceAcceptanceThreshold は後方互換段階の no-regression 基準。
// 最新mainでの private-eval-v2 ベースライン（High 97.56%、Medium 92.41%）を下回らず、
// かつ全3プロファイルで満たせる保守的な下限に丸めている。
func confidenceAcceptanceThreshold(confidence string) float64 {
	switch confidence {
	case "high":
		return 0.975
	case "medium":
		return 0.92
	default:
		return 0
	}
}

// EvaluateConfidenceCalibrationCases は期待スパンを包含した finding を TP、
// 対応しない finding を FP として、最終 Confidence ごとに集計する。Confidence
// は「その値が PII か」の確度なので RuleID は問わず、ルール帰属の正しさは既存の
// profile 別 row/span 指標へ委ねる。
// private corpus v2 は全陽性 (case, rule) に span を要求するため、ルール単位の
// 行評価より直接的に「その Confidence で報告した1件」の適合率を測定できる。
func EvaluateConfidenceCalibrationCases(cases []Case, opts Options) ([]ConfidenceCalibration, error) {
	minConfidence := opts.MinConfidence
	if minConfidence == "" {
		minConfidence = "low"
	}
	cfg, err := config.Parse(fmt.Sprintf("min_confidence = %q\n[rules]\nhigh_recall = %t\n",
		minConfidence, opts.HighRecall))
	if err != nil {
		return nil, err
	}
	d, err := detect.New(cfg)
	if err != nil {
		return nil, err
	}

	type counts struct{ tp, fp int }
	byConfidence := map[string]*counts{
		"low": {}, "medium": {}, "high": {},
	}
	for _, c := range cases {
		findings, err := scanCase(d, c)
		if err != nil {
			return nil, err
		}
		gotSpans := make([]Span, 0, len(findings))
		for _, finding := range findings {
			gotSpans = append(gotSpans, spanFromFinding(finding))
		}
		matched := make([]bool, len(findings))
		_, pairs := matchSpans(c.Spans, gotSpans, spansContainedByIgnoringRule)
		for _, gotIndex := range pairs {
			if gotIndex >= 0 {
				matched[gotIndex] = true
			}
		}
		for i, finding := range findings {
			confidence := finding.Confidence.String()
			bucket := byConfidence[confidence]
			if bucket == nil {
				return nil, fmt.Errorf("unknown confidence %q", confidence)
			}
			if matched[i] {
				bucket.tp++
			} else {
				bucket.fp++
			}
		}
	}

	result := make([]ConfidenceCalibration, 0, 3)
	for _, confidence := range []string{"high", "medium", "low"} {
		c := byConfidence[confidence]
		n := c.tp + c.fp
		precision := 0.0
		if n > 0 {
			precision = float64(c.tp) / float64(n)
		}
		result = append(result, ConfidenceCalibration{
			Confidence: confidence,
			TP:         c.tp,
			FP:         c.fp,
			Precision:  precision,
			Lower95:    wilsonLower95(c.tp, n),
		})
	}
	return result, nil
}

func spansContainedByIgnoringRule(want, got Span) bool {
	return spanLine(want) == spanLine(got) && got.Start <= want.Start && got.End >= want.End
}

func wilsonLower95(successes, total int) float64 {
	if total == 0 {
		return 0
	}
	const z = 1.959963984540054
	n := float64(total)
	p := float64(successes) / n
	z2 := z * z
	return (p + z2/(2*n) - z*math.Sqrt((p*(1-p)+z2/(4*n))/n)) / (1 + z2/n)
}
