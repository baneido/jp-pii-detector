package eval

import (
	"testing"

	"github.com/baneido/jp-pii-detector/internal/privatecorpus"
)

func TestConfidenceCalibrationAcceptance(t *testing.T) {
	corpus := privatecorpus.Require(t)
	for _, profile := range PublishedProfiles {
		rows, err := EvaluateConfidenceCalibrationCases(corpus.Dataset, profile.Options)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			threshold := confidenceAcceptanceThreshold(row.Confidence)
			if threshold == 0 {
				continue
			}
			t.Logf("profile=%s confidence=%s TP=%d FP=%d precision=%.4f lower95=%.4f",
				profile.ID, row.Confidence, row.TP, row.FP, row.Precision, row.Lower95)
			if row.TP+row.FP == 0 {
				t.Errorf("profile=%s confidence=%s: sample is empty", profile.ID, row.Confidence)
			} else if row.Precision < threshold {
				t.Errorf("profile=%s confidence=%s: precision %.4f < acceptance %.4f",
					profile.ID, row.Confidence, row.Precision, threshold)
			}
		}
	}
}
