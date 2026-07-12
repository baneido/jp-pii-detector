package eval

import "testing"

func TestEvaluateConfidenceCalibrationCases(t *testing.T) {
	cases := []Case{
		{
			Line:  "contact: user@gmail.com", // jp-pii-detector:ignore
			Spans: []Span{{RuleID: "email-address", Line: 1, Start: 9, End: 23}},
		},
		{
			Line: "debug: randomperson@gmail.com", // jp-pii-detector:ignore
		},
		{
			Line:  "口座番号: 1234567", // jp-pii-detector:ignore
			Spans: []Span{{RuleID: "jp-bank-account", Line: 1, Start: 6, End: 13}},
		},
	}
	got, err := EvaluateConfidenceCalibrationCases(cases, Options{MinConfidence: "low"})
	if err != nil {
		t.Fatal(err)
	}
	byConfidence := map[string]ConfidenceCalibration{}
	for _, row := range got {
		byConfidence[row.Confidence] = row
	}
	if high := byConfidence["high"]; high.TP != 1 || high.FP != 1 || high.Precision != 0.5 || high.Lower95 <= 0 || high.Lower95 >= high.Precision {
		t.Errorf("high = %+v", high)
	}
	if medium := byConfidence["medium"]; medium.TP != 1 || medium.FP != 0 || medium.Precision != 1 || medium.Lower95 <= 0 || medium.Lower95 >= medium.Precision {
		t.Errorf("medium = %+v", medium)
	}
}

func TestWilsonLower95EmptySample(t *testing.T) {
	if got := wilsonLower95(0, 0); got != 0 {
		t.Fatalf("wilsonLower95(0, 0) = %f, want 0", got)
	}
}
