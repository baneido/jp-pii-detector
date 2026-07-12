package detect

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/rule"
)

func TestConfidenceFromScoreThresholds(t *testing.T) {
	tests := []struct {
		score int
		want  rule.Confidence
	}{{0, rule.Low}, {39, rule.Low}, {40, rule.Medium}, {74, rule.Medium}, {75, rule.High}, {100, rule.High}}
	for _, tt := range tests {
		if got := confidenceFromScore(tt.score); got != tt.want {
			t.Errorf("confidenceFromScore(%d) = %s, want %s", tt.score, got, tt.want)
		}
	}
}

func TestFinalizeFindingScoreAddsSafeEvidenceWithoutChangingConfidence(t *testing.T) {
	plain := Finding{RuleID: "plain", Confidence: rule.Medium}
	validated := Finding{RuleID: "validated", Confidence: rule.Medium, Reason: DetectReason{Validated: true}}
	structured := Finding{
		RuleID: "structured", Confidence: rule.Medium,
		Reason:        DetectReason{Validated: true, ContextKeywords: []string{"phone"}},
		scoreEvidence: confidenceScoreEvidence{structuredContext: true},
	}
	for _, finding := range []*Finding{&plain, &validated, &structured} {
		finalizeFindingScore(finding)
		if finding.Confidence != rule.Medium {
			t.Fatalf("%s confidence = %s, want medium", finding.RuleID, finding.Confidence)
		}
	}
	if !(plain.ConfidenceScore < validated.ConfidenceScore && validated.ConfidenceScore < structured.ConfidenceScore) {
		t.Fatalf("scores = plain:%d validated:%d structured:%d", plain.ConfidenceScore, validated.ConfidenceScore, structured.ConfidenceScore)
	}
}

func TestBetterUsesConfidenceThenScoreThenLengthThenRuleID(t *testing.T) {
	base := Finding{Confidence: rule.Medium, ConfidenceScore: 55, start: 0, end: 4}
	highConfidence := base
	highConfidence.Confidence = rule.High
	highConfidence.ConfidenceScore = 75
	highScore := base
	highScore.ConfidenceScore = 56
	longer := base
	longer.end = 5
	lexical := base
	lexical.RuleID = "a"
	base.RuleID = "b"

	if !better(highConfidence, highScore) {
		t.Error("Confidence should win before score")
	}
	if !better(highScore, longer) {
		t.Error("score should win before length")
	}
	if !better(longer, base) {
		t.Error("length should win after equal score")
	}
	if !better(lexical, base) {
		t.Error("RuleID should be the final deterministic tie-break")
	}
}

func TestContextScoreEvidenceTracksDistanceAndCrossLine(t *testing.T) {
	near := contextScoreEvidenceForMatch("電話: 090", len("電話: "), len("電話: 090"), []string{"電話"}, false)
	far := contextScoreEvidenceForMatch("電話: abcdefghijkl 090", len("電話: abcdefghijkl "), len("電話: abcdefghijkl 090"), []string{"電話"}, false)
	cross := contextScoreEvidenceForMatch("電話:\n090", len("電話:\n"), len("電話:\n090"), []string{"電話"}, false)
	if !near.contextDistanceKnown || !far.contextDistanceKnown || near.contextDistance >= far.contextDistance {
		t.Fatalf("near=%+v far=%+v", near, far)
	}
	if !cross.crossLineContext {
		t.Fatalf("cross=%+v, want crossLineContext", cross)
	}
}

func TestFindingJSONDoesNotExposeConfidenceScore(t *testing.T) {
	b, err := json.Marshal(Finding{RuleID: "test", Confidence: rule.High, ConfidenceScore: 99})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "score") {
		t.Fatalf("Finding JSON exposed internal score: %s", b)
	}
}

func TestScorePrefersSameRecordBoostAndStandardRulePrior(t *testing.T) {
	nearby := Finding{RuleID: "person-name", Confidence: rule.Medium, Reason: DetectReason{CooccurrenceBoosted: true}}
	sameRecord := nearby
	sameRecord.scoreEvidence.sameRecordBoost = true
	standard := Finding{RuleID: "jp-address", Confidence: rule.High, Reason: DetectReason{Validated: true}}
	highRecall := standard
	highRecall.RuleID = "jp-address-high-recall"
	for _, finding := range []*Finding{&nearby, &sameRecord, &standard, &highRecall} {
		finalizeFindingScore(finding)
	}
	if sameRecord.ConfidenceScore <= nearby.ConfidenceScore {
		t.Fatalf("same-record=%d nearby=%d", sameRecord.ConfidenceScore, nearby.ConfidenceScore)
	}
	if standard.ConfidenceScore <= highRecall.ConfidenceScore {
		t.Fatalf("standard=%d high-recall=%d", standard.ConfidenceScore, highRecall.ConfidenceScore)
	}
}
