package evalcase

import "testing"

func TestValidate(t *testing.T) {
	valid := []Case{{ID: "case-1", Line: "canary", Want: []string{"rule"}}}
	if err := Validate(valid); err != nil {
		t.Fatalf("Validate(valid) error: %v", err)
	}
	for name, cases := range map[string][]Case{
		"empty":      {},
		"two-inputs": {{ID: "case-1", Line: "a", Content: "b"}},
		"duplicate":  {{ID: "same", Line: "a"}, {ID: "same", Line: "b"}},
		"bad-span":   {{ID: "case-1", Line: "a", Spans: []Span{{RuleID: "r", Start: 2, End: 1}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := Validate(cases); err == nil {
				t.Fatal("Validate accepted invalid cases")
			}
		})
	}
}
