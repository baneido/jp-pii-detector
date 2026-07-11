package privatecorpus

import (
	"strings"
	"testing"
)

func TestDecodeStrictAndVersioned(t *testing.T) {
	c, err := Decode(strings.NewReader(`{
  "schema_version": 1,
  "dataset_id": "eval-v1",
  "dataset": [{"id":"case-1","line":"canary","want":["rule"]}]
}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.DatasetID != "eval-v1" || len(c.Dataset) != 1 {
		t.Fatalf("decoded metadata mismatch: id=%q cases=%d", c.DatasetID, len(c.Dataset))
	}
}

func TestDecodeRejectsUnknownFieldAndEmptyDataset(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown": `{"schema_version":1,"dataset_id":"v1","dataset":[{"line":"x"}],"typo":true}`,
		"empty":   `{"schema_version":1,"dataset_id":"v1","dataset":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(raw)); err == nil {
				t.Fatal("Decode accepted invalid corpus")
			}
		})
	}
}

func TestFromEnvDistinguishesUnsetAndBroken(t *testing.T) {
	t.Setenv(EnvVar, "")
	if _, configured, err := FromEnv(); configured || err != nil {
		t.Fatalf("unset: configured=%t err=%v", configured, err)
	}

	t.Setenv(EnvVar, t.TempDir()+"/missing.json")
	if _, configured, err := FromEnv(); !configured || err == nil {
		t.Fatalf("broken: configured=%t err=%v", configured, err)
	}
}
