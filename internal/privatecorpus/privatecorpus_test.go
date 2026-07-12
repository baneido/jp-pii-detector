package privatecorpus

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/corpusv2"
	"github.com/baneido/jp-pii-detector/internal/evalcase"
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

func TestDecodeUpgradesPublishedV2KnownTestPAN(t *testing.T) {
	pan := strings.Join([]string{"4242", "4242", "4242", "4242"}, "")
	raw := fmt.Sprintf(`{
  "schema_version": 1,
  "dataset_id": "private-eval-v2",
  "dataset": [{
    "id":"legacy-test-pan",
    "source_class":"legacy-curated",
    "line":"card: %s",
    "want":["credit-card"],
    "spans":[{"rule_id":"credit-card","line":1,"start":6,"end":22}]
  }]
}`, pan)
	c, err := Decode(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Dataset[0].Want) != 0 || len(c.Dataset[0].Spans) != 0 {
		t.Fatalf("公開済みv2のテストPANが正例のまま残った: %+v", c.Dataset[0])
	}
	positive := 0
	for _, item := range c.Dataset {
		for _, id := range item.Want {
			if id == "credit-card" {
				positive++
				break
			}
		}
	}
	if positive < corpusv2.MinPositiveCasesPerRule {
		t.Fatalf("credit-card positives = %d, want >= %d", positive, corpusv2.MinPositiveCasesPerRule)
	}
}

func TestMigrateLegacyDropsStringPoolAndAddsAnonymousMetadata(t *testing.T) {
	legacy := &Corpus{
		SchemaVersion: CurrentSchemaVersion,
		DatasetID:     "legacy",
		Strings:       map[string]string{"unused": "private-canary"},
		Dataset: []evalcase.Case{
			{Line: "canary"},
			{ID: "preserved", SourceClass: "manual", Line: "canary-2"},
		},
	}
	migrated, err := MigrateLegacy(legacy, "private-eval-2026-07-v1", "legacy-curated")
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Strings != nil {
		t.Fatal("legacy strings pool must not be copied")
	}
	if migrated.Dataset[0].ID != "private-case-0001" || migrated.Dataset[0].SourceClass != "legacy-curated" {
		t.Fatalf("anonymous metadata not assigned: %+v", migrated.Dataset[0])
	}
	if migrated.Dataset[1].ID != "preserved" || migrated.Dataset[1].SourceClass != "manual" {
		t.Fatalf("existing metadata changed: %+v", migrated.Dataset[1])
	}

	path := filepath.Join(t.TempDir(), "corpus.json")
	if err := WriteNew(path, migrated); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	if err := WriteNew(path, migrated); err == nil {
		t.Fatal("WriteNew overwrote an existing file")
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
