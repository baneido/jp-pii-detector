package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/privatecorpus"
)

func TestRunRejectsUnknownCommand(t *testing.T) {
	if err := run([]string{"unknown"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown command accepted")
	}
}

func TestGcloudCopyArgsAreNonInteractiveAndExplicitlyScoped(t *testing.T) {
	t.Setenv(gcloudAccountEnv, "fixture-reader@example.invalid")
	t.Setenv(projectEnv, "fixture-project")
	got := gcloudCopyArgs("gs://bucket/object#123", "/tmp/corpus.json")
	want := []string{
		"storage", "cp", "gs://bucket/object#123", "/tmp/corpus.json", "--quiet",
		"--account=fixture-reader@example.invalid", "--project=fixture-project",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gcloudCopyArgs() = %q, want %q", got, want)
	}
}

func TestMigrateCommandWritesVersionedCorpusWithoutLegacyStrings(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "legacy.json")
	output := filepath.Join(dir, "migrated.json")
	legacy := `{"strings":{"unused":"private-canary"},"dataset":[{"line":"canary"}]}`
	if err := os.WriteFile(input, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"migrate", "-input", input, "-output", output, "-dataset-id", "private-eval-v1"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var corpus privatecorpus.Corpus
	if err := json.Unmarshal(b, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.SchemaVersion != 1 || corpus.DatasetID != "private-eval-v1" || len(corpus.Dataset) != 1 {
		t.Fatalf("unexpected migrated metadata: schema=%d id=%q cases=%d", corpus.SchemaVersion, corpus.DatasetID, len(corpus.Dataset))
	}
	if corpus.Strings != nil || corpus.Dataset[0].ID == "" || corpus.Dataset[0].SourceClass != "legacy-curated" {
		t.Fatal("migration retained legacy strings or omitted anonymous metadata")
	}
}

func TestLoadLock(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	if err := os.WriteFile(filepath.Join(dir, lockPath), []byte(`{
  "schema_version": 1,
  "dataset_id": "eval-v1",
  "object": "datasets/eval-v1.json",
  "generation": "123"
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := loadLock()
	if err != nil {
		t.Fatal(err)
	}
	if lock.DatasetID != "eval-v1" || lock.Generation != "123" {
		t.Fatalf("unexpected lock: %+v", lock)
	}
}
