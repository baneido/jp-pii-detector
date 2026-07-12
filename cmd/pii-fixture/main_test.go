package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/evalcase"
	"github.com/baneido/jp-pii-detector/internal/privatecorpus"
)

func TestRunRejectsUnknownCommand(t *testing.T) {
	if err := run([]string{"unknown"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown command accepted")
	}
}

func TestCollectNameHomographsUsesNegativeCasesOnly(t *testing.T) {
	cases := []evalcase.Case{
		{ID: "negative-1", Line: "酒米の山田錦と山田錦"},
		{ID: "negative-2", Content: "候補は山田太郎\n"},
		{ID: "positive", Line: "氏名: 山田太郎", Want: []string{"person-name"}}, // jp-pii-detector:ignore
	}
	got := collectNameHomographs(cases, 1, 8)
	find := func(value string) (homographCandidate, bool) {
		for _, c := range got {
			if c.Value == value {
				return c, true
			}
		}
		return homographCandidate{}, false
	}
	yamadaNishiki, ok := find("山田錦")
	if !ok || yamadaNishiki.Count != 2 || yamadaNishiki.Surname != "山田" || yamadaNishiki.Given != "錦" {
		t.Fatalf("山田錦 candidate = %+v, present=%v", yamadaNishiki, ok)
	}
	yamadaTaro, ok := find("山田太郎")
	if !ok || yamadaTaro.Count != 1 {
		t.Fatalf("山田太郎 candidate = %+v, present=%v（陽性ケースは数えない）", yamadaTaro, ok)
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

func TestBuildV2CommandProducesCompleteVersionedCorpus(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "v1.json")
	output := filepath.Join(dir, "v2.json")
	base := &privatecorpus.Corpus{
		SchemaVersion: 1,
		DatasetID:     "private-eval-v1",
		Dataset: []evalcase.Case{
			{ID: "legacy-negative-1", SourceClass: "legacy-curated", Line: "識別情報を含まない行"},
		},
	}
	if err := privatecorpus.WriteNew(input, base); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"build-v2", "-input", input, "-output", output}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	got, err := privatecorpus.Load(output)
	if err != nil {
		t.Fatal(err)
	}
	if got.DatasetID != "private-eval-v2" || len(got.Dataset) < 200 {
		t.Fatalf("unexpected v2 metadata: dataset_id=%q cases=%d", got.DatasetID, len(got.Dataset))
	}
	if !strings.Contains(stdout.String(), "spanless=0") {
		t.Fatalf("summary does not prove complete spans: %q", stdout.String())
	}
}

func TestBuildV2CommandRejectsUnexpectedBaseDataset(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "other.json")
	output := filepath.Join(dir, "v2.json")
	base := &privatecorpus.Corpus{
		SchemaVersion: 1,
		DatasetID:     "private-eval-other",
		Dataset:       []evalcase.Case{{ID: "case-1", Line: "no identifiers"}},
	}
	if err := privatecorpus.WriteNew(input, base); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"build-v2", "-input", input, "-output", output}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("build-v2 accepted an unexpected base dataset")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("rejected build created output: %v", err)
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
