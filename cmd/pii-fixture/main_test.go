package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRunRejectsUnknownCommand(t *testing.T) {
	if err := run([]string{"unknown"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown command accepted")
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
