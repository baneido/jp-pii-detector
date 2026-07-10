package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/fixturegen"
)

// TestRunWritesPiifixturesCompatibleJSON は run() が internal/piifixtures の
// JSON スキーマ（"strings" / "dataset"）と互換な出力を書き出すことを検証する。
func TestRunWritesPiifixturesCompatibleJSON(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "synthetic-cases.json")

	if err := run(output, os.Stdout, os.Stderr); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}

	var decoded struct {
		Strings map[string]string `json:"strings"`
		Dataset []struct {
			Line string   `json:"line"`
			Want []string `json:"want"`
			Tags []string `json:"tags"`
		} `json:"dataset"`
	}
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("output is not valid piifixtures-compatible JSON: %v", err)
	}
	if len(decoded.Dataset) == 0 {
		t.Fatal("decoded dataset is empty")
	}
	if len(decoded.Dataset) != len(fixturegen.Generate()) {
		t.Fatalf("decoded dataset has %d cases, want %d (fixturegen.Generate() must be deterministic)",
			len(decoded.Dataset), len(fixturegen.Generate()))
	}
	for _, c := range decoded.Dataset {
		if len(c.Tags) == 0 {
			t.Errorf("case %+v has no tags (should include %s)", c, fixturegen.SourceTag)
		}
	}
}

func TestRunRequiresOutputPath(t *testing.T) {
	dir := t.TempDir()
	// 出力先ディレクトリが存在しない場合はエラーになること（誤ったパス指定で
	// 静かに失敗しない）。
	if err := run(filepath.Join(dir, "nonexistent-subdir", "out.json"), os.Stdout, os.Stderr); err == nil {
		t.Fatal("run() with a nonexistent output directory should return an error")
	}
}
