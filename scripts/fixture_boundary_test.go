package scripts

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPrivateCorpusImportBoundary は非公開平文のloaderが通常の単体テストへ
// 再び広がらないことを、import境界として固定する。
func TestPrivateCorpusImportBoundary(t *testing.T) {
	allowed := []string{
		"cmd/pii-fixture/",
		"internal/eval/",
		"internal/piifixtures/", // 旧API互換層
		"internal/privatecorpus/",
	}
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(b), "internal/privatecorpus\"") {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, "../"))
		for _, prefix := range allowed {
			if strings.HasPrefix(rel, prefix) {
				return nil
			}
		}
		t.Errorf("%s imports internal/privatecorpus outside the approved boundary", rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
