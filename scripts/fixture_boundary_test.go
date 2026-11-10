package scripts

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPrivateCorpusImportBoundary は評価コーパスの loader が通常の単体テストへ
// 広がらないことを、import 境界として固定する。
func TestPrivateCorpusImportBoundary(t *testing.T) {
	allowed := []string{
		"cmd/pii-fixture/",
		"internal/eval/",
		"internal/privatecorpus/",
	}
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// .claude/ はエージェントのローカル worktree（リポジトリの複製）を置く場所で、
			// 走査するとリポジトリ外の古いコピーまで検査してしまう。
			if d.Name() == ".git" || d.Name() == ".claude" {
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
		rel := strings.TrimPrefix(filepath.ToSlash(path), "../")
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
