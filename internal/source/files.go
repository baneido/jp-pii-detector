// Package source は走査対象（ファイルツリー・git diff）の列挙を提供する。
package source

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/baneido/jp-pii-detecter/internal/config"
	"github.com/baneido/jp-pii-detecter/internal/detect"
)

// MaxFileSize を超えるファイルは走査しない。
const MaxFileSize = 5 * 1024 * 1024

// skipDirs は常に走査しないディレクトリ。
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	"dist":         true,
	"build":        true,
	".next":        true,
	"target":       true,
}

// ScanPaths は指定パス配下のテキストファイルを走査する。
// allowlist.paths は検出結果に報告するパスと同じ表記
// （走査ルートを含むスラッシュ区切りパス）に対して評価する。
func ScanPaths(d *detect.Detector, cfg *config.Config, paths []string) ([]detect.Finding, error) {
	files, err := listFiles(cfg, paths)
	if err != nil {
		return nil, err
	}
	return scanFiles(d, files)
}

// listFiles は走査対象ファイルを walk 順に列挙する。
func listFiles(cfg *config.Config, paths []string) ([]string, error) {
	var files []string
	for _, root := range paths {
		err := filepath.WalkDir(root, func(path string, ent fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			slashed := filepath.ToSlash(path)
			if ent.IsDir() {
				if skipDirs[ent.Name()] {
					return filepath.SkipDir
				}
				if path != root && !cfg.PathAllowed(slashed) {
					return filepath.SkipDir
				}
				return nil
			}
			if !ent.Type().IsRegular() || !cfg.PathAllowed(slashed) {
				return nil
			}
			info, err := ent.Info()
			if err != nil || info.Size() > MaxFileSize {
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

// scanFiles はファイル群を並列に読み込み・走査し、入力順の結果を返す。
// Detector は走査中は読み取り専用のため、ゴルーチン間で安全に共有できる。
func scanFiles(d *detect.Detector, files []string) ([]detect.Finding, error) {
	workers := max(min(runtime.GOMAXPROCS(0), len(files)), 1)
	results := make([][]detect.Finding, len(files))
	errs := make([]error, len(files))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range jobs {
				path := files[i]
				data, err := os.ReadFile(path)
				if err != nil {
					errs[i] = fmt.Errorf("read %s: %w", path, err)
					continue
				}
				if isBinary(data) {
					continue
				}
				results[i] = d.ScanContent(filepath.ToSlash(path), string(data))
			}
		})
	}
	for i := range files {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	var findings []detect.Finding
	for i := range files {
		if errs[i] != nil {
			return nil, errs[i]
		}
		findings = append(findings, results[i]...)
	}
	return findings, nil
}

// isBinary は先頭 8KB に NUL バイトが含まれるかで判定する。
func isBinary(data []byte) bool {
	n := min(len(data), 8192)
	return bytes.IndexByte(data[:n], 0) >= 0
}
