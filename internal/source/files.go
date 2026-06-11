// Package source は走査対象（ファイルツリー・git diff）の列挙を提供する。
package source

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

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
func ScanPaths(d *detect.Detector, cfg *config.Config, paths []string) ([]detect.Finding, error) {
	var findings []detect.Finding
	for _, root := range paths {
		err := filepath.WalkDir(root, func(path string, ent fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel := relPath(root, path)
			if ent.IsDir() {
				if skipDirs[ent.Name()] {
					return filepath.SkipDir
				}
				if rel != "." && !cfg.PathAllowed(rel) {
					return filepath.SkipDir
				}
				return nil
			}
			if !ent.Type().IsRegular() || !cfg.PathAllowed(rel) {
				return nil
			}
			info, err := ent.Info()
			if err != nil || info.Size() > MaxFileSize {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			if isBinary(data) {
				return nil
			}
			findings = append(findings, d.ScanContent(filepath.ToSlash(path), string(data))...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return findings, nil
}

func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

// isBinary は先頭 8KB に NUL バイトが含まれるかで判定する。
func isBinary(data []byte) bool {
	n := min(len(data), 8192)
	return bytes.IndexByte(data[:n], 0) >= 0
}
