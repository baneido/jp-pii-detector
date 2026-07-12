// Package source は走査対象（ファイルツリー・git diff）の列挙を提供する。
package source

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
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
// allowlist.paths は検出結果に報告するパス（走査ルートを含むスラッシュ
// 区切りパス）に加え、リポジトリルートからの相対パスに対しても評価する。
// サブディレクトリから実行しても、ルートの設定に書いたルート相対の
// 正規表現（^testdata/ 等）が機能する。
//
// 個々のファイルの読み取りエラー（権限拒否・走査中の削除等）は致命的として
// 扱わない。該当ファイルをスキップして戻り値の warnings に集約し、他ファイルの
// 収集済み findings は失わずに返す。err は listFiles 自体の失敗（走査対象の
// ルートが存在しない等）のみを表す。
func ScanPaths(d *detect.Detector, cfg *config.Config, paths []string) ([]detect.Finding, []error, error) {
	files, warnings, err := listFiles(cfg, paths)
	if err != nil {
		return nil, nil, err
	}
	findings, readWarnings := scanFiles(d, files)
	warnings = append(warnings, readWarnings...)
	return findings, warnings, nil
}

// listFiles は走査対象ファイルを walk 順に列挙する。
func listFiles(cfg *config.Config, paths []string) ([]string, []error, error) {
	repoRoot := gitRoot()
	var files []string
	var warnings []error
	for _, root := range paths {
		err := filepath.WalkDir(root, func(path string, ent fs.DirEntry, err error) error {
			if err != nil {
				if path == root {
					return err
				}
				warnings = append(warnings, fmt.Errorf("walk %s: %w", path, err))
				if ent != nil && ent.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if ent.IsDir() {
				if skipDirs[ent.Name()] {
					return filepath.SkipDir
				}
				if path != root && !pathAllowed(cfg, repoRoot, path) {
					return filepath.SkipDir
				}
				return nil
			}
			if !ent.Type().IsRegular() || !pathAllowed(cfg, repoRoot, path) {
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
			return nil, nil, err
		}
	}
	return files, warnings, nil
}

// pathAllowed は allowlist.paths を、走査時のパス表記とリポジトリルート
// 相対パスの両方で評価する（どちらかにマッチすれば除外）。
func pathAllowed(cfg *config.Config, repoRoot, path string) bool {
	if !cfg.PathAllowed(filepath.ToSlash(path)) {
		return false
	}
	if repoRoot == "" {
		return true
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return true
	}
	rel, err := filepath.Rel(repoRoot, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true // リポジトリ外のパスはルート相対では評価しない
	}
	return cfg.PathAllowed(filepath.ToSlash(rel))
}

// gitRoot はカレントディレクトリから親方向に .git を探し、リポジトリ
// ルートの絶対パスを返す（リポジトリ外なら空文字列）。設定ファイルの
// 上方探索（config.Load）と同じ基準でルートを決める。
func gitRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// scanFiles はファイル群を並列に読み込み・走査し、入力順の結果を返す。
// Detector は走査中は読み取り専用のため、ゴルーチン間で安全に共有できる。
//
// 個々のファイルの読み取りエラーは致命的にせず warnings に集約して走査を
// 継続する（セキュリティツールとして、1 ファイルのエラーで収集済みの他
// findings を握りつぶさないため）。呼び出し元（ScanPaths）が warnings の
// 有無を呼び出し元にさらに伝える。
func scanFiles(d *detect.Detector, files []string) ([]detect.Finding, []error) {
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
				text, ok := decodeUTF16(data)
				if !ok {
					text, ok = decodeLegacyJapanese(data)
				}
				if !ok {
					if isBinary(data) {
						continue
					}
					text = string(data)
				}
				// 上記いずれの経路で得た最終的な UTF-8 テキストに対しても、
				// 後段として \uXXXX エスケープ（ensure_ascii=True 出力・.ipynb
				// 等）→ HTML 数値文字参照（&#...; 等）→ URL パーセントエンコード
				// （%XX の連続列）の順に適用する復号ビューの直列チェーン
				// （decodeEscapedViews）を適用する。DecodeEscapedView（scan
				// --stdin 経路、cmd/jp-pii-detect/main.go）も同じ
				// decodeEscapedViews を呼ぶため、フルスキャンと stdin の両経路は
				// 常に同じ復号チェーンを通る。1 箇所も復号できなければ text は
				// そのまま変わらない。
				if unescaped, ok := decodeEscapedViews(text); ok {
					text = unescaped
				}
				results[i] = d.ScanContent(filepath.ToSlash(path), text)
			}
		})
	}
	for i := range files {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	var findings []detect.Finding
	var warnings []error
	for i := range files {
		if errs[i] != nil {
			warnings = append(warnings, errs[i])
			continue
		}
		findings = append(findings, results[i]...)
	}
	return findings, warnings
}

// isBinary は先頭 8KB に NUL バイトが含まれるかで判定する。
func isBinary(data []byte) bool {
	n := min(len(data), 8192)
	return bytes.IndexByte(data[:n], 0) >= 0
}
