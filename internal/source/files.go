// Package source は走査対象（ファイルツリー・git diff）の列挙を提供する。
package source

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unicode/utf16"

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
				if text, ok := decodeUTF16(data); ok {
					results[i] = d.ScanContent(filepath.ToSlash(path), text)
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

// decodeUTF16 は UTF-16 の BOM（FF FE = リトルエンディアン、FE FF =
// ビッグエンディアン）を検出したときだけ UTF-8 へデコードする。BOM が無い
// 場合は ok=false を返し、呼び出し側は従来どおり isBinary 判定へ委ねる
// （UTF-16 は半角文字が 1 バイト置きに NUL を挟むため、BOM チェックより先に
// isBinary を通すと確実にバイナリ扱いされ完全に検出漏れになる。この関数を
// isBinary より前に呼ぶことでそれを避ける）。
//
// 奇数バイト長（BOM を除いた本体が 2 バイト単位にならない）や不正な
// サロゲートペアは ok=false を返し、呼び出し側は従来どおりのバイナリ判定
// （isBinary）にフォールバックする。
//
// 注意（呼び出し側・ドキュメントで明記が必要な既知の制約）:
//   - デコード後の Finding の行・列はルーン単位で正しいが、デコード後の
//     文字列上の位置であり、元ファイルの UTF-16 バイトオフセットとは
//     対応しない。
//   - git diff は UTF-16 ファイルをバイナリ扱いするため、この関数は
//     フルスキャン（ScanPaths）経由でのみ効き、--staged/--diff の
//     差分走査では UTF-16 ファイルはそもそも対象にならない。
func decodeUTF16(data []byte) (string, bool) {
	var order binary.ByteOrder
	switch {
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE:
		order = binary.LittleEndian
	case len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF:
		order = binary.BigEndian
	default:
		return "", false
	}
	body := data[2:]
	if len(body)%2 != 0 {
		return "", false
	}
	units := make([]uint16, len(body)/2)
	for i := range units {
		units[i] = order.Uint16(body[i*2:])
	}
	if !validUTF16Surrogates(units) {
		return "", false
	}
	return string(utf16.Decode(units)), true
}

// validUTF16Surrogates は units が正しいサロゲートペアの並びかを検証する。
// utf16.Decode は不正なサロゲートを黙って置換文字（U+FFFD）に変換するため、
// 事前にここで検証し、不正な入力はデコード失敗としてバイナリ判定へ
// フォールバックさせる（置換文字での化けを防ぐ）。
func validUTF16Surrogates(units []uint16) bool {
	for i := 0; i < len(units); i++ {
		u := units[i]
		switch {
		case u >= 0xD800 && u <= 0xDBFF: // 上位サロゲート
			if i+1 >= len(units) {
				return false
			}
			next := units[i+1]
			if next < 0xDC00 || next > 0xDFFF {
				return false
			}
			i++ // ペアを消費
		case u >= 0xDC00 && u <= 0xDFFF: // 対応する上位サロゲートの無い下位サロゲート
			return false
		}
	}
	return true
}
