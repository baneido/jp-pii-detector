// Package source は走査対象（ファイルツリー・git diff）の列挙を提供する。
package source

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/external"
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
	findings, warnings, _, err := ScanPathsWithStats(d, cfg, paths)
	return findings, warnings, err
}

// ScanStats はフルスキャンの完全性を利用者へ説明するための匿名集計。
// パスや検出値は保持せず、走査・除外理由ごとの件数だけを返す。
type ScanStats struct {
	FilesDiscovered     int
	FilesScanned        int
	SkippedBinary       int
	SkippedTooLarge     int
	ExcludedPaths       int
	ExcludedDefaultDirs int
}

// SkippedFiles は列挙後に内容判定で走査しなかったファイル数を返す。
// allowlist と既定除外ディレクトリは配下を列挙しないため含めない。
func (s ScanStats) SkippedFiles() int {
	return s.SkippedBinary + s.SkippedTooLarge
}

// ScanPathsWithStats は ScanPaths と同じ走査を行い、走査完全性の匿名集計も返す。
// 既存 API の呼び出し元を壊さないため、ScanPaths はこの関数への薄い委譲として残す。
func ScanPathsWithStats(d *detect.Detector, cfg *config.Config, paths []string) ([]detect.Finding, []error, ScanStats, error) {
	files, warnings, stats, err := listFiles(cfg, paths)
	if err != nil {
		return nil, nil, stats, err
	}
	findings, readWarnings, scanStats := scanFilesWithStats(d, cfg, files)
	warnings = append(warnings, readWarnings...)
	stats.FilesScanned = scanStats.FilesScanned
	stats.SkippedBinary = scanStats.SkippedBinary
	return findings, warnings, stats, nil
}

// listFiles は走査対象ファイルを walk 順に列挙する。
func listFiles(cfg *config.Config, paths []string) ([]string, []error, ScanStats, error) {
	repoRoot := gitRoot()
	var files []string
	var warnings []error
	var stats ScanStats
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
					stats.ExcludedDefaultDirs++
					return filepath.SkipDir
				}
				if path != root && !pathAllowed(cfg, repoRoot, path) {
					stats.ExcludedPaths++
					return filepath.SkipDir
				}
				return nil
			}
			if !ent.Type().IsRegular() {
				return nil
			}
			if !pathAllowed(cfg, repoRoot, path) {
				stats.ExcludedPaths++
				return nil
			}
			info, err := ent.Info()
			if err != nil {
				warnings = append(warnings, fmt.Errorf("stat %s: %w", path, err))
				return nil
			}
			stats.FilesDiscovered++
			if info.Size() > MaxFileSize {
				stats.SkippedTooLarge++
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			return nil, nil, stats, err
		}
	}
	return files, warnings, stats, nil
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
//
// 読み取り・デコードと走査を 2 段の並列フェーズに分けている。cfg.ExternalRecognizerEnabled()
// の場合、その間に runExternalRecognizer が全ファイルのテキストをまとめて
// internal/external.Run へ 1 回だけ渡す（ファイルごとに子プロセスを起動する
// コストを避けるため。詳細は internal/external のパッケージコメントと CLAUDE.md を
// 参照）。未設定時は runExternalRecognizer が即座に nil を返すため、この構造化に
// よる追加コストは 2 つ目の jobs チャネルのセットアップ程度で無視できる。
func scanFiles(d *detect.Detector, cfg *config.Config, files []string) ([]detect.Finding, []error) {
	findings, warnings, _ := scanFilesWithStats(d, cfg, files)
	return findings, warnings
}

// scanFilesWithStats は scanFiles と同じ処理に、内容判定後の走査・バイナリ除外件数を加える。
func scanFilesWithStats(d *detect.Detector, cfg *config.Config, files []string) ([]detect.Finding, []error, ScanStats) {
	workers := max(min(runtime.GOMAXPROCS(0), len(files)), 1)
	texts := make([]string, len(files))
	// skip[i] はバイナリ判定・読み取りエラーで走査対象外になったファイルを表す
	// （テキストが空文字列の 0 バイトファイルと区別するために必要）。
	skip := make([]bool, len(files))
	results := make([][]detect.Finding, len(files))
	errs := make([]error, len(files))

	readJobs := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range readJobs {
				path := files[i]
				data, err := os.ReadFile(path)
				if err != nil {
					errs[i] = fmt.Errorf("read %s: %w", path, err)
					skip[i] = true
					continue
				}
				text, ok := decodeUTF16(data)
				if !ok {
					text, ok = decodeLegacyJapanese(data)
				}
				if !ok {
					if isBinary(data) {
						skip[i] = true
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
				texts[i] = text
			}
		})
	}
	for i := range files {
		readJobs <- i
	}
	close(readJobs)
	wg.Wait()

	extByFile := runExternalRecognizer(cfg, files, texts, skip)

	scanJobs := make(chan int)
	for range workers {
		wg.Go(func() {
			for i := range scanJobs {
				if skip[i] {
					continue
				}
				path := filepath.ToSlash(files[i])
				findings := d.ScanContent(path, texts[i])
				if cand := extByFile[path]; len(cand) > 0 {
					findings = d.MergeExternalFindings(path, texts[i], findings, cand)
				}
				results[i] = findings
			}
		})
	}
	for i := range files {
		scanJobs <- i
	}
	close(scanJobs)
	wg.Wait()

	var findings []detect.Finding
	var warnings []error
	var stats ScanStats
	for i := range files {
		if errs[i] != nil {
			warnings = append(warnings, errs[i])
			continue
		}
		if skip[i] {
			stats.SkippedBinary++
			continue
		}
		stats.FilesScanned++
		findings = append(findings, results[i]...)
	}
	return findings, warnings, stats
}

// runExternalRecognizer は cfg.ExternalRecognizerEnabled() の場合のみ、読み取り済みの
// 全ファイルのテキストを 1 回の子プロセス起動（internal/external.Run）にまとめて渡す。
// 戻り値は走査時のパス表記（filepath.ToSlash 済み、scanFiles の scanJobs フェーズが
// d.ScanContent に渡すのと同じキー）でグループ化した候補。未設定時・対象ファイルが
// 無い場合は nil を返し、呼び出し側はそれを「外部候補なし」として扱う。
//
// 診断メッセージ（タイムアウト・異常終了・不正 JSON 行での破棄、子プロセスの
// 標準エラー出力）は標準エラーへログとして出力するだけで、戻り値には含めない
// （呼び出し元 scanFiles/ScanPaths の warnings ＝ exit code 2 判定には使わない。
// 外部レコグナイザの不調で通常の検出そのものを失敗させないため）。
func runExternalRecognizer(cfg *config.Config, files, texts []string, skip []bool) map[string][]external.Candidate {
	if !cfg.ExternalRecognizerEnabled() {
		return nil
	}
	inputs := make([]external.FileInput, 0, len(files))
	for i, path := range files {
		if skip[i] {
			continue
		}
		inputs = append(inputs, external.FileInput{File: filepath.ToSlash(path), Text: texts[i]})
	}
	if len(inputs) == 0 {
		return nil
	}
	candidates, diagnostics := external.Run(context.Background(), cfg.ExternalRecognizerConfig(), inputs)
	for _, msg := range diagnostics {
		fmt.Fprintln(os.Stderr, "jp-pii-detect: external-recognizer:", msg)
	}
	if len(candidates) == 0 {
		return nil
	}
	byFile := make(map[string][]external.Candidate, len(candidates))
	for _, c := range candidates {
		byFile[c.File] = append(byFile[c.File], c)
	}
	return byFile
}

// isBinary は先頭 8KB に NUL バイトが含まれるかで判定する。
func isBinary(data []byte) bool {
	n := min(len(data), 8192)
	return bytes.IndexByte(data[:n], 0) >= 0
}
