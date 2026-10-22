// Package suppression は、利用者のリポジトリで検出がどれだけ・どのルールについて
// 抑制されているか（行内 ignore マーカーと .jp-pii.toml の [allowlist]）を集計する。
//
// 抑制が多いルールは利用現場で誤検出（ノイズ）が多いルールの有力な手がかりになる。
// 誤検出の報告（Issue）に添える、または保守者が自分のリポジトリで傾向を見るための
// 道具で、出力はルール ID・件数・allowlist の要素番号・（指定時のみ）ファイルパス
// だけに限る。マッチ値は生値もマスク値も出さない。
package suppression

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/normalize"
	"github.com/baneido/jp-pii-detector/internal/source"
)

// Markers は集計対象の行内 ignore マーカー（detect.IgnoreMarker と旧 detect.AllowMarker）。
var Markers = []string{detect.IgnoreMarker, detect.AllowMarker}

// skipDirs は internal/source のフルスキャンが既定で降りないディレクトリ。
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"__pycache__": true, "dist": true, "build": true, ".next": true, "target": true,
}

// RuleRow は 1 ルール分の集計。
type RuleRow struct {
	RuleID string `json:"rule_id"`
	// Reported は抑制後もなお報告された件数（通常の scan の結果）。
	Reported int `json:"reported"`
	// IgnoredByMarker は ignore マーカー付きの行で、マーカーが無ければ検出された件数。
	IgnoredByMarker int `json:"ignored_by_marker"`
	// AllowlistPaths / AllowlistRegexes / AllowlistStopwords は各 [allowlist] が
	// 抑制した件数。AllowlistOther は allowlist を外すと現れるが、どの要素にも
	// 直接は一致しない差分（重複解決の結果が変わったもの等）。
	AllowlistPaths     int `json:"allowlist_paths"`
	AllowlistRegexes   int `json:"allowlist_regexes"`
	AllowlistStopwords int `json:"allowlist_stopwords"`
	AllowlistOther     int `json:"allowlist_other"`
}

// Suppressed は抑制された件数の合計。
func (r RuleRow) Suppressed() int {
	return r.IgnoredByMarker + r.AllowlistPaths + r.AllowlistRegexes + r.AllowlistStopwords + r.AllowlistOther
}

// SuppressionRate は 抑制 /（抑制 + 報告）。分母 0 なら 0。
func (r RuleRow) SuppressionRate() float64 {
	total := r.Suppressed() + r.Reported
	if total == 0 {
		return 0
	}
	return float64(r.Suppressed()) / float64(total)
}

// EntryCount は allowlist の 1 要素が抑制した件数。Entry は paths ならパターン
// そのもの、regexes / stopwords は値を含みうるため "regexes[0]" のような要素番号。
type EntryCount struct {
	Entry    string         `json:"entry"`
	Findings int            `json:"findings"`
	ByRule   map[string]int `json:"by_rule"`
}

// FileCount はファイルごとの ignore マーカー行数。
type FileCount struct {
	Path        string `json:"path"`
	MarkerLines int    `json:"marker_lines"`
}

// Report は集計結果。
type Report struct {
	FilesWithMarkers int `json:"files_with_markers"`
	// MarkerLines はマーカー別の行数。
	MarkerLines map[string]int `json:"marker_lines"`
	// StaleMarkerLines はマーカーを外しても何も検出されない（抑制の役目を
	// 果たしていない）行数。ルール改善で不要になった ignore の掃除の目安。
	StaleMarkerLines int          `json:"stale_marker_lines"`
	Rules            []RuleRow    `json:"rules"`
	Allowlist        []EntryCount `json:"allowlist"`
	// Files は --files 指定時のみ埋まる（マーカー行の多い順）。
	Files []FileCount `json:"files,omitempty"`
}

// Options は Run の動作設定。
type Options struct {
	// IncludeFiles はファイルごとのマーカー行数を Report.Files に含める。
	IncludeFiles bool
}

// Run は paths 配下を cfg で走査して抑制状況を集計する。warnings は読めなかった
// ファイル等の非致命的な問題。
func Run(cfg *config.Config, paths []string, opts Options) (Report, []error, error) {
	det, err := detect.New(cfg)
	if err != nil {
		return Report{}, nil, err
	}
	bareCfg := cfg.WithoutAllowlist()
	bare, err := detect.New(bareCfg)
	if err != nil {
		return Report{}, nil, err
	}

	rows := map[string]*RuleRow{}
	row := func(id string) *RuleRow {
		if r, ok := rows[id]; ok {
			return r
		}
		r := &RuleRow{RuleID: id}
		rows[id] = r
		return r
	}

	reported, warnings, err := source.ScanPaths(det, cfg, paths)
	if err != nil {
		return Report{}, warnings, err
	}
	seen := map[string]bool{}
	for _, f := range reported {
		row(f.RuleID).Reported++
		seen[key(f)] = true
	}

	// allowlist を外した走査との差分を、どの要素が抑制したかへ帰属させる。
	unsuppressed, _, err := source.ScanPaths(bare, bareCfg, paths)
	if err != nil {
		return Report{}, warnings, err
	}
	attr := newAttributor(cfg)
	entries := map[string]*EntryCount{}
	for _, f := range unsuppressed {
		if seen[key(f)] {
			continue
		}
		kind, entry := attr.attribute(f)
		r := row(f.RuleID)
		switch kind {
		case "paths":
			r.AllowlistPaths++
		case "regexes":
			r.AllowlistRegexes++
		case "stopwords":
			r.AllowlistStopwords++
		default:
			r.AllowlistOther++
		}
		if entry == "" {
			continue
		}
		e, ok := entries[entry]
		if !ok {
			e = &EntryCount{Entry: entry, ByRule: map[string]int{}}
			entries[entry] = e
		}
		e.Findings++
		e.ByRule[f.RuleID]++
	}

	rep := Report{MarkerLines: map[string]int{}}
	markerWarnings, err := scanMarkers(det, cfg, paths, &rep, row, opts)
	warnings = append(warnings, markerWarnings...)
	if err != nil {
		return Report{}, warnings, err
	}

	for _, r := range rows {
		rep.Rules = append(rep.Rules, *r)
	}
	sort.Slice(rep.Rules, func(i, j int) bool {
		a, b := rep.Rules[i], rep.Rules[j]
		if a.Suppressed() != b.Suppressed() {
			return a.Suppressed() > b.Suppressed()
		}
		return a.RuleID < b.RuleID
	})
	for _, e := range entries {
		rep.Allowlist = append(rep.Allowlist, *e)
	}
	sort.Slice(rep.Allowlist, func(i, j int) bool {
		a, b := rep.Allowlist[i], rep.Allowlist[j]
		if a.Findings != b.Findings {
			return a.Findings > b.Findings
		}
		return a.Entry < b.Entry
	})
	sort.Slice(rep.Files, func(i, j int) bool {
		a, b := rep.Files[i], rep.Files[j]
		if a.MarkerLines != b.MarkerLines {
			return a.MarkerLines > b.MarkerLines
		}
		return a.Path < b.Path
	})
	return rep, warnings, nil
}

func key(f detect.Finding) string {
	return fmt.Sprintf("%s\x00%d\x00%d\x00%s", f.File, f.Line, f.Column, f.RuleID)
}

// attributor は allowlist を外すと現れた検出を、抑制した要素へ帰属させる。
type attributor struct {
	cfg       *config.Config
	repoRoot  string
	pathCfgs  []*config.Config
	stopwords []string
}

func newAttributor(cfg *config.Config) *attributor {
	a := &attributor{cfg: cfg, repoRoot: source.RepoRoot()}
	for _, p := range cfg.Allowlist.Paths {
		// 要素ごとに単独の設定を作り、どのパターンが除外したかを判定する。
		single, err := config.Parse(fmt.Sprintf("[allowlist]\npaths = [%s]\n", tomlString(p)))
		if err != nil {
			single = nil
		}
		a.pathCfgs = append(a.pathCfgs, single)
	}
	for _, sw := range cfg.Allowlist.Stopwords {
		a.stopwords = append(a.stopwords, normalize.Line(sw))
	}
	return a
}

func (a *attributor) excludedBy(c *config.Config, file string) bool {
	if !c.PathAllowed(filepath.ToSlash(file)) {
		return true
	}
	if a.repoRoot == "" {
		return false
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(a.repoRoot, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return !c.PathAllowed(filepath.ToSlash(rel))
}

func (a *attributor) attribute(f detect.Finding) (kind, entry string) {
	if a.excludedBy(a.cfg, f.File) {
		for i, c := range a.pathCfgs {
			if c != nil && a.excludedBy(c, f.File) {
				return "paths", "paths: " + a.cfg.Allowlist.Paths[i]
			}
		}
		return "paths", ""
	}
	norm := normalize.Line(f.Match)
	for i, sw := range a.cfg.Allowlist.Stopwords {
		if f.Match == sw || norm == sw || norm == a.stopwords[i] {
			return "stopwords", fmt.Sprintf("stopwords[%d]", i)
		}
	}
	for i, re := range a.cfg.AllowRegexes() {
		if re.MatchString(norm) || re.MatchString(f.Match) {
			return "regexes", fmt.Sprintf("regexes[%d]", i)
		}
	}
	return "other", ""
}

// tomlString は s を TOML のリテラル文字列（'...'）または基本文字列で表す。
func tomlString(s string) string {
	if !strings.ContainsAny(s, "'\n\r") {
		return "'" + s + "'"
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	return `"` + r.Replace(s) + `"`
}

// scanMarkers はマーカー行を持つファイルだけ、マーカーを空白に置き換えて再走査し、
// マーカー行に現れる検出をルール別に数える。
func scanMarkers(det *detect.Detector, cfg *config.Config, paths []string, rep *Report, row func(string) *RuleRow, opts Options) ([]error, error) {
	var warnings []error
	attr := &attributor{cfg: cfg, repoRoot: source.RepoRoot()}
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
				if skipDirs[ent.Name()] || (path != root && attr.excludedBy(cfg, path)) {
					return filepath.SkipDir
				}
				return nil
			}
			// allowlist.paths で除外されたファイルは allowlist 側で数える。
			if !ent.Type().IsRegular() || attr.excludedBy(cfg, path) {
				return nil
			}
			info, err := ent.Info()
			if err != nil || info.Size() > source.MaxFileSize {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				warnings = append(warnings, fmt.Errorf("read %s: %w", path, err))
				return nil
			}
			if isBinary(data) {
				return nil
			}
			countMarkers(det, path, string(data), rep, row, opts)
			return nil
		})
		if err != nil && !errors.Is(err, fs.SkipAll) {
			return warnings, err
		}
	}
	return warnings, nil
}

func countMarkers(det *detect.Detector, path, text string, rep *Report, row func(string) *RuleRow, opts Options) {
	text = strings.TrimPrefix(text, "\uFEFF")
	lines := strings.Split(text, "\n")
	markerLines := map[int]bool{}
	for i, line := range lines {
		stripped := line
		for _, m := range Markers {
			var found bool
			stripped, found = blankMarker(stripped, m)
			if found {
				rep.MarkerLines[m]++
				markerLines[i+1] = true
			}
		}
		lines[i] = stripped
	}
	if len(markerLines) == 0 {
		return
	}
	rep.FilesWithMarkers++
	if opts.IncludeFiles {
		rep.Files = append(rep.Files, FileCount{Path: filepath.ToSlash(path), MarkerLines: len(markerLines)})
	}
	hit := map[int]bool{}
	for _, f := range det.ScanContent(path, strings.Join(lines, "\n")) {
		if markerLines[f.Line] {
			row(f.RuleID).IgnoredByMarker++
			hit[f.Line] = true
		}
	}
	rep.StaleMarkerLines += len(markerLines) - len(hit)
}

// blankMarker は line 中のトークン境界付きの marker をすべて同じ長さの空白に置き換える
// （列位置を保つ）。detect の containsMarkerToken と同じ境界規則に従う。
func blankMarker(line, marker string) (string, bool) {
	found := false
	for idx := 0; idx < len(line); {
		pos := strings.Index(line[idx:], marker)
		if pos < 0 {
			break
		}
		start := idx + pos
		end := start + len(marker)
		before, after := true, true
		if start > 0 {
			r, _ := utf8.DecodeLastRuneInString(line[:start])
			before = !isMarkerTokenChar(r)
		}
		if end < len(line) {
			r, _ := utf8.DecodeRuneInString(line[end:])
			after = !isMarkerTokenChar(r)
		}
		if before && after {
			line = line[:start] + strings.Repeat(" ", len(marker)) + line[end:]
			found = true
			idx = end
			continue
		}
		idx = start + 1
	}
	return line, found
}

func isMarkerTokenChar(r rune) bool {
	return r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// isBinary は internal/source と同じく先頭 8KiB の NUL で判定する。UTF-16 や
// Shift_JIS のファイルは復号しない（マーカーは ASCII のため UTF-8 / Shift_JIS では
// 見つかるが、UTF-16 のファイルのマーカーは数えない）。
func isBinary(data []byte) bool {
	n := min(len(data), 8192)
	return bytes.IndexByte(data[:n], 0) >= 0
}
