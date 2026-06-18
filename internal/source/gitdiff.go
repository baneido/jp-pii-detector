package source

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
)

// ScanStaged は git のステージ済み変更の追加行を走査する（pre-commit 用）。
func ScanStaged(d *detect.Detector, cfg *config.Config) ([]detect.Finding, error) {
	return scanGitDiff(d, cfg, []string{"--staged"})
}

// ScanDiff は指定リビジョン範囲（例: origin/main...HEAD）の追加行を走査する（CI 用）。
func ScanDiff(d *detect.Detector, cfg *config.Config, diffRange string) ([]detect.Finding, error) {
	return scanGitDiff(d, cfg, []string{diffRange})
}

func scanGitDiff(d *detect.Detector, cfg *config.Config, extra []string) ([]detect.Finding, error) {
	// core.quotePath=false: 日本語などの非 ASCII ファイル名が
	// 8 進エスケープ（"\346\227\245..."）で出力されるのを防ぐ。
	args := append([]string{"-c", "core.quotePath=false",
		"diff", "-U0", "--no-color", "--no-ext-diff", "--diff-filter=ACMRT"}, extra...)
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	var findings []detect.Finding
	findings = append(findings, scanAddedLines(d, cfg, ParseDiff(string(out)))...)
	return findings, nil
}

func scanAddedLines(d *detect.Detector, cfg *config.Config, lines []AddedLine) []detect.Finding {
	var findings []detect.Finding
	for i := 0; i < len(lines); {
		l := lines[i]
		if !cfg.PathAllowed(l.File) {
			i++
			continue
		}
		file := l.File
		startLine := l.Line
		texts := []string{l.Text}
		i++
		for i < len(lines) && lines[i].File == file && lines[i].Line == startLine+len(texts) {
			texts = append(texts, lines[i].Text)
			i++
		}
		for _, f := range d.ScanContent(file, strings.Join(texts, "\n")) {
			f.Line += startLine - 1
			findings = append(findings, f)
		}
	}
	return findings
}

// AddedLine は diff 内の追加行。
type AddedLine struct {
	File string
	Line int // 新ファイルでの行番号（1 始まり）
	Text string
}

// ParseDiff は unified diff から追加行（+ で始まる行）を抽出する。
func ParseDiff(diff string) []AddedLine {
	var out []AddedLine
	file := ""
	newLine := 0
	for line := range strings.SplitSeq(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "+++ "):
			file = strings.TrimPrefix(line, "+++ ")
			// 引用符（引用符・制御文字を含むパスで付く）を外してから
			// b/ 接頭辞を取り除く。逆順だと引用時に b/ が残る。
			file = strings.Trim(file, `"`)
			file = strings.TrimPrefix(file, "b/")
			if file == "/dev/null" {
				file = ""
			}
		case strings.HasPrefix(line, "@@ "):
			// 例: @@ -10,2 +15,3 @@
			parts := strings.Fields(line)
			for _, p := range parts {
				if numPart, ok := strings.CutPrefix(p, "+"); ok {
					if i := strings.IndexByte(numPart, ','); i >= 0 {
						numPart = numPart[:i]
					}
					if n, err := strconv.Atoi(numPart); err == nil {
						newLine = n
					}
					break
				}
			}
		case strings.HasPrefix(line, "+") && file != "":
			out = append(out, AddedLine{File: file, Line: newLine, Text: strings.TrimPrefix(line, "+")})
			newLine++
		case strings.HasPrefix(line, " "):
			newLine++
		}
	}
	return out
}
