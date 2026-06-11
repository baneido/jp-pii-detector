package source

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/baneido/jp-pii-detecter/internal/config"
	"github.com/baneido/jp-pii-detecter/internal/detect"
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
	args := append([]string{"diff", "-U0", "--no-color", "--no-ext-diff", "--diff-filter=ACMRT"}, extra...)
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	var findings []detect.Finding
	for _, l := range ParseDiff(string(out)) {
		if !cfg.PathAllowed(l.File) {
			continue
		}
		findings = append(findings, d.ScanLine(l.File, l.Line, l.Text)...)
	}
	return findings, nil
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
			file = strings.TrimPrefix(file, "b/")
			file = strings.Trim(file, `"`)
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
