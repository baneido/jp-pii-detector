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
	//
	// -U3: 文脈行（未変更行）を前後 3 行含める。ラベルが既存行にあり値だけを
	// 追加したケース（例: 直前の行に「口座番号:」があり、追加行は値だけ）でも、
	// コンテキスト必須ルールを発火させるため。検出値が追加行に乗っているものだけを
	// 報告し、文脈行上の既存 PII は報告しない（scanHunk）。
	args := append([]string{"-c", "core.quotePath=false",
		"diff", "-U3", "--no-color", "--no-ext-diff", "--diff-filter=ACMRT"}, extra...)
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	var findings []detect.Finding
	for _, h := range parseDiffHunks(string(out)) {
		findings = append(findings, scanHunk(d, cfg, h)...)
	}
	return findings, nil
}

// scanHunk は 1 つの diff hunk を走査し、検出値が追加行に乗っているものだけを
// 報告する。文脈行（未変更行）はラベル等のコンテキストを補うために走査対象へ
// 含めるが、文脈行上で完結する検出（既存 PII）は新規追加ではないため除外する。
func scanHunk(d *detect.Detector, cfg *config.Config, h fileHunk) []detect.Finding {
	if h.File == "" || !cfg.PathAllowed(h.File) {
		return nil
	}
	texts := make([]string, len(h.Lines))
	for i, l := range h.Lines {
		texts[i] = l.Text
	}
	var findings []detect.Finding
	for _, f := range d.ScanContent(h.File, strings.Join(texts, "\n")) {
		// ScanContent の行番号はウィンドウ内 1 始まり。元ファイルの行番号へ写像し、
		// その行が追加行のときだけ報告する。
		idx := f.Line - 1
		if idx < 0 || idx >= len(h.Lines) || !h.Lines[idx].Added {
			continue
		}
		f.Line = h.Lines[idx].Line
		findings = append(findings, f)
	}
	return findings
}

// diffLine は diff hunk 内の新ファイル側 1 行。
type diffLine struct {
	Line  int    // 新ファイルでの行番号（1 始まり）
	Text  string // 行頭の diff マーカー（'+' / ' '）を除いた本文
	Added bool   // true: 追加行（+）、false: 文脈行（未変更）
}

// fileHunk は 1 つの diff hunk。文脈行と追加行が新ファイル順に連続するブロック。
type fileHunk struct {
	File  string
	Lines []diffLine
}

// AddedLine は diff 内の追加行。
type AddedLine struct {
	File string
	Line int // 新ファイルでの行番号（1 始まり）
	Text string
}

// ParseDiff は unified diff から追加行（+ で始まる行）のみを抽出する。
// hunk 単位の解析（parseDiffHunks）から追加行を平坦化した薄いラッパで、
// 既存の利用箇所・テストとの互換のために残している。
func ParseDiff(diff string) []AddedLine {
	var out []AddedLine
	for _, h := range parseDiffHunks(diff) {
		for _, l := range h.Lines {
			if l.Added {
				out = append(out, AddedLine{File: h.File, Line: l.Line, Text: l.Text})
			}
		}
	}
	return out
}

// parseDiffHunks は unified diff を hunk 単位に分解する。各 hunk には文脈行
// （' '）と追加行（'+'）を新ファイル順に保持する（削除行は新ファイルに存在
// しないため保持しない）。ファイルパス・行番号の解釈は ParseDiff と共通。
func parseDiffHunks(diff string) []fileHunk {
	var hunks []fileHunk
	var cur *fileHunk
	file := ""
	newLine := 0
	flush := func() {
		if cur != nil && len(cur.Lines) > 0 {
			hunks = append(hunks, *cur)
		}
		cur = nil
	}
	for line := range strings.SplitSeq(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "+++ "):
			flush()
			file = strings.TrimPrefix(line, "+++ ")
			// 引用符（引用符・制御文字を含むパスで付く）を外してから
			// b/ 接頭辞を取り除く。逆順だと引用時に b/ が残る。
			file = strings.Trim(file, `"`)
			file = strings.TrimPrefix(file, "b/")
			if file == "/dev/null" {
				file = ""
			}
		case strings.HasPrefix(line, "--- "):
			// 旧ファイルパス。'-' 始まりだが削除行ではないので何もしない
			// （下の '+' / ' ' / '-' 判定に流さないために明示的に分岐する）。
		case strings.HasPrefix(line, "@@ "):
			flush()
			newLine = parseHunkNewStart(line)
			if file != "" {
				cur = &fileHunk{File: file}
			}
		case strings.HasPrefix(line, "+"):
			if cur != nil {
				cur.Lines = append(cur.Lines, diffLine{Line: newLine, Text: strings.TrimPrefix(line, "+"), Added: true})
				newLine++
			}
		case strings.HasPrefix(line, " "):
			if cur != nil {
				cur.Lines = append(cur.Lines, diffLine{Line: newLine, Text: line[1:], Added: false})
				newLine++
			}
		}
		// '-'（削除行）やその他のメタ行はスキップする（newLine も進めない）。
	}
	flush()
	return hunks
}

// parseHunkNewStart は hunk ヘッダ（例: @@ -10,2 +15,3 @@）から新ファイル側の
// 開始行番号を取り出す。
func parseHunkNewStart(line string) int {
	for p := range strings.FieldsSeq(line) {
		numPart, ok := strings.CutPrefix(p, "+")
		if !ok {
			continue
		}
		if i := strings.IndexByte(numPart, ','); i >= 0 {
			numPart = numPart[:i]
		}
		if n, err := strconv.Atoi(numPart); err == nil {
			return n
		}
		break
	}
	return 0
}
