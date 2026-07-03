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
	//
	// --src-prefix=a/ --dst-prefix=b/: ユーザー/CI の gitconfig
	// （diff.mnemonicPrefix=true 等）に関わらず "+++ " ヘッダの接頭辞を
	// 常に b/ 固定にする。これが揺れると下流の TrimPrefix(file, "b/") が
	// 効かず（例: "+++ i/path"）、報告パスに接頭辞が残って allowlist.paths
	// が一致しなくなる。
	args := append([]string{"-c", "core.quotePath=false",
		"diff", "-U3", "--no-color", "--no-ext-diff", "--diff-filter=ACMRT",
		"--src-prefix=a/", "--dst-prefix=b/"}, extra...)
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
	dlines := make([]detect.DiffLine, len(h.Lines))
	for i, l := range h.Lines {
		dlines[i] = detect.DiffLine{Text: l.Text, Added: l.Added}
	}
	var findings []detect.Finding
	// ScanDiffHunk は検出値が追加行に乗る finding だけを返す（文脈行は正の
	// コンテキスト補完にのみ使う）。行番号はウィンドウ内 1 始まりなので、
	// 元ファイルの行番号へ写像する。
	for _, f := range d.ScanDiffHunk(h.File, dlines) {
		idx := f.Line - 1
		if idx < 0 || idx >= len(h.Lines) {
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
// しないため保持しない）。
//
// hunk ヘッダの行数（@@ -a,b +c,d @@ の b・d）でカウントして本文の終端を判定し、
// 本文中は先頭 1 文字だけで分類する。これにより、内容が "++ " で始まる追加行
// （diff 上は "+++ " と出力される）をファイルヘッダと誤認しない。
func parseDiffHunks(diff string) []fileHunk {
	var hunks []fileHunk
	var cur *fileHunk
	file := ""
	newLine := 0
	oldRemaining, newRemaining := 0, 0
	inHunk := func() bool { return oldRemaining > 0 || newRemaining > 0 }
	flush := func() {
		if cur != nil && len(cur.Lines) > 0 {
			hunks = append(hunks, *cur)
		}
		cur = nil
	}
	for line := range strings.SplitSeq(diff, "\n") {
		if inHunk() {
			// hunk 本文。先頭 1 文字で分類する（"+++"/"---" も本文の内容行として扱う）。
			switch {
			case strings.HasPrefix(line, "+"):
				if cur != nil {
					cur.Lines = append(cur.Lines, diffLine{Line: newLine, Text: line[1:], Added: true})
				}
				newLine++
				newRemaining--
			case strings.HasPrefix(line, "-"):
				oldRemaining-- // 削除行は新ファイルに存在しない
			case strings.HasPrefix(line, `\`):
				// "\ No newline at end of file" — 行数に影響しない
			default: // 文脈行（先頭スペース。空文脈行は " " のみ）
				text := line
				if strings.HasPrefix(line, " ") {
					text = line[1:]
				}
				if cur != nil {
					cur.Lines = append(cur.Lines, diffLine{Line: newLine, Text: text, Added: false})
				}
				newLine++
				newRemaining--
				oldRemaining--
			}
			continue
		}
		// ヘッダ領域。
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
			// 旧ファイルパス。'-' 始まりだが削除行ではないので何もしない。
		case strings.HasPrefix(line, "@@ "):
			flush()
			var newStart int
			newStart, newRemaining, oldRemaining = parseHunkHeader(line)
			// 新ファイル開始行が不正（標準 git では非到達）なら hunk を作らず、
			// Line:0 の finding が出ないようにする。本文はカウントで読み飛ばす。
			if file != "" && newStart >= 1 {
				cur = &fileHunk{File: file}
				newLine = newStart
			}
		}
	}
	flush()
	return hunks
}

// parseHunkHeader は hunk ヘッダ（例: @@ -10,2 +15,3 @@ func）から新ファイル側の
// 開始行番号・新ファイル行数・旧ファイル行数を取り出す。個数省略時は 1。
// 関数名コンテキスト（2 つ目の @@ 以降）に紛れた +/- を誤読しないよう、
// @@ と @@ の間のレンジ部だけを解析する。
func parseHunkHeader(line string) (newStart, newCount, oldCount int) {
	newStart, newCount, oldCount = 0, 1, 1
	inner := line
	if i := strings.Index(inner, "@@"); i >= 0 {
		inner = inner[i+2:]
	}
	if i := strings.Index(inner, "@@"); i >= 0 {
		inner = inner[:i]
	}
	for tok := range strings.FieldsSeq(inner) {
		if rest, ok := strings.CutPrefix(tok, "+"); ok {
			newStart, newCount = parseStartCount(rest)
		} else if rest, ok := strings.CutPrefix(tok, "-"); ok {
			_, oldCount = parseStartCount(rest)
		}
	}
	return
}

// parseStartCount は "15,3" や "15" を start=15, count=3（省略時 1）に分解する。
func parseStartCount(s string) (start, count int) {
	count = 1
	if i := strings.IndexByte(s, ','); i >= 0 {
		if n, err := strconv.Atoi(s[i+1:]); err == nil {
			count = n
		}
		s = s[:i]
	}
	if n, err := strconv.Atoi(s); err == nil {
		start = n
	}
	return
}
