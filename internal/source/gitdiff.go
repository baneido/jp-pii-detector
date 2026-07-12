package source

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
)

// ScanStaged は git のステージ済み変更の追加行を走査する（pre-commit 用）。
// CSV/TSV 列コンテキストの post-image ヘッダは `git show :<path>`（インデックスの
// stage 0 = ステージ済み内容）で取得するため、csvHeaderRevSpec は空文字を渡す
// （fetchCSVHeader 参照。"" + ":path" = ":path"）。
func ScanStaged(d *detect.Detector, cfg *config.Config) ([]detect.Finding, error) {
	return scanGitDiff(d, cfg, []string{"--staged"}, "", true)
}

// ScanDiff は指定リビジョン範囲（例: origin/main...HEAD）の追加行を走査する（CI 用）。
// CSV/TSV 列コンテキストの post-image ヘッダは diffRange の右辺（post-image を
// 指すリビジョン）から取得する。diffRangePostRevision で解決できない場合
// （裸のリビジョンなど）は csvHeaderRevOK=false となり、scanGitDiff はヘッダ取得を
// 試みず列コンテキストなしにフォールバックする。
func ScanDiff(d *detect.Detector, cfg *config.Config, diffRange string) ([]detect.Finding, error) {
	rev, ok := diffRangePostRevision(diffRange)
	return scanGitDiff(d, cfg, []string{diffRange}, rev, ok)
}

// csvHeaderRevSpec/csvHeaderRevOK は CSV/TSV の post-image ヘッダ行を
// `git show <csvHeaderRevSpec>:<path>` で取得する際に使うリビジョン式
// （ScanStaged/ScanDiff がそれぞれの post-image に応じて解決する）。
// csvHeaderRevOK=false は「単一のリビジョンを解決できない」ことを表し、
// この呼び出し全体でヘッダ取得を行わない（列コンテキストなしの安全側）。
func scanGitDiff(d *detect.Detector, cfg *config.Config, extra []string, csvHeaderRevSpec string, csvHeaderRevOK bool) ([]detect.Finding, error) {
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
	// CSV/TSV ファイルの post-image ヘッダ行（1 行目）を、実際にそのファイルの
	// hunk が現れたときだけ遅延取得してファイルパスごとにキャッシュする（1 ファイルに
	// 複数 hunk があっても git show の呼び出しは 1 回で済む）。ヘッダ自体を使わない
	// 呼び出し（csvHeaderRevOK=false・CSV/TSV を含まない diff）では一切 git show を
	// 呼ばない。
	headerCache := map[string]string{}
	var findings []detect.Finding
	for _, h := range parseDiffHunks(string(out)) {
		findings = append(findings, scanHunk(d, cfg, h, csvHeaderRevSpec, csvHeaderRevOK, headerCache)...)
	}
	return findings, nil
}

// scanHunk は 1 つの diff hunk を走査し、検出値が追加行に乗っているものだけを
// 報告する。文脈行（未変更行）はラベル等のコンテキストを補うために走査対象へ
// 含めるが、文脈行上で完結する検出（既存 PII）は新規追加ではないため除外する。
func scanHunk(d *detect.Detector, cfg *config.Config, h fileHunk, csvHeaderRevSpec string, csvHeaderRevOK bool, headerCache map[string]string) []detect.Finding {
	if h.File == "" || !cfg.PathAllowed(h.File) {
		return nil
	}
	dlines := make([]detect.DiffLine, len(h.Lines))
	for i, l := range h.Lines {
		dlines[i] = detect.DiffLine{Text: l.Text, Added: l.Added}
	}
	// CSV/TSV の列コンテキスト（internal/detect/csv_context.go）は post-image の
	// ヘッダ行を要求するが、hunk は変更箇所がファイル先頭付近でない限りヘッダ行を
	// 含まない。git show で個別取得できたときだけ ScanDiffHunkWithCSVHeader へ渡し、
	// 取得できなければ（csvHeaderRevOK=false・非 CSV・取得失敗・ヘッダ行らしくない
	// 等）空文字のまま渡す — detect.ScanDiffHunkWithCSVHeader はそれを
	// ScanDiffHunk と同じ「列コンテキストなし」として扱う。
	var csvHeader string
	if csvHeaderRevOK && detect.IsCSVOrTSVPath(h.File) {
		csvHeader = cachedCSVHeader(headerCache, csvHeaderRevSpec, h.File)
	}
	var findings []detect.Finding
	// ScanDiffHunkWithCSVHeader は検出値が追加行に乗る finding だけを返す（文脈行は
	// 正のコンテキスト補完にのみ使う）。行番号はウィンドウ内 1 始まりなので、
	// 元ファイルの行番号へ写像する。
	for _, f := range d.ScanDiffHunkWithCSVHeader(h.File, dlines, csvHeader) {
		idx := f.Line - 1
		if idx < 0 || idx >= len(h.Lines) {
			continue
		}
		f.Line = h.Lines[idx].Line
		findings = append(findings, f)
	}
	return findings
}

// diffRangePostRevision は `--diff <range>` の range 文字列から、post-image
// （新しい側 = diff の "+" 側）を指す単一のリビジョンを取り出す。ScanDiff は
// range をそのまま 1 個の git diff 引数として渡す（git 自身が "A..B" /
// "A...B" のドット記法を解釈する。scanGitDiff 参照）ため、ここでも同じ文字列を
// 解析する。二点（"A..B"）・三点（"A...B"）のいずれも右辺が post-image を
// 指すため、最初に出現した方の区切りで分割し右辺を使う（"..." は ".." を
// 含むため先に調べる）。右辺省略時（"A.."・"A..." 等）は git 自身の既定動作に
// ならい HEAD を補う。
//
// ドットを含まない裸のリビジョン（例: "abc123"）は git diff 的には作業ツリーとの
// 比較になり、単一のリビジョンを指せないため ok=false を返す（呼び出し側は
// ヘッダ取得を諦め、列コンテキストなしの安全側にフォールバックする）。この
// ツールが文書化する --diff の使用例は常に "origin/main...HEAD" のような
// 二点/三点記法であり（README・docs/integrations.md 等）、裸のリビジョンは
// 通常の利用形ではないため、この安全側フォールバックによる機能低下は実運用上
// 問題にならない想定。
func diffRangePostRevision(diffRange string) (rev string, ok bool) {
	s := strings.TrimSpace(diffRange)
	sep := "..."
	i := strings.Index(s, sep)
	if i < 0 {
		sep = ".."
		i = strings.Index(s, sep)
	}
	if i < 0 {
		return "", false
	}
	rev = strings.TrimSpace(s[i+len(sep):])
	if rev == "" {
		rev = "HEAD"
	}
	return rev, true
}

// cachedCSVHeader は fetchCSVHeader の結果をファイルパスごとにキャッシュする。
func cachedCSVHeader(cache map[string]string, revSpec, path string) string {
	if header, ok := cache[path]; ok {
		return header
	}
	header := fetchCSVHeader(revSpec, path)
	cache[path] = header
	return header
}

// fetchCSVHeader は post-image の 1 行目（ヘッダ想定）を
// `git show <revSpec>:<path>` で取得する。revSpec=="" なら ":<path>"
// （インデックスの stage 0 = --staged の post-image）になる。
//
// path は diff hunk のヘッダ（"+++ b/..."）由来で常にリポジトリルート相対
// （gitrevisions(7): "<rev>:<path>" の <path> は "./"/"../" 接頭辞がない限り
// リポジトリルート相対に解釈される）なので、走査時のカレントディレクトリに
// 関わらずそのまま使える。
//
// 取得失敗（新規ファイルが対象リビジョンにまだ存在しない・マージ未解決で
// stage 0 が無い等）・バイナリ・空はすべて "" を返す。呼び出し側
// （detect.ScanDiffHunkWithCSVHeader）はこれを「列コンテキストなし」として扱う
// 安全側デフォルトなので、ここでは git diff 本体のエラーとして呼び出し元へ
// 伝播させない — ヘッダ取得は列コンテキストを広げるためだけのベストエフォートな
// 補助機能であり、失敗のたびに走査全体を止めるべきではないため。
func fetchCSVHeader(revSpec, path string) string {
	out, err := exec.Command("git", "show", revSpec+":"+path).Output()
	if err != nil {
		return ""
	}
	if isBinary(out) {
		return ""
	}
	return firstLine(out)
}

// firstLine は git show の出力（バイト列）から 1 行目だけを取り出す
// （CRLF の \r も取り除く）。ヘッダ行らしいかどうかの判定自体は呼び出し先の
// detect.ScanDiffHunkWithCSVHeader（内部的には parseCSVHeader/looksLikeCSVHeader）
// に委ねる。
func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSuffix(string(b), "\r")
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
