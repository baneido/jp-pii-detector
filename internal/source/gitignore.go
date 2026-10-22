package source

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// gitignoreFilter はフルスキャンで .gitignore 等により無視されるパスを判定する。
//
// 走査ルートが git の作業ツリー内なら git 自身（git ls-files --others --ignored
// --exclude-standard --directory）に無視対象の未追跡パスを列挙させる。.gitignore
// の全意味論（ネスト・否定・.git/info/exclude・core.excludesFile）に加え、
// 「追跡済みファイルは .gitignore にマッチしても対象」という git の挙動もそのまま
// 再現できる。git が使えない・作業ツリー外の場合は、走査中に出会った .gitignore
// ファイルだけを解釈する簡易実装（gitignoreMatcher）にフォールバックする。
type gitignoreFilter struct {
	// ignored は git が列挙した無視対象の絶対パス（ディレクトリは配下全体）。
	ignored map[string]bool
	// useGit は ignored が git の列挙結果である（フォールバックしない）ことを表す。
	useGit bool
	// fallback は git を使えない場合のディレクトリ別パターン（絶対パス → パターン群）。
	fallback map[string][]gitignorePattern
	root     string
}

// newGitignoreFilter は走査ルート root 用のフィルタを作る。
func newGitignoreFilter(root string) *gitignoreFilter {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	f := &gitignoreFilter{root: abs, fallback: map[string][]gitignorePattern{}}
	dir := abs
	if info, err := os.Stat(abs); err == nil && !info.IsDir() {
		dir = filepath.Dir(abs)
	}
	if ignored, ok := gitListIgnored(dir); ok {
		f.ignored = ignored
		f.useGit = true
	}
	return f
}

// gitListIgnored は dir を作業ディレクトリとして git に無視対象の未追跡パスを
// 列挙させ、絶対パスの集合を返す。dir が作業ツリー外・git 不在なら ok=false。
func gitListIgnored(dir string) (map[string]bool, bool) {
	inside, err := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree").Output()
	if err != nil || strings.TrimSpace(string(inside)) != "true" {
		return nil, false
	}
	out, err := exec.Command("git", "-C", dir, "ls-files", "-z", "--others", "--ignored",
		"--exclude-standard", "--directory").Output()
	if err != nil {
		return nil, false
	}
	ignored := map[string]bool{}
	for _, p := range bytes.Split(out, []byte{0}) {
		if len(p) == 0 {
			continue
		}
		rel := strings.TrimSuffix(string(p), "/")
		ignored[filepath.Clean(filepath.Join(dir, filepath.FromSlash(rel)))] = true
	}
	return ignored, true
}

// ignoredPath は path（走査時の表記）が無視対象なら true を返す。isDir は
// path がディレクトリかどうか。ディレクトリが無視対象なら呼び出し元は配下を
// 丸ごとスキップする。走査ルート自身は常に対象（明示指定を優先する）。
func (f *gitignoreFilter) ignoredPath(path string, isDir bool) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	abs = filepath.Clean(abs)
	if abs == f.root {
		return false
	}
	if f.useGit {
		return f.ignored[abs]
	}
	return f.fallbackIgnored(abs, isDir)
}

// fallbackIgnored は root から abs の親までの .gitignore を順に評価する。
// 後に評価したパターン（深いディレクトリ・同一ファイル内の後方）が優先される。
// 祖先ディレクトリが無視されている場合は WalkDir が既に SkipDir しているため、
// ここでは abs 自身だけを判定すればよい。
func (f *gitignoreFilter) fallbackIgnored(abs string, isDir bool) bool {
	ignored := false
	parent := filepath.Dir(abs)
	var dirs []string
	for d := parent; ; d = filepath.Dir(d) {
		dirs = append(dirs, d)
		if d == f.root || filepath.Dir(d) == d || !strings.HasPrefix(d, f.root) {
			break
		}
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		pats, ok := f.fallback[d]
		if !ok {
			pats = loadGitignore(filepath.Join(d, ".gitignore"))
			f.fallback[d] = pats
		}
		rel, err := filepath.Rel(d, abs)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		for _, p := range pats {
			if p.dirOnly && !isDir {
				continue
			}
			if p.re.MatchString(rel) {
				ignored = !p.negate
			}
		}
	}
	return ignored
}

// gitignorePattern は .gitignore の 1 行をコンパイルしたもの。
type gitignorePattern struct {
	re      *regexp.Regexp
	negate  bool
	dirOnly bool
}

func loadGitignore(path string) []gitignorePattern {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	var pats []gitignorePattern
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		if p, ok := parseGitignoreLine(sc.Text()); ok {
			pats = append(pats, p)
		}
	}
	return pats
}

// parseGitignoreLine は gitignore(5) の主要な記法（# コメント・! 否定・末尾 /・
// 先頭や途中の / によるアンカー・* ? [...] **）を正規表現へ変換する。
func parseGitignoreLine(line string) (gitignorePattern, bool) {
	line = strings.TrimRight(line, "\r")
	if !strings.HasSuffix(line, `\ `) {
		line = strings.TrimRight(line, " ")
	}
	if line == "" || strings.HasPrefix(line, "#") {
		return gitignorePattern{}, false
	}
	var p gitignorePattern
	if strings.HasPrefix(line, "!") {
		p.negate = true
		line = line[1:]
	} else if strings.HasPrefix(line, `\`) {
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		p.dirOnly = true
		line = strings.TrimRight(line, "/")
	}
	if line == "" {
		return gitignorePattern{}, false
	}
	anchored := strings.Contains(line, "/")
	line = strings.TrimPrefix(line, "/")
	var b strings.Builder
	if anchored {
		b.WriteString("^")
	} else {
		b.WriteString("^(?:.*/)?")
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '*' && strings.HasPrefix(line[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case c == '*' && strings.HasPrefix(line[i:], "**") && i+2 == len(line):
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		case c == '[':
			j := strings.IndexByte(line[i+1:], ']')
			if j < 0 {
				b.WriteString(`\[`)
				continue
			}
			class := line[i+1 : i+1+j]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
			i += j + 1
		case c == '\\' && i+1 < len(line):
			i++
			b.WriteString(regexp.QuoteMeta(string(line[i])))
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return gitignorePattern{}, false
	}
	p.re = re
	return p, true
}
