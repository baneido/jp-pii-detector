package cli

import (
	"io"
	"sort"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/rule"
	"github.com/baneido/jp-pii-detector/internal/source"
)

// ScanInfo は走査の内容を Hooks.AfterScan へ渡す。
type ScanInfo struct {
	// Mode は "full" / "paths"（位置引数）/ "stdin" / "staged" / "diff"。
	// 位置引数での走査は従来どおりサマリー上 "full" と表示されるが、Paths が
	// 実際に走査したパスを持つ。
	Mode      string
	Paths     []string
	DiffRange string
	StdinText string
	cfg       *config.Config
}

// Files は Mode が full / paths のとき、PII 走査と同じ規則で選んだ走査対象ファイルを返す。
func (si ScanInfo) Files() ([]string, error) {
	if len(si.Paths) == 0 {
		return nil, nil
	}
	return source.ListFiles(si.cfg, si.Paths)
}

// PathAllowed はリポジトリルート相対パスが [allowlist] paths 等で除外されていなければ true。
func (si ScanInfo) PathAllowed(repoPath string) bool { return si.cfg.PathAllowed(repoPath) }

// ValueAllowed は検出値が [allowlist] regexes / stopwords に一致すれば false を返す。
func (si ScanInfo) ValueAllowed(value string) bool { return valueAllowed(si.cfg, value) }

func valueAllowed(cfg *config.Config, value string) bool {
	for _, w := range cfg.Allowlist.Stopwords {
		if value == w {
			return false
		}
	}
	for _, re := range cfg.AllowRegexes() {
		if re.MatchString(value) {
			return false
		}
	}
	return true
}

// Renderer は追加の出力形式。salt は fingerprint 用（空なら fingerprint なし）。
type Renderer func(w io.Writer, findings []detect.Finding, unmask bool, salt string) error

// Hooks は jp-pii-detect を組み込むプログラムが scan の流れに処理を足すための
// 拡張点。ゼロ値（または nil）なら従来の動作・出力・終了コードと完全に同じ。
type Hooks struct {
	// AfterScan は PII 走査の直後に呼ばれ、追加の検出と警告を返す
	// （警告は従来の読み取りエラーと同じく exit 2 になる）。
	AfterScan func(ScanInfo) ([]detect.Finding, []error, error)
	// Suppress は baseline 判定の前に呼ばれ、除外する検出を取り除く。
	Suppress func([]detect.Finding) (kept, suppressed []detect.Finding)
	// FingerprintSalt は --baseline 未指定時に json 出力の fingerprint に使う salt。
	FingerprintSalt string
	// ExtraRules は sarif の driver.rules に追加するルール定義。
	ExtraRules []rule.Rule
	// Formats は追加の出力形式（既存の形式名を指定すると上書きする）。
	Formats map[string]Renderer
}

func (h *Hooks) formatNames() string {
	var names []string
	for n := range h.Formats {
		if !validFormat(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return "|" + strings.Join(names, "|")
}
