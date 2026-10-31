// Package jppii は jp-pii-detector の検出エンジンを他の Go プログラムから
// 使うための公開 API（安定化前の試験的なファサード）。
//
// 検出ロジックそのものは internal/ 以下にあり、このパッケージは CLI
// （cmd/jp-pii-detect）と同じ手順で設定の読み込み・検出器の構築・走査を行う
// 薄い窓口に徹する。検出結果・終了コードの意味は CLI と同じで、検出値の
// マスクと baseline と同じ salt つき HMAC の fingerprint も提供する。
//
// 互換性: v1.0 までは API が変わる可能性がある（docs/roadmap.md の互換性
// 方針の対象外）。
package jppii

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/baseline"
	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/external"
	"github.com/baneido/jp-pii-detector/internal/model"
	"github.com/baneido/jp-pii-detector/internal/report"
	"github.com/baneido/jp-pii-detector/internal/rule"
	"github.com/baneido/jp-pii-detector/internal/source"
)

// ConfigFileName は既定の設定ファイル名（.jp-pii.toml）。
const ConfigFileName = config.DefaultFileName

// Options は Scanner の構築オプション。ゼロ値は CLI の既定と同じ。
type Options struct {
	// ConfigPath は設定ファイルのパス。空ならカレントディレクトリから
	// リポジトリルートまで .jp-pii.toml を上方探索する（CLI と同じ）。
	ConfigPath string
	// ConfigTOML が nil でなければ、ファイルを読まずにこの TOML を設定として
	// 使う（ConfigPath より優先）。設定を合成してから渡す利用者向け。
	ConfigTOML *string
	// MinConfidence は報告する最小信頼度（low|medium|high）。空なら設定値。
	MinConfidence string
	// FailOn は終了判定用の最小信頼度。空なら MinConfidence と同じ。
	FailOn string
	// HighRecall / NameRoster は CLI の --high-recall / --name-roster と同じ。
	HighRecall bool
	NameRoster bool
	// NoGitignore は CLI の --no-gitignore と同じ。
	NoGitignore bool
	// ModelDir が空でなければ Sumi（ONNX）モデルを読み込む。-tags ort かつ
	// cgo 有効でビルドしたバイナリでのみ使える。
	ModelDir  string
	ModelFull bool

	// 以下は後から足したオプション。ゼロ値なら従来と同じ動きになる。

	// DisableIgnoreMarkers を true にすると、行内の ignore マーカー
	// （jp-pii-detector:ignore と旧 pii-allow）がある行も検出する。既定（false）は
	// 従来どおり、マーカーのある行を検出しない。CLI に対応するフラグはない。
	// 検出の結果を返すだけで、入力を書き換えることはない。
	DisableIgnoreMarkers bool
	// NoDecodeEscapes を true にすると、ScanText が JSON の \uXXXX エスケープを
	// 読める形に戻してから走査する前処理（--stdin と同じ）を行わない。
	// Finding.Offset などの位置を、渡した text の位置としていつも受け取りたい
	// 呼び出し側向け。既定（false）は従来どおりエスケープを戻す。
	NoDecodeEscapes bool
}

// Finding は 1 件の検出。Match は生値なので、表示・保存の前に必ず Masked を使うこと。
type Finding struct {
	RuleID      string
	Description string
	// File は報告用のパス（CLI の出力と同じ）。
	File string
	// RepoPath はリポジトリルートからのスラッシュ区切り相対パス（fingerprint
	// 計算用）。リポジトリ外のパスは File と同じ。
	RepoPath   string
	Line       int // 1 始まり
	Column     int // 1 始まり（ルーン単位）
	Match      string
	Confidence string // low|medium|high

	// 以下は後から足した項目。既存の項目の値と意味は変えていない。

	// Kind は検出の大きな種別。このパッケージの走査では常に "pii"。
	Kind string
	// SubKind はルールごとの細かい種別（例: jp-phone-number の mobile・fixed・
	// service・ip・international）。そのルールに細かい種別がなければ空。
	SubKind string
	// Reason は検出の根拠（ルール・モデル・外部の認識器のどれが見つけたか）。
	Reason Reason
	// HasOffset が true のとき、Offset/EndOffset と ByteOffset/ByteEndOffset に
	// 位置が入る。位置が入るのは ScanText の結果だけで、ScanPaths・ScanStaged・
	// ScanDiff では常に false（ファイルは文字コードの変換をしてから走査するため）。
	// ScanText でも、JSON のエスケープを戻して走査した場合（Result.EscapesDecoded）
	// は、渡した text の中の位置にならないので false になる。
	HasOffset bool
	// Offset/EndOffset は ScanText に渡した text の先頭から数えた、文字（ルーン）
	// 単位の半開区間 [Offset, EndOffset)。先頭の BOM も 1 文字として数える。
	Offset    int
	EndOffset int
	// ByteOffset/ByteEndOffset は同じ区間を UTF-8 のバイト単位で表したもの。
	// HasOffset が true なら text[ByteOffset:ByteEndOffset] == Match が成り立つ。
	ByteOffset    int
	ByteEndOffset int
}

// 検出の根拠（Reason.Source）の値。
const (
	SourceRule     = "rule"     // 組み込みルールまたは設定のカスタムルール
	SourceModel    = "model"    // ローカルの推論モデル（Sumi、Options.ModelDir）
	SourceExternal = "external" // 設定の [external_recognizer] の外部コマンド
)

// Reason は 1 件の検出の根拠（CLI の --explain が表示する情報の一部）。
// Finding を == で比べたり map のキーにしたりする既存のコードが壊れないよう、
// 比較できる型（文字列と真偽値）だけで作る。
type Reason struct {
	// Source は検出した仕組み（SourceRule・SourceModel・SourceExternal）。
	Source string
	// Model / External は Source が SourceModel / SourceExternal のとき true。
	Model    bool
	External bool
	// Validated はチェックサムなどの検証に通ったとき true。
	Validated bool
	// ContextPromoted は周りのキーワードで信頼度が上がったとき true。
	ContextPromoted bool
	// CooccurrenceBoosted は近くにある別の種類の検出によって信頼度が上がったとき true。
	CooccurrenceBoosted bool
	// PathDemoted はテスト用のパス（testdata/ など）にあるため信頼度が下がったとき true。
	PathDemoted bool
	// BaseConfidence / FinalConfidence は調整前と調整後の信頼度（low|medium|high、
	// 記録がなければ空）。
	BaseConfidence  string
	FinalConfidence string
}

// Masked は検出値を CLI の既定と同じ規則で伏せ字にした文字列を返す。
func (f Finding) Masked() string { return report.Mask(f.Match) }

// Fingerprint は baseline と同じ salt つき HMAC-SHA256 の fingerprint を返す。
func (f Finding) Fingerprint(salt string) string {
	return baseline.Fingerprint(salt, f.RuleID, f.RepoPath, f.Match)
}

// Stats は走査の統計（フルスキャン時のみ値が入る）。
type Stats struct {
	FilesDiscovered int
	FilesScanned    int
	SkippedFiles    int
	ExcludedPaths   int
}

// ErrExternalMaxFindings は外部レコグナイザの候補が max_findings の上限を超え、
// 超過分を読み捨てたことを表す。Result.Warnings の要素や
// ScanInfo.ExternalMaxFindingsExceeded() の戻り値に errors.Is で使う。
var ErrExternalMaxFindings = external.ErrMaxFindingsExceeded

// Result は走査結果。Warnings が空でなければ走査は不完全（CLI では exit 2）。
type Result struct {
	Findings []Finding
	Warnings []error
	Stats    Stats

	// 以下は ScanText だけが設定する（後から足した項目）。
	// BOMStripped は text の先頭の BOM を除いて走査したとき true。
	BOMStripped bool
	// EscapesDecoded は JSON の \uXXXX エスケープを戻して走査したとき true。
	// このとき Finding の位置は入らない（HasOffset が false）。
	EscapesDecoded bool
}

// RuleInfo は検出ルールの説明。
type RuleInfo struct {
	ID          string
	Description string
	Enabled     bool
	HighRecall  bool
}

// Scanner は設定済みの検出器。並行に使わないこと（1 走査ずつ）。
type Scanner struct {
	cfg             *config.Config
	det             *detect.Detector
	rec             *model.Recognizer
	reportAt        rule.Confidence
	noDecodeEscapes bool
}

// NewScanner は Options から Scanner を構築する。
func NewScanner(opts Options) (*Scanner, error) {
	var cfg *config.Config
	var err error
	if opts.ConfigTOML != nil {
		cfg, err = config.Parse(*opts.ConfigTOML)
	} else {
		cfg, err = config.Load(opts.ConfigPath)
	}
	if err != nil {
		return nil, err
	}
	if opts.MinConfidence != "" {
		cfg.MinConfidence = opts.MinConfidence
	}
	if opts.NoGitignore {
		cfg.SetRespectGitignore(false)
	}
	if opts.HighRecall {
		cfg.SetHighRecall(true)
	}
	if opts.NameRoster {
		cfg.SetNameRoster(true)
	}
	reportAt, err := rule.ParseConfidence(cfg.MinConfidence)
	if err != nil {
		return nil, fmt.Errorf("min_confidence: %w", err)
	}
	det, err := detect.New(cfg)
	if err != nil {
		return nil, err
	}
	if opts.FailOn != "" {
		t, err := rule.ParseConfidence(opts.FailOn)
		if err != nil {
			return nil, fmt.Errorf("fail_on: %w", err)
		}
		det.SetScanMinConfidence(t)
	}
	if opts.DisableIgnoreMarkers {
		det.SetIgnoreMarkersEnabled(false)
	}
	s := &Scanner{cfg: cfg, det: det, reportAt: reportAt, noDecodeEscapes: opts.NoDecodeEscapes}
	if opts.ModelDir != "" {
		rec, err := model.Open(opts.ModelDir)
		if err != nil {
			return nil, fmt.Errorf("model: %w", err)
		}
		rec.SetFullScan(opts.ModelFull)
		det.SetModel(rec)
		s.rec = rec
	}
	return s, nil
}

// Close はモデル等の資源を解放する。
func (s *Scanner) Close() error {
	if s.rec != nil {
		return s.rec.Close()
	}
	return nil
}

// ConfigWarnings は設定の非致命的な警告（未知のキーなど）を返す。
func (s *Scanner) ConfigWarnings() []string { return s.cfg.Warnings() }

// MinConfidence は報告に使う最小信頼度を返す。
func (s *Scanner) MinConfidence() string { return s.reportAt.String() }

// ScanPaths はパス配下をフルスキャンする（CLI の scan [path...]）。
func (s *Scanner) ScanPaths(paths []string) (Result, error) {
	if len(paths) == 0 {
		paths = []string{"."}
	}
	fs, warns, st, err := source.ScanPathsWithStats(s.det, s.cfg, paths)
	if err != nil {
		return Result{}, err
	}
	if st.ExternalTruncated != nil {
		warns = append(warns, fmt.Errorf("external-recognizer: %w", st.ExternalTruncated))
	}
	res := Result{Findings: s.convert(fs, RepoRelativeFunc()), Warnings: warns}
	res.Stats = Stats{FilesDiscovered: st.FilesDiscovered, FilesScanned: st.FilesScanned, SkippedFiles: st.SkippedBinary + st.SkippedTooLarge, ExcludedPaths: st.ExcludedPaths + st.ExcludedDefaultDirs + st.ExcludedGitignored}
	return s.withModelErr(res), nil
}

// ScanStaged は git のステージ済み追加行を走査する（--staged）。
func (s *Scanner) ScanStaged() (Result, error) {
	fs, err := source.ScanStaged(s.det, s.cfg)
	if err != nil {
		return Result{}, err
	}
	return s.withModelErr(Result{Findings: s.convert(fs, nil)}), nil
}

// ScanDiff は git diff の追加行を走査する（--diff <range>）。
func (s *Scanner) ScanDiff(diffRange string) (Result, error) {
	fs, err := source.ScanDiff(s.det, s.cfg, diffRange)
	if err != nil {
		return Result{}, err
	}
	return s.withModelErr(Result{Findings: s.convert(fs, nil)}), nil
}

// ScanText はテキスト 1 本を走査する（--stdin と同じ前処理）。name は報告用の名前。
func (s *Scanner) ScanText(name, text string) Result {
	input := text
	text = strings.TrimPrefix(text, "\uFEFF")
	bomStripped := len(text) != len(input)
	escapesDecoded := false
	if !s.noDecodeEscapes {
		if decoded, ok := source.DecodeEscapedView(text); ok {
			text = decoded
			escapesDecoded = true
		}
	}
	fs := s.det.ScanContent(name, text)
	var warns []error
	if s.cfg.ExternalRecognizerEnabled() {
		o := external.RunDetailed(context.Background(), s.cfg.ExternalRecognizerConfig(), []external.FileInput{{File: name, Text: text}})
		for _, d := range o.Diagnostics {
			if o.Truncated != nil && d == o.Truncated.Error() {
				continue // 下で ErrExternalMaxFindings として 1 件だけ入れる
			}
			warns = append(warns, errors.New("external-recognizer: "+d))
		}
		if o.Truncated != nil {
			warns = append(warns, fmt.Errorf("external-recognizer: %w", o.Truncated))
		}
		if len(o.Candidates) > 0 {
			fs = s.det.MergeExternalFindings(name, text, fs, o.Candidates)
		}
	}
	res := Result{Findings: s.convert(fs, nil), Warnings: warns, BOMStripped: bomStripped, EscapesDecoded: escapesDecoded}
	if !escapesDecoded {
		setOffsets(res.Findings, fs, input, text, bomStripped)
	}
	return s.withModelErr(res)
}

// setOffsets は ScanText の検出に、渡された text（input）の中の位置を付ける。
// scanned は実際に走査した文字列（input から先頭の BOM を除いたもの）。
// 計算した区間の文字列が Match と一致しない検出には位置を付けない。
func setOffsets(out []Finding, in []detect.Finding, input, scanned string, bomStripped bool) {
	in = detect.ComputeOffsets(scanned, append([]detect.Finding(nil), in...))
	runeShift, byteShift := 0, 0
	if bomStripped {
		runeShift, byteShift = 1, len("\uFEFF")
	}
	var idx runeByteIndex
	for i := range in {
		if i >= len(out) || !in[i].HasOffset {
			continue
		}
		bs, ok1 := idx.byteAt(scanned, in[i].Offset)
		be, ok2 := idx.byteAt(scanned, in[i].EndOffset)
		if !ok1 || !ok2 || scanned[bs:be] != in[i].Match {
			continue
		}
		f := &out[i]
		f.HasOffset = true
		f.Offset, f.EndOffset = in[i].Offset+runeShift, in[i].EndOffset+runeShift
		f.ByteOffset, f.ByteEndOffset = bs+byteShift, be+byteShift
	}
}

// runeByteIndex は文字（ルーン）位置からバイト位置への変換表を遅延して作る。
type runeByteIndex struct{ starts []int }

func (x *runeByteIndex) byteAt(s string, r int) (int, bool) {
	if x.starts == nil {
		x.starts = make([]int, 0, len(s)+1)
		for b := range s {
			x.starts = append(x.starts, b)
		}
		x.starts = append(x.starts, len(s))
	}
	if r < 0 || r >= len(x.starts) {
		return 0, false
	}
	return x.starts[r], true
}

// Rules は実効ルール（カスタムルールを含む）の一覧を返す。
func (s *Scanner) Rules() []RuleInfo {
	disabled := map[string]bool{}
	for _, id := range s.cfg.Rules.Disabled {
		disabled[id] = true
	}
	hr := map[string]bool{}
	for _, id := range rule.HighRecallRuleIDs() {
		hr[id] = true
	}
	all := append([]rule.Rule{}, rule.Builtin()...)
	all = append(all, s.cfg.CustomRules()...)
	seen := map[string]bool{}
	var out []RuleInfo
	for _, r := range all {
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		out = append(out, RuleInfo{ID: r.ID, Description: r.Description, Enabled: !disabled[r.ID], HighRecall: hr[r.ID]})
	}
	return out
}

// IsReportable は confidence が報告閾値（MinConfidence）以上かを返す。
// FailOn を MinConfidence より低くした場合の、終了判定用だけの検出を区別する。
func (s *Scanner) IsReportable(confidence string) bool {
	c, err := rule.ParseConfidence(confidence)
	return err == nil && c >= s.reportAt
}

func (s *Scanner) withModelErr(r Result) Result {
	if err := s.det.ModelError(); err != nil {
		r.Warnings = append(r.Warnings, err)
	}
	return r
}

func (s *Scanner) convert(in []detect.Finding, norm func(string) string) []Finding {
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		rp := filepath.ToSlash(f.File)
		if norm != nil {
			rp = norm(f.File)
		}
		kind := f.Kind
		if kind == "" {
			kind = "pii"
		}
		out = append(out, Finding{RuleID: f.RuleID, Description: f.Description, File: f.File, RepoPath: rp, Line: f.Line, Column: f.Column, Match: f.Match, Confidence: f.Confidence.String(),
			Kind: kind, SubKind: f.Reason.Kind, Reason: convertReason(f.Reason)})
	}
	return out
}

func convertReason(r detect.DetectReason) Reason {
	src := SourceRule
	switch {
	case r.Model:
		src = SourceModel
	case r.External:
		src = SourceExternal
	}
	return Reason{Source: src, Model: r.Model, External: r.External, Validated: r.Validated,
		ContextPromoted:     r.ContextPromoted,
		CooccurrenceBoosted: r.CooccurrenceBoosted, PathDemoted: r.PathDemoted,
		BaseConfidence: r.BaseConfidence, FinalConfidence: r.FinalConfidence}
}

// Mask は値を CLI の既定と同じ規則で伏せ字にする。
func Mask(s string) string { return report.Mask(s) }

// Fingerprint は baseline と同じ salt つき HMAC-SHA256 を計算する。
func Fingerprint(salt, ruleID, repoPath, match string) string {
	return baseline.Fingerprint(salt, ruleID, repoPath, match)
}

// NewSalt は fingerprint 用のランダムな salt（16 バイトの 16 進）を返す。
func NewSalt() (string, error) { return baseline.NewSalt() }

// RepoRoot はカレントディレクトリの git リポジトリのルートを返す（git 外なら空）。
func RepoRoot() string { return source.RepoRoot() }

// RepoRelativeFunc は、パスをリポジトリルート相対のスラッシュ区切りに変換する
// 関数を返す（CLI のフルスキャンが baseline fingerprint に使う正規化と同じ）。
func RepoRelativeFunc() func(string) string {
	root := source.RepoRoot()
	return func(path string) string {
		if root == "" {
			return filepath.ToSlash(path)
		}
		abs, err := filepath.Abs(filepath.FromSlash(path))
		if err != nil {
			return filepath.ToSlash(path)
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(path)
		}
		return filepath.ToSlash(rel)
	}
}

// ValidateConfig は TOML 文字列が .jp-pii.toml として読み込めるかを検証し、警告を返す。
func ValidateConfig(data string) ([]string, error) {
	cfg, err := config.Parse(data)
	if err != nil {
		return nil, err
	}
	if _, err := detect.New(cfg); err != nil {
		return nil, err
	}
	return cfg.Warnings(), nil
}

// PathAllowed は repoPath（リポジトリルート相対のスラッシュ区切り）が
// [allowlist] paths で除外されていなければ true を返す（祖先ディレクトリも評価）。
func (s *Scanner) PathAllowed(repoPath string) bool { return s.cfg.PathAllowed(repoPath) }

// ValueAllowed は検出値が [allowlist] regexes / stopwords に一致すれば false を返す。
// 組み込みルール以外の検出器（シークレット検出など）に同じ allowlist を効かせるために使う。
func (s *Scanner) ValueAllowed(value string) bool {
	for _, w := range s.cfg.Allowlist.Stopwords {
		if value == w {
			return false
		}
	}
	for _, re := range s.cfg.AllowRegexes() {
		if re.MatchString(value) {
			return false
		}
	}
	return true
}

// RespectGitignore はフルスキャンが .gitignore を尊重する設定かを返す。
func (s *Scanner) RespectGitignore() bool { return s.cfg.GitignoreRespected() }

// AddedLine は git diff の追加行（リポジトリルート相対パス、新ファイルの行番号）。
type AddedLine = source.AddedLine

// AddedLines は ScanStaged（staged=true）または ScanDiff(diffRange) と同じ git diff の
// 追加行を返す。組み込みルール以外の検出器を同じ範囲に適用するために使う。
func AddedLines(staged bool, diffRange string) ([]AddedLine, error) {
	args := []string{"-c", "core.quotePath=false", "diff", "--no-color", "--no-ext-diff", "-U0", "--src-prefix=a/", "--dst-prefix=b/", "--no-relative", "--diff-filter=ACMRT"}
	if staged {
		args = append(args, "--staged")
	} else {
		args = append(args, diffRange)
	}
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}
	return source.ParseDiff(string(out)), nil
}
