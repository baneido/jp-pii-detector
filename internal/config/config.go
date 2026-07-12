// Package config は設定ファイル（.jp-pii.toml）の読み込みを提供する。
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// DefaultFileName は探索する設定ファイル名。
const DefaultFileName = ".jp-pii.toml"

// CustomRule は利用者が定義する追加の検出ルール（[[rules.custom]]）。
// 学籍番号・社員番号など組織固有の ID 形式を、コード変更なしで追加するために使う。
type CustomRule struct {
	// ID はルール識別子。組み込みルールおよび他のカスタムルールと重複できない。
	ID string `toml:"id"`
	// Description は rules コマンド・検出結果に表示される説明。
	Description string `toml:"description"`
	// Pattern は Go の RE2 正規表現。DigitBoundary が false の場合、
	// パターン自身にキャプチャグループがあればグループ 1 を検出値として扱う
	// （builtin ルールの dg()/ag() と同じ規約）。グループがなければマッチ全体を使う。
	Pattern string `toml:"pattern"`
	// Context は信頼度昇格・RequireContext 判定に使う周辺キーワード（小文字）。
	Context []string `toml:"context"`
	// NegativeContext は近傍にあれば検出を棄却する語（金額・件数等）。
	NegativeContext []string `toml:"negative_context"`
	// RequireContext が true の場合、Context のキーワードが無ければ検出を破棄する。
	RequireContext bool `toml:"require_context"`
	// RequireContextWindow は RequireContext の肯定語探索をマッチ前後の
	// ルーン数に限定する。0 の場合は行全体を見る。
	RequireContextWindow int `toml:"require_context_window"`
	// BaseConfidence はパターン単体でマッチした場合の信頼度（low|medium|high）。
	// 省略時は medium。
	BaseConfidence string `toml:"base_confidence"`
	// DigitBoundary が true の場合、パターンを組み込みルールの dg() と同じ
	// 境界ガード `(?:^|[^0-9])(pattern)(?:[^0-9]|$)` で包む。数字エンティティが
	// より長い数字列の一部として誤って切り出されるのを防ぐ。
	DigitBoundary bool `toml:"digit_boundary"`
}

// Config はツール全体の設定。
type Config struct {
	// MinConfidence 未満の検出は報告しない（low|medium|high）。
	MinConfidence string `toml:"min_confidence"`
	Rules         struct {
		// Disabled は無効化するルール ID の一覧。
		Disabled []string `toml:"disabled"`
		// HighRecall は高再現率ルールを明示的に有効化する。
		// 偽陽性リスクが高いため既定では無効。
		HighRecall bool `toml:"high_recall"`
		// CooccurrenceBoost は、氏名系ルール（person-name 等）の Low / Medium
		// 候補を、同一ファイル内の近傍に検証済み/ラベル
		// 付きの高信頼 PII（電話番号・郵便番号・マイナンバー等）があるときだけ
		// 1 段昇格（Low→Medium 等）させる。既存の報告結果を変えないよう、
		// 既定では無効（opt-in）。
		CooccurrenceBoost bool `toml:"cooccurrence_boost"`
		// PathDemotion はテスト経路（testdata/ ・ fixtures/ ・ *_test.go 等）に
		// 対する信頼度降格（Medium→Low、対象は RequireContext かつ Base=Medium の
		// ルールのみ）を有効にする。既定で有効。値そのものを消す除外ではなく、
		// 既定の min_confidence=medium 運用で非表示になる降格に留まるため、
		// --min-confidence low で常に確認できる。無効化すると全ルールが
		// パスに関わらず通常どおりの信頼度で報告される。
		PathDemotion bool `toml:"path_demotion"`
		// ExcludeKinds は Rule.Kind（internal/rule）が返す下位種別のうち、
		// 検出結果から除外する種別の一覧（例: jp-phone-number の PhoneKind が
		// 返す "service" を指定すると、フリーダイヤル等のサービス番号だけを
		// 除外できる）。Kind が未設定のルールには影響しない。既定は空（nil）
		// のため、既存の検出結果は変わらない。
		ExcludeKinds []string `toml:"exclude_kinds"`
		// Custom は利用者定義の追加ルール。
		Custom []CustomRule `toml:"custom"`
	} `toml:"rules"`
	Allowlist struct {
		// Paths は走査から除外するパスの正規表現または glob。検出結果に
		// 報告されるパス（フルスキャンは走査ルートを含むパス、git diff は
		// リポジトリ相対パス）に適用する。フルスキャンではさらに
		// リポジトリルートからの相対パスにも適用されるため、
		// サブディレクトリからの実行でもルート相対の指定が機能する。
		Paths []string `toml:"paths"`
		// Regexes はマッチ文字列に対する除外正規表現。
		Regexes []string `toml:"regexes"`
		// Stopwords はマッチ文字列との完全一致で除外する値。
		Stopwords []string `toml:"stopwords"`
	} `toml:"allowlist"`

	pathRes  []*regexp.Regexp
	allowRes []*regexp.Regexp
	// explicitDisabled は設定ファイル等で明示的に無効化されたルール ID。
	// high_recall の切り替え時に、自動付与した無効化だけを戻すために保持する。
	explicitDisabled []string
	// customRules は Rules.Custom をコンパイルした結果。
	customRules []rule.Rule
	// warnings は Parse 時に検出した非致命的な問題（未知の設定キー等）。
	warnings []string
}

// Default は既定値の設定を返す。
func Default() *Config {
	cfg := defaultConfig()
	cfg.SetHighRecall(false)
	return cfg
}

func defaultConfig() *Config {
	cfg := &Config{MinConfidence: "medium"}
	cfg.Rules.PathDemotion = true
	return cfg
}

// Load は設定ファイルを読み込む。path が空の場合はカレントディレクトリから
// 親方向に DefaultFileName を探す（リポジトリルート =.git のあるディレクトリ
// まで。サブディレクトリからの実行でもリポジトリルートの設定が使われる）。
// 見つからなければ既定値を返す。
func Load(path string) (*Config, error) {
	if path == "" {
		found, err := findUpward()
		if err != nil {
			return nil, err
		}
		if found == "" {
			return Parse("")
		}
		path = found
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return Parse(string(data))
}

// findUpward はカレントディレクトリから親方向に DefaultFileName を探す。
// .git を持つディレクトリ（リポジトリルート）より上には遡らない。
func findUpward() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("config: %w", err)
	}
	for {
		candidate := filepath.Join(dir, DefaultFileName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return "", nil // リポジトリルートに到達
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil // ファイルシステムルートに到達
		}
		dir = parent
	}
}

// Parse は TOML 文字列から設定を構築する。
// 未知の設定キー（typo 等）を検出した場合は、既存の緩い互換性を壊さないよう
// エラーにはせず、標準エラーへ警告を出力する（Warnings でも取得できる）。
func Parse(data string) (*Config, error) {
	cfg := defaultConfig()
	md, err := toml.Decode(data, cfg)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		cfg.warnings = append(cfg.warnings, fmt.Sprintf("未知の設定キーを無視しました: %s", strings.Join(keys, ", ")))
	}
	if err := cfg.compile(); err != nil {
		return nil, err
	}
	for _, w := range cfg.warnings {
		fmt.Fprintf(os.Stderr, "jp-pii-detect: warning: %s\n", w)
	}
	return cfg, nil
}

func (c *Config) compile() error {
	c.explicitDisabled = append([]string{}, c.Rules.Disabled...)
	c.SetHighRecall(c.Rules.HighRecall)
	for _, p := range c.Allowlist.Paths {
		re, err := compilePathPattern(p)
		if err != nil {
			return fmt.Errorf("config: allowlist.paths %q: %w", p, err)
		}
		c.pathRes = append(c.pathRes, re)
	}
	for _, p := range c.Allowlist.Regexes {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("config: allowlist.regexes %q: %w", p, err)
		}
		c.allowRes = append(c.allowRes, re)
	}
	if err := c.compileCustomRules(); err != nil {
		return err
	}
	return nil
}

// compileCustomRules は Rules.Custom をコンパイルし customRules に保持する。
// id の重複（組み込みルールとの衝突を含む）や正規表現のコンパイル失敗は
// 設定エラーとして返し、既存の fail(err) → exit 2 経路に乗せる（パニックさせない）。
func (c *Config) compileCustomRules() error {
	if len(c.Rules.Custom) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, r := range rule.Builtin() {
		seen[r.ID] = true
	}
	for _, cr := range c.Rules.Custom {
		if cr.ID == "" {
			return fmt.Errorf("config: rules.custom: id is required")
		}
		if seen[cr.ID] {
			return fmt.Errorf("config: rules.custom %q: id は組み込みルールまたは他のカスタムルールと重複しています", cr.ID)
		}
		seen[cr.ID] = true
		if cr.Pattern == "" {
			return fmt.Errorf("config: rules.custom %q: pattern is required", cr.ID)
		}
		base := rule.Medium
		if cr.BaseConfidence != "" {
			b, err := rule.ParseConfidence(cr.BaseConfidence)
			if err != nil {
				return fmt.Errorf("config: rules.custom %q: base_confidence: %w", cr.ID, err)
			}
			base = b
		}
		pattern := cr.Pattern
		if cr.DigitBoundary {
			pattern = `(?:^|[^0-9])(` + pattern + `)(?:[^0-9]|$)`
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("config: rules.custom %q: %w", cr.ID, err)
		}
		c.customRules = append(c.customRules, rule.Rule{
			ID:                   cr.ID,
			Description:          cr.Description,
			Context:              cr.Context,
			NegativeContext:      cr.NegativeContext,
			RequireContextWindow: cr.RequireContextWindow,
			Patterns: []rule.Pattern{
				{Re: re, Base: base, RequireContext: cr.RequireContext},
			},
		})
	}
	return nil
}

func compilePathPattern(pattern string) (*regexp.Regexp, error) {
	if looksLikePathGlob(pattern) {
		return compilePathGlob(pattern)
	}
	return regexp.Compile(pattern)
}

func looksLikePathGlob(pattern string) bool {
	if strings.ContainsAny(pattern, `^\(){}+|$`) || strings.Contains(pattern, `.*`) {
		return false
	}
	return strings.Contains(pattern, "**") || strings.ContainsAny(pattern, "*?")
}

func compilePathGlob(pattern string) (*regexp.Regexp, error) {
	pattern = filepath.ToSlash(pattern)
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i += 2
				if i < len(pattern) && pattern[i] == '/' {
					b.WriteString("(?:.*/)?")
					i++
				} else {
					b.WriteString(".*")
				}
				continue
			}
			b.WriteString("[^/]*")
			i++
		case '?':
			b.WriteString("[^/]")
			i++
		default:
			r, size := utf8.DecodeRuneInString(pattern[i:])
			b.WriteString(regexp.QuoteMeta(string(r)))
			i += size
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// SetHighRecall は高再現率ルールの有効/無効を切り替える。
// 明示的に disabled されたルールは維持し、自動で付与した既定無効化だけを更新する。
func (c *Config) SetHighRecall(enabled bool) {
	if c.explicitDisabled == nil {
		c.explicitDisabled = append([]string{}, c.Rules.Disabled...)
	}
	c.Rules.HighRecall = enabled
	c.Rules.Disabled = append([]string{}, c.explicitDisabled...)
	if enabled {
		return
	}
	for _, id := range rule.HighRecallRuleIDs() {
		if !slices.Contains(c.Rules.Disabled, id) {
			c.Rules.Disabled = append(c.Rules.Disabled, id)
		}
	}
}

// PathAllowed はパスが走査対象かどうかを返す（除外なら false）。
func (c *Config) PathAllowed(relPath string) bool {
	for _, re := range c.pathRes {
		if re.MatchString(relPath) {
			return false
		}
	}
	return true
}

// AllowRegexes はコンパイル済みのマッチ除外正規表現を返す。
func (c *Config) AllowRegexes() []*regexp.Regexp { return c.allowRes }

// CustomRules は rules.custom をコンパイルしたルール一覧を返す。
func (c *Config) CustomRules() []rule.Rule { return c.customRules }

// Warnings は Parse 時に検出した非致命的な警告（未知の設定キー等）を返す。
func (c *Config) Warnings() []string { return c.warnings }
