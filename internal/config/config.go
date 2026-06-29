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
}

// Default は既定値の設定を返す。
func Default() *Config {
	cfg := defaultConfig()
	cfg.SetHighRecall(false)
	return cfg
}

func defaultConfig() *Config {
	return &Config{MinConfidence: "medium"}
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
func Parse(data string) (*Config, error) {
	cfg := defaultConfig()
	if _, err := toml.Decode(data, cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := cfg.compile(); err != nil {
		return nil, err
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
