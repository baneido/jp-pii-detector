// Package config は設定ファイル（.jp-pii.toml）の読み込みを提供する。
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/BurntSushi/toml"
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
	} `toml:"rules"`
	Allowlist struct {
		// Paths は走査から除外するパスの正規表現。検出結果に報告される
		// パス（フルスキャンは走査ルートを含むパス、git diff は
		// リポジトリ相対パス）に適用する。
		Paths []string `toml:"paths"`
		// Regexes はマッチ文字列に対する除外正規表現。
		Regexes []string `toml:"regexes"`
		// Stopwords はマッチ文字列との完全一致で除外する値。
		Stopwords []string `toml:"stopwords"`
	} `toml:"allowlist"`

	pathRes  []*regexp.Regexp
	allowRes []*regexp.Regexp
}

// Default は既定値の設定を返す。
func Default() *Config {
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
			return Default(), nil
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
	cfg := Default()
	if _, err := toml.Decode(data, cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := cfg.compile(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) compile() error {
	for _, p := range c.Allowlist.Paths {
		re, err := regexp.Compile(p)
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
