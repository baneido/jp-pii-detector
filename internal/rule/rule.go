// Package rule は検出ルールの型定義と組み込みルールを提供する。
package rule

import (
	"fmt"
	"regexp"
)

// Confidence は検出結果の信頼度。
type Confidence int

const (
	Low Confidence = iota + 1
	Medium
	High
)

func (c Confidence) String() string {
	switch c {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	}
	return "unknown"
}

// ParseConfidence は文字列を Confidence に変換する。
func ParseConfidence(s string) (Confidence, error) {
	switch s {
	case "low":
		return Low, nil
	case "medium":
		return Medium, nil
	case "high":
		return High, nil
	}
	return 0, fmt.Errorf("invalid confidence %q (low|medium|high)", s)
}

// Pattern は 1 つの正規表現パターン。
// 正規表現にキャプチャグループがある場合、グループ 1 を検出対象とする
// （境界ガード `(?:^|[^0-9])` などをグループ外に置くため）。
type Pattern struct {
	Re *regexp.Regexp
	// Base はパターン単体でマッチした場合の信頼度。
	// コンテキストキーワードが同一行にあれば High に昇格する。
	Base Confidence
	// RequireContext が true の場合、コンテキストキーワードが
	// 同一行に存在しなければ検出を破棄する。
	RequireContext bool
}

// Rule は 1 種類の PII に対応する検出ルール。
type Rule struct {
	ID          string
	Description string
	// Context は信頼度昇格・RequireContext 判定に使う周辺キーワード。
	// 小文字で定義し、正規化・小文字化した行に対する部分一致で評価する。
	Context []string
	// Validate はマッチ文字列の追加検証（チェックディジット等）。
	// nil の場合は常に有効。引数は正規化済みのマッチ文字列。
	Validate func(match string) bool
	Patterns []Pattern
}
