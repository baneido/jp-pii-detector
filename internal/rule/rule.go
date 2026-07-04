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
	// Validate はこのパターン固有の追加検証（nil なら検証なし）。
	// ルール全体の Rule.Validate に加えて適用され、パターンごとに
	// 異なる検証（例: 氏名の弱いラベルだけ姓名辞書で照合する）を
	// 行うために使う。引数は正規化済みのマッチ文字列。
	Validate func(match string) bool
}

// Prefilter は行単位の事前判定。正規化済みの行に必要な文字種が
// 含まれない場合、そのルールの正規表現マッチをまるごとスキップする
// （性能最適化）。既定の PrefilterNone は常に走査する安全側の値。
type Prefilter int

const (
	// PrefilterNone は常に走査する（既定）。
	PrefilterNone Prefilter = iota
	// PrefilterDigit は ASCII 数字を含む行のみ走査する。
	// 全角数字は事前判定の前に正規化で半角になっている。
	PrefilterDigit
	// PrefilterAt は '@' を含む行のみ走査する（メールアドレス用）。
	PrefilterAt
	// PrefilterCJK は U+3000 以上の文字（日本語等）を含む行のみ走査する。
	PrefilterCJK
)

// Rule は 1 種類の PII に対応する検出ルール。
type Rule struct {
	ID          string
	Description string
	// Context は信頼度昇格・RequireContext 判定に使う周辺キーワード。
	// 小文字で定義し、ASCII 語は単語境界つき、日本語語は部分一致で評価する。
	Context []string
	// NegativeContext は同一行（または近傍）に存在する場合に検出を
	// 棄却する語。金額・数量・連番 ID など PII でない数字列の文脈を表す。
	// 各語がどの近接判定（値の直前隣接・直後隣接・±window 汎用一致）で
	// 扱われるかは ClassifyNegativeKeyword（negative_context.go）が単一の
	// 情報源として分類する。
	NegativeContext []string
	// RequireContextWindow は RequireContext の肯定語をマッチ前後の
	// ルーン数に限定する。0 の場合は後方互換のため行全体を見る。
	RequireContextWindow int
	// Prefilter はパターンがマッチし得ない行を走査前に除外する事前判定。
	// パターンの必須文字種（数字など）を含まない行をスキップする。
	Prefilter Prefilter
	// PrefilterLiterals は、いずれか 1 つも正規化済みの行に含まれなければ
	// このルールの正規表現走査をまるごとスキップするリテラル集合（OR 条件）。
	// 全パターンが特定のラベル語（氏名の「名」「姓」「name」等）を必須とする
	// ルールで、語を含まない大量の行（日本語コメント等）の正規表現評価を
	// 避けるための最適化。空なら無効。ASCII 語は大小文字を区別しない
	// （internal/detect の containsAnyLiteral が判定する。パターン側の
	// `(?i:...)` ラベルに大文字表記が到達できるようにするため）。リテラルは
	// 小文字で定義すること。
	PrefilterLiterals []string
	// Validate はマッチ文字列の追加検証（チェックディジット等）。
	// nil の場合は常に有効。引数は正規化済みのマッチ文字列。
	Validate func(match string) bool
	Patterns []Pattern
}
