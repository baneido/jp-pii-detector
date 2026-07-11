// Package piifixtures は旧APIとの互換層である。
//
// 新規コードでは、評価モデルは internal/evalcase、非公開コーパスの読み込みは
// internal/privatecorpus、公開単体テスト値は internal/testfixtures を使うこと。
package piifixtures

import (
	"github.com/baneido/jp-pii-detector/internal/evalcase"
	"github.com/baneido/jp-pii-detector/internal/privatecorpus"
)

const EnvVar = privatecorpus.EnvVar

type (
	Span     = evalcase.Span
	DiffLine = evalcase.DiffLine
	Case     = evalcase.Case
)

// TB は後方互換のテストインターフェース。
type TB = privatecorpus.TB

// Require は非公開コーパスが未設定の場合だけSkipする。
func Require(t TB) { privatecorpus.Require(t) }

// Available は非公開コーパスの設定・読み込み可否を返す。
func Available() bool {
	_, configured, err := privatecorpus.FromEnv()
	return configured && err == nil
}

// Dataset は非公開評価ケースを返す。
func Dataset() ([]Case, bool) {
	c, configured, err := privatecorpus.FromEnv()
	if err != nil || !configured {
		return nil, false
	}
	return c.Dataset, true
}

// Get は旧JSONの strings を読む移行専用API。公開単体テストでは使わない。
func Get(key string) (string, bool) {
	c, configured, err := privatecorpus.FromEnv()
	if err != nil || !configured {
		return "", false
	}
	v, ok := c.Strings[key]
	return v, ok
}

// MustGet は旧API互換。新規テストでは internal/testfixtures を使う。
func MustGet(t TB, key string) string {
	t.Helper()
	v, ok := Get(key)
	if !ok {
		t.Fatalf("非公開評価コーパスに旧fixtureキー %q がありません", key)
	}
	return v
}
