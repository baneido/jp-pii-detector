// Package piifixtures は、実在しうる PII を含むテストデータを
// リポジトリ外（GCS 等）の JSON から読み込む。
//
// 評価データセットや各種ユニットテストが使う「有効な実在形式の個人識別子」
// （携帯電話番号・マイナンバー・住所・氏名など）はリポジトリにコミットせず、
// 環境変数 JP_PII_FIXTURES が指すローカル JSON から読み込む。CI では GitHub
// OIDC → GCP Workload Identity Federation で認証し、gcloud で GCS から取得して
// このパスへ展開する。環境変数が未設定、またはファイルが読めない場合は
// Available() が false を返し、依存テストは Require(t) で Skip される。
//
// JSON スキーマ:
//
//	{
//	  "strings": { "<key>": "<生 PII 文字列>" },
//	  "dataset": [
//	    { "line": "...", "want": ["rule-id"], "spans": [ ... ] },
//	    { "file": "sample.ts", "content": "...\n...", "spans": [ ... ] },
//	    { "diff": [ { "text": "...", "added": true } ], "spans": [ ... ] }
//	  ]
//	}
package piifixtures

import (
	"encoding/json"
	"os"
	"sync"
)

// EnvVar はフィクスチャ JSON のローカルパスを指す環境変数名。
const EnvVar = "JP_PII_FIXTURES"

// Span は 1 件の期待検出範囲。Line は 1 始まりの行番号で、0 は後方互換のため
// 1 行目として扱う。Start/End はその行内の 0 始まりルーンオフセット
// （End は半開区間）。Tags は easy/hard などの層化用メタデータ。
type Span struct {
	RuleID string   `json:"rule_id"`
	Line   int      `json:"line,omitempty"`
	Start  int      `json:"start"`
	End    int      `json:"end"`
	Tags   []string `json:"tags,omitempty"`
	// WantConfidence は任意項目（"low" | "medium" | "high"）。設定すると、この
	// スパンの検出が期待信頼度以上で報告されることを要求する（内部で Base のまま
	// 昇格しない等、低い信頼度に埋もれて既定設定では黙って見えなくなる「実質的な
	// 検出漏れ」を可視化するため）。省略時はこのスパンを信頼度チェックの対象外とする。
	// 後方互換: 既存データセット JSON はこのフィールドを持たないが、
	// encoding/json は未知フィールドを無視して Unmarshal するため、コード側を
	// 先にデプロイしてもデータセット未更新のまま全テストが green のまま動く。
	WantConfidence string `json:"want_confidence,omitempty"`
}

// DiffLine は diff hunk 内の 1 行。Added が true なら追加行、false なら文脈行。
type DiffLine struct {
	Text  string `json:"text"`
	Added bool   `json:"added"`
}

// Case は 1 つの評価ケース。Line / Content / Diff のいずれか 1 つで入力を表す。
// Want または Spans があるケースでは入力指定を必須とし、フィクスチャの指定漏れを
// 検出する。入力も期待値も空のケースは、後方互換のため空行の陰性ケースとして扱う。
// Line は従来どおり 1 行の ScanLine、Content は複数行の ScanContent、Diff は
// 追加行だけを評価する ScanDiffHunk に対応する。Want は、そのケースで検出されるべき
// ルール ID の集合（空なら「何も検出されないべき」陰性ケース）。File は
// ソースコード文脈などファイル名依存の挙動を評価したい場合だけ指定する。Tags は
// Span.Tags と同様、表記ゆれ（notation:fullwidth 等）やケースの由来
// （source:synthetic 等）でケース単位に層別集計するためのメタデータで、検出結果
// そのものには影響せず internal/eval の Stratified 集計にだけ使う。既知タグの
// 語彙は docs/development.md を参照。
type Case struct {
	File    string     `json:"file,omitempty"`
	Line    string     `json:"line,omitempty"`
	Content string     `json:"content,omitempty"`
	Diff    []DiffLine `json:"diff,omitempty"`
	Want    []string   `json:"want,omitempty"`
	Spans   []Span     `json:"spans,omitempty"`
	Tags    []string   `json:"tags,omitempty"`
}

type data struct {
	Strings map[string]string `json:"strings"`
	Dataset []Case            `json:"dataset"`
}

var (
	once    sync.Once
	loaded  *data
	loadErr error
)

func load() {
	once.Do(func() {
		path := os.Getenv(EnvVar)
		if path == "" {
			return
		}
		b, err := os.ReadFile(path)
		if err != nil {
			loadErr = err
			return
		}
		var d data
		if err := json.Unmarshal(b, &d); err != nil {
			loadErr = err
			return
		}
		loaded = &d
	})
}

// Available はフィクスチャ JSON を読み込めたかを返す。
func Available() bool {
	load()
	return loaded != nil
}

// Dataset は評価データセットを返す。第 2 戻り値は取得可否。
func Dataset() ([]Case, bool) {
	load()
	if loaded == nil {
		return nil, false
	}
	return loaded.Dataset, true
}

// Get はキーに対応する生 PII 文字列を返す。第 2 戻り値は存在可否。
func Get(key string) (string, bool) {
	load()
	if loaded == nil {
		return "", false
	}
	v, ok := loaded.Strings[key]
	return v, ok
}

// TB は *testing.T / *testing.B が満たす最小インターフェース。
// piifixtures が testing パッケージを import しないための構造的インターフェース。
type TB interface {
	Helper()
	Skipf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// Require はフィクスチャが無ければテストを Skip する。
func Require(t TB) {
	t.Helper()
	if Available() {
		return
	}
	if loadErr != nil {
		t.Skipf("PII フィクスチャを読み込めません（%s=%q）: %v", EnvVar, os.Getenv(EnvVar), loadErr)
		return
	}
	t.Skipf("PII フィクスチャ未設定のためスキップします（%s にローカル JSON のパスを設定してください）", EnvVar)
}

// MustGet はキーが無ければ Fatal する。Require 済みのテストから使う。
func MustGet(t TB, key string) string {
	t.Helper()
	v, ok := Get(key)
	if !ok {
		t.Fatalf("PII フィクスチャにキー %q がありません（pii-fixtures.json を確認してください）", key)
	}
	return v
}
