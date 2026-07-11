// Package privatecorpus は、採取由来または実在空間と衝突しうる値を含む
// 非公開評価コーパスを、明示的なローカルファイルから読み込む。
package privatecorpus

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/evalcase"
)

const (
	// EnvVar は非公開評価コーパスのローカルパスを指す。
	EnvVar = "JP_PII_FIXTURES"
	// CurrentSchemaVersion は厳密デコード対象の現行スキーマ。
	CurrentSchemaVersion = 1
)

// Corpus は非公開コーパスのファイル形式。Strings は旧形式を安全に読み替える
// 移行専用フィールドで、新しい単体テストからは参照しない。
type Corpus struct {
	SchemaVersion int               `json:"schema_version,omitempty"`
	DatasetID     string            `json:"dataset_id,omitempty"`
	Strings       map[string]string `json:"strings,omitempty"`
	Dataset       []evalcase.Case   `json:"dataset"`
}

// Load は path のコーパスを読み込み、設定済みファイルの不備をエラーにする。
func Load(path string) (*Corpus, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("非公開評価コーパスを開けません: %w", err)
	}
	defer f.Close()
	return Decode(f)
}

// Decode は未知フィールドを拒否してコーパスを読み込む。
func Decode(r io.Reader) (*Corpus, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var c Corpus
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("非公開評価コーパスのJSONが不正です: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return nil, err
	}
	// 既存GCSオブジェクトを段階移行できるよう、未指定だけは legacy として
	// 読める。新規publishは必ず schema_version / dataset_id を付ける。
	if c.SchemaVersion == 0 {
		c.SchemaVersion = CurrentSchemaVersion
	}
	if c.SchemaVersion != CurrentSchemaVersion {
		return nil, fmt.Errorf("非公開評価コーパスの schema_version=%d は未対応です", c.SchemaVersion)
	}
	if c.DatasetID == "" {
		c.DatasetID = "legacy"
	}
	if err := evalcase.Validate(c.Dataset); err != nil {
		return nil, err
	}
	return &c, nil
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("非公開評価コーパスの末尾が不正です: %w", err)
	}
	return fmt.Errorf("非公開評価コーパスに複数のJSON値があります")
}

// FromEnv は環境変数が未設定なら (nil, false, nil)、設定済みで読み込みに
// 失敗した場合は error を返す。設定済みエラーをSkipへ変換しない。
func FromEnv() (*Corpus, bool, error) {
	path := strings.TrimSpace(os.Getenv(EnvVar))
	if path == "" {
		return nil, false, nil
	}
	c, err := Load(path)
	if err != nil {
		return nil, true, err
	}
	return c, true, nil
}

// TB は *testing.T が満たす最小インターフェース。
type TB interface {
	Helper()
	Skipf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// Require は未設定だけをSkipし、設定済みの読み込み失敗はFatalにする。
func Require(t TB) *Corpus {
	t.Helper()
	c, configured, err := FromEnv()
	if err != nil {
		t.Fatalf("非公開評価コーパスを読み込めません（%s=%q）: %v", EnvVar, os.Getenv(EnvVar), err)
	}
	if !configured {
		t.Skipf("非公開評価コーパス未設定のためスキップします（%s にローカルJSONのパスを設定してください）", EnvVar)
	}
	return c
}
