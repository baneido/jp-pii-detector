// Package privatecorpus は、評価コーパス（cmd/pii-fixture が公開データセット
// Nemotron-PII-Japan から生成するローカル JSON）を、明示的に指定したファイルから
// 読み込む。合成とはいえ PII の形をした値を大量に含むため、リポジトリには置かず、
// 通常の単体テストからも参照しない。
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
	// EnvVar は評価コーパスのローカルパスを指す。
	EnvVar = "JP_PII_FIXTURES"
	// CurrentSchemaVersion は厳密デコード対象の現行スキーマ。
	CurrentSchemaVersion = 1
)

// Corpus は評価コーパスのファイル形式。
type Corpus struct {
	SchemaVersion int             `json:"schema_version"`
	DatasetID     string          `json:"dataset_id"`
	Dataset       []evalcase.Case `json:"dataset"`
}

// Load は path のコーパスを読み込み、設定済みファイルの不備をエラーにする。
func Load(path string) (*Corpus, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("評価コーパスを開けません: %w", err)
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
		return nil, fmt.Errorf("評価コーパスのJSONが不正です: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return nil, err
	}
	if c.SchemaVersion != CurrentSchemaVersion {
		return nil, fmt.Errorf("評価コーパスの schema_version=%d は未対応です", c.SchemaVersion)
	}
	if c.DatasetID == "" {
		return nil, fmt.Errorf("評価コーパスの dataset_id が空です")
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
		return fmt.Errorf("評価コーパスの末尾が不正です: %w", err)
	}
	return fmt.Errorf("評価コーパスに複数のJSON値があります")
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
		t.Fatalf("評価コーパスを読み込めません（%s=%q）: %v", EnvVar, os.Getenv(EnvVar), err)
	}
	if !configured {
		t.Skipf("評価コーパス未設定のためスキップします（%s にローカルJSONのパスを設定してください）", EnvVar)
	}
	return c
}

// WriteNew は既存ファイルを上書きせず、0600でコーパスを書き出す。
func WriteNew(path string, c *Corpus) (err error) {
	if c == nil || c.SchemaVersion != CurrentSchemaVersion || c.DatasetID == "" {
		return fmt.Errorf("書き出すコーパスのmetadataが不正です")
	}
	if err := evalcase.Validate(c.Dataset); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	_, err = f.Write(b)
	return err
}
