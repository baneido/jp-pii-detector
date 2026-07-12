// Package privatecorpus は、採取由来または実在空間と衝突しうる値を含む
// 非公開評価コーパスを、明示的なローカルファイルから読み込む。
package privatecorpus

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/corpusv2"
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
	// 固定済みの初期v2 generationには、後から公知sandbox PANと判明した
	// credit-card正例が含まれる。GCS本文を書き換えず、決定的な互換migrationで
	// 陰性への再分類と不足正例の補完を行う。
	if c.DatasetID == "private-eval-v2" {
		upgraded, err := corpusv2.UpgradePublishedV2(c.Dataset)
		if err != nil {
			return nil, fmt.Errorf("private-eval-v2 の互換migrationに失敗しました: %w", err)
		}
		c.Dataset = upgraded
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

// MigrateLegacy は旧コーパスをversion付きの独立した評価コーパスへ変換する。
// 旧stringsプールは通常テスト移行後の互換データであり、評価ケースから参照されない
// ため引き継がない。ケース本文を識別子へ埋め込むこともない。
func MigrateLegacy(c *Corpus, datasetID, sourceClass string) (*Corpus, error) {
	if c == nil || c.DatasetID != "legacy" {
		return nil, fmt.Errorf("legacyコーパスだけを移行できます")
	}
	if strings.TrimSpace(datasetID) == "" || datasetID == "legacy" {
		return nil, fmt.Errorf("新しいdataset_idを指定してください")
	}
	if strings.TrimSpace(sourceClass) == "" {
		return nil, fmt.Errorf("source_classを指定してください")
	}

	dataset := append([]evalcase.Case(nil), c.Dataset...)
	usedIDs := make(map[string]bool, len(dataset))
	for _, item := range dataset {
		if item.ID != "" {
			usedIDs[item.ID] = true
		}
	}
	nextID := 1
	for i := range dataset {
		if dataset[i].ID == "" {
			for {
				candidate := fmt.Sprintf("private-case-%04d", nextID)
				nextID++
				if !usedIDs[candidate] {
					dataset[i].ID = candidate
					usedIDs[candidate] = true
					break
				}
			}
		}
		if dataset[i].SourceClass == "" {
			dataset[i].SourceClass = sourceClass
		}
	}
	if err := evalcase.Validate(dataset); err != nil {
		return nil, err
	}
	return &Corpus{
		SchemaVersion: CurrentSchemaVersion,
		DatasetID:     datasetID,
		Dataset:       dataset,
	}, nil
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
