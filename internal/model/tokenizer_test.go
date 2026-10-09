package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// modelDirForTest は JP_PII_MODEL_DIR（Sumi のモデルディレクトリ）を返す。
// モデルは数百 MB あるためリポジトリに含めず、未設定ならテストをスキップする
// （非公開評価コーパスの JP_PII_FIXTURES と同じ扱い）。
func modelDirForTest(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("JP_PII_MODEL_DIR")
	if dir == "" {
		t.Skip("JP_PII_MODEL_DIR が未設定のためスキップ")
	}
	return dir
}

type goldenCase struct {
	Name    string   `json:"name"`
	Text    string   `json:"text"`
	IDs     []int64  `json:"ids"`
	Offsets [][2]int `json:"offsets"`
}

// TestTokenizerMatchesHuggingFace は、Hugging Face tokenizers（Python）で生成した
// ID 列と文字オフセットに、Go 実装が token 単位で一致することを確かめる。
// ゴールデンの差し替えは JP_PII_TOKENIZER_GOLDEN で行える（大規模比較用）。
func TestTokenizerMatchesHuggingFace(t *testing.T) {
	tok, err := loadTokenizer(filepath.Join(modelDirForTest(t), "tokenizer.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("JP_PII_TOKENIZER_GOLDEN")
	if path == "" {
		path = filepath.Join("testdata", "tokenizer_golden.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cases []goldenCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		got := tok.encode(c.Text)
		if len(got) != len(c.IDs) {
			t.Errorf("%s: トークン数 %d, want %d", c.Name, len(got), len(c.IDs))
		}
		for i := range min(len(got), len(c.IDs)) {
			if got[i].ID != c.IDs[i] || got[i].Start != c.Offsets[i][0] || got[i].End != c.Offsets[i][1] {
				r := []rune(c.Text)
				t.Errorf("%s: token %d = {%d [%d,%d)}, want {%d [%d,%d)} 付近 %q", c.Name, i,
					got[i].ID, got[i].Start, got[i].End, c.IDs[i], c.Offsets[i][0], c.Offsets[i][1],
					string(r[max(0, c.Offsets[i][0]-5):min(len(r), c.Offsets[i][1]+5)]))
				break
			}
		}
	}
}
