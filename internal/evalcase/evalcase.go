// Package evalcase は、評価ケースのデータモデルとスキーマ検証を提供する。
// データの生成元（公開合成値 / 非公開コーパス）や取得方法には依存しない。
package evalcase

import (
	"fmt"
	"strings"
)

// Span は 1 件の期待検出範囲。Line は 1 始まり、Start/End は行内の
// 0 始まりルーンオフセット（End は半開区間）。
type Span struct {
	RuleID         string   `json:"rule_id"`
	Line           int      `json:"line,omitempty"`
	Start          int      `json:"start"`
	End            int      `json:"end"`
	Tags           []string `json:"tags,omitempty"`
	WantConfidence string   `json:"want_confidence,omitempty"`
}

// DiffLine は diff hunk 内の 1 行。
type DiffLine struct {
	Text  string `json:"text"`
	Added bool   `json:"added"`
}

// Case は 1 つの評価ケース。ID は失敗時に生データを表示せず対象を特定する
// 安定識別子。Line / Content / Diff のいずれか 1 つで入力を表す。
type Case struct {
	ID          string     `json:"id,omitempty"`
	SourceClass string     `json:"source_class,omitempty"`
	File        string     `json:"file,omitempty"`
	Line        string     `json:"line,omitempty"`
	Content     string     `json:"content,omitempty"`
	Diff        []DiffLine `json:"diff,omitempty"`
	Want        []string   `json:"want,omitempty"`
	Spans       []Span     `json:"spans,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
}

// Validate は構造上の誤りを、生値をエラーメッセージへ含めずに検出する。
func Validate(cases []Case) error {
	if len(cases) == 0 {
		return fmt.Errorf("評価データセットが空です")
	}
	seen := map[string]int{}
	for i, c := range cases {
		inputs := 0
		if c.Line != "" {
			inputs++
		}
		if c.Content != "" {
			inputs++
		}
		if len(c.Diff) > 0 {
			inputs++
		}
		if inputs > 1 || (inputs == 0 && (len(c.Want) > 0 || len(c.Spans) > 0)) {
			return fmt.Errorf("dataset[%d] (%s) の入力指定が不正です", i, safeID(c.ID))
		}
		if c.ID != "" {
			if first, ok := seen[c.ID]; ok {
				return fmt.Errorf("dataset[%d] の id %q は dataset[%d] と重複しています", i, c.ID, first)
			}
			seen[c.ID] = i
		}
		for si, s := range c.Spans {
			if strings.TrimSpace(s.RuleID) == "" || s.Start < 0 || s.End < s.Start || s.Line < 0 {
				return fmt.Errorf("dataset[%d] (%s) の spans[%d] が不正です", i, safeID(c.ID), si)
			}
			switch s.WantConfidence {
			case "", "low", "medium", "high":
			default:
				return fmt.Errorf("dataset[%d] (%s) の spans[%d].want_confidence が不正です", i, safeID(c.ID), si)
			}
		}
	}
	return nil
}

func safeID(id string) string {
	if id == "" {
		return "idなし"
	}
	return id
}
