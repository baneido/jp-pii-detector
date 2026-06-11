// Package eval はラベル付き評価データセットに対する検出精度
// （適合率・再現率・F1）を計測する。検出ルールごとの品質を
// 数値で表し、README のバッジと CI の回帰ガードの根拠にする。
package eval

import (
	"fmt"
	"sort"

	"github.com/baneido/jp-pii-detecter/internal/config"
	"github.com/baneido/jp-pii-detecter/internal/detect"
)

// Case は 1 行の評価ケース。Want は、その行で検出されるべき
// ルール ID の集合（空なら「何も検出されないべき」陰性ケース）。
type Case struct {
	Line string
	Want []string
}

// Result は 1 ルールの集計結果。
type Result struct {
	RuleID                string
	TP, FP, FN            int
	Precision, Recall, F1 float64
}

// Evaluate はデータセット全体を走査し、ルールごとの指標を返す。
// すべてのルールを評価対象にするため min_confidence=low で検出する。
func Evaluate() ([]Result, error) {
	cfg, err := config.Parse(`min_confidence = "low"`)
	if err != nil {
		return nil, err
	}
	d, err := detect.New(cfg)
	if err != nil {
		return nil, err
	}

	type counts struct{ tp, fp, fn int }
	stat := map[string]*counts{}
	at := func(id string) *counts {
		if stat[id] == nil {
			stat[id] = &counts{}
		}
		return stat[id]
	}

	for _, c := range Dataset {
		want := map[string]bool{}
		for _, id := range c.Want {
			want[id] = true
			at(id) // 母数 0 のルールも結果に出す
		}
		got := map[string]bool{}
		for _, f := range d.ScanLine("dataset", 1, c.Line) {
			got[f.RuleID] = true
		}
		// 期待・検出の和集合でルールごとに TP/FP/FN を加算する。
		for id := range want {
			if got[id] {
				at(id).tp++
			} else {
				at(id).fn++
			}
		}
		for id := range got {
			if !want[id] {
				at(id).fp++
			}
		}
	}

	results := make([]Result, 0, len(stat))
	for id, c := range stat {
		r := Result{RuleID: id, TP: c.tp, FP: c.fp, FN: c.fn}
		if c.tp+c.fp > 0 {
			r.Precision = float64(c.tp) / float64(c.tp+c.fp)
		}
		if c.tp+c.fn > 0 {
			r.Recall = float64(c.tp) / float64(c.tp+c.fn)
		}
		if r.Precision+r.Recall > 0 {
			r.F1 = 2 * r.Precision * r.Recall / (r.Precision + r.Recall)
		}
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].RuleID < results[j].RuleID })
	return results, nil
}

// Badge は F1 の表示文字列（小数 2 桁）と shields.io の色名を返す。
func Badge(f1 float64) (text, color string) {
	text = fmt.Sprintf("%.2f", f1)
	switch {
	case f1 >= 0.95:
		color = "brightgreen"
	case f1 >= 0.85:
		color = "green"
	case f1 >= 0.75:
		color = "yellowgreen"
	case f1 >= 0.65:
		color = "yellow"
	case f1 >= 0.5:
		color = "orange"
	default:
		color = "red"
	}
	return text, color
}

// BadgeMarkdown は README の表に埋め込む shields.io バッジの Markdown を返す。
func BadgeMarkdown(f1 float64) string {
	text, color := Badge(f1)
	return fmt.Sprintf("![F1 %s](https://img.shields.io/badge/F1-%s-%s)", text, text, color)
}
