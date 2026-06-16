// Package eval はラベル付き評価データセットに対する検出精度
// （適合率・再現率・F1）を計測する。検出ルールごとの品質を
// 数値で表し、README のバッジと CI の回帰ガードの根拠にする。
package eval

import (
	"fmt"
	"math"
	"sort"

	"github.com/baneido/jp-pii-detecter/internal/config"
	"github.com/baneido/jp-pii-detecter/internal/detect"
)

// Case は 1 行の評価ケース。Want は、その行で検出されるべき
// ルール ID の集合（空なら「何も検出されないべき」陰性ケース）。
type Case struct {
	Line  string
	Want  []string
	Spans []Span
}

// Span は 1 件の期待検出範囲。Start/End は 0 始まりのルーンオフセット
// （End は半開区間）。Tags は easy/hard などの層化用メタデータ。
type Span struct {
	RuleID     string
	Start, End int
	Tags       []string
}

// Score は TP/FP/FN と、それらから算出した指標。
type Score struct {
	TP, FP, FN            int
	Precision, Recall, F1 float64
}

// Result は 1 ルールの集計結果。
type Result struct {
	RuleID                string
	TP, FP, FN            int
	Precision, Recall, F1 float64
	SpanExact             Score
	SpanRelaxed           Score
}

// Evaluate はデータセット全体を走査し、ルールごとの指標を返す。
// すべてのルールを評価対象にするため min_confidence=low で検出する。
func Evaluate() ([]Result, error) {
	return EvaluateCases(Dataset)
}

// EvaluateCases は指定されたケース集合を評価する。テストや将来の外部データセット
// 取り込みではこちらを使い、Evaluate は同梱 Dataset を渡す薄いラッパーにする。
func EvaluateCases(cases []Case) ([]Result, error) {
	cfg, err := config.Parse(`min_confidence = "low"`)
	if err != nil {
		return nil, err
	}
	d, err := detect.New(cfg)
	if err != nil {
		return nil, err
	}

	type counts struct {
		row         Score
		spanExact   Score
		spanRelaxed Score
	}
	stat := map[string]*counts{}
	at := func(id string) *counts {
		if stat[id] == nil {
			stat[id] = &counts{}
		}
		return stat[id]
	}

	for _, c := range cases {
		want := map[string]bool{}
		for _, id := range c.Want {
			want[id] = true
			at(id) // 母数 0 のルールも結果に出す
		}
		for _, s := range c.Spans {
			if s.RuleID == "" {
				return nil, fmt.Errorf("span rule id is empty for line %q", c.Line)
			}
			if s.Start < 0 || s.End < s.Start {
				return nil, fmt.Errorf("invalid span for %s in line %q: [%d,%d)",
					s.RuleID, c.Line, s.Start, s.End)
			}
			want[s.RuleID] = true
			at(s.RuleID)
		}
		got := map[string]bool{}
		findings := d.ScanLine("dataset", 1, c.Line)
		for _, f := range findings {
			got[f.RuleID] = true
		}
		// 期待・検出の和集合でルールごとに TP/FP/FN を加算する。
		for id := range want {
			if got[id] {
				at(id).row.TP++
			} else {
				at(id).row.FN++
			}
		}
		for id := range got {
			if !want[id] {
				at(id).row.FP++
			}
		}

		if len(c.Spans) > 0 {
			wantSpans := map[string][]Span{}
			for _, s := range c.Spans {
				wantSpans[s.RuleID] = append(wantSpans[s.RuleID], s)
			}
			gotSpans := map[string][]Span{}
			for _, f := range findings {
				s := spanFromFinding(f)
				gotSpans[s.RuleID] = append(gotSpans[s.RuleID], s)
			}

			for id, spans := range wantSpans {
				gotForRule := gotSpans[id]
				exact := matchSpans(spans, gotForRule, spansEqual)
				relaxed := matchSpans(spans, gotForRule, spansOverlap)
				addScore(&at(id).spanExact, exact)
				addScore(&at(id).spanRelaxed, relaxed)
				delete(gotSpans, id)
			}
			for id, spans := range gotSpans {
				missed := Score{FP: len(spans)}
				addScore(&at(id).spanExact, missed)
				addScore(&at(id).spanRelaxed, missed)
			}
		}
	}

	results := make([]Result, 0, len(stat))
	for id, c := range stat {
		fillScore(&c.row)
		fillScore(&c.spanExact)
		fillScore(&c.spanRelaxed)
		r := Result{
			RuleID:      id,
			TP:          c.row.TP,
			FP:          c.row.FP,
			FN:          c.row.FN,
			Precision:   c.row.Precision,
			Recall:      c.row.Recall,
			F1:          c.row.F1,
			SpanExact:   c.spanExact,
			SpanRelaxed: c.spanRelaxed,
		}
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].RuleID < results[j].RuleID })
	return results, nil
}

func spanFromFinding(f detect.Finding) Span {
	start := f.Column - 1
	return Span{
		RuleID: f.RuleID,
		Start:  start,
		End:    start + len([]rune(f.Match)),
	}
}

func matchSpans(want, got []Span, match func(Span, Span) bool) Score {
	matchTo := make([]int, len(want))
	for i := range matchTo {
		matchTo[i] = -1
	}
	gotMatch := make([]int, len(got))
	for i := range gotMatch {
		gotMatch[i] = -1
	}

	var augment func(wi int, visited []bool) bool
	augment = func(wi int, visited []bool) bool {
		for gi, g := range got {
			if visited[gi] || !match(want[wi], g) {
				continue
			}
			visited[gi] = true
			if gotMatch[gi] == -1 || augment(gotMatch[gi], visited) {
				matchTo[wi] = gi
				gotMatch[gi] = wi
				return true
			}
		}
		return false
	}

	matched := 0
	for wi := range want {
		visited := make([]bool, len(got))
		if augment(wi, visited) {
			matched++
		}
	}

	return Score{
		TP: matched,
		FN: len(want) - matched,
		FP: len(got) - matched,
	}
}

func spansEqual(a, b Span) bool {
	return a.RuleID == b.RuleID && a.Start == b.Start && a.End == b.End
}

func spansOverlap(a, b Span) bool {
	return a.RuleID == b.RuleID && a.Start < b.End && b.Start < a.End
}

func addScore(dst *Score, src Score) {
	dst.TP += src.TP
	dst.FP += src.FP
	dst.FN += src.FN
}

func fillScore(s *Score) {
	if s.TP+s.FP > 0 {
		s.Precision = float64(s.TP) / float64(s.TP+s.FP)
	}
	if s.TP+s.FN > 0 {
		s.Recall = float64(s.TP) / float64(s.TP+s.FN)
	}
	if s.Precision+s.Recall > 0 {
		s.F1 = 2 * s.Precision * s.Recall / (s.Precision + s.Recall)
	}
}

// Micro は全ルール合算のマイクロ平均を返す。README 先頭の総合バッジと
// docs/accuracy.md の合計行に使う。
// 適合率・再現率・F1 の算出は fillScore に一元化する（式の二重実装を避ける）。
func Micro(results []Result) Result {
	var s Score
	for _, r := range results {
		s.TP += r.TP
		s.FP += r.FP
		s.FN += r.FN
	}
	fillScore(&s)
	return Result{
		RuleID:    "micro",
		TP:        s.TP,
		FP:        s.FP,
		FN:        s.FN,
		Precision: s.Precision,
		Recall:    s.Recall,
		F1:        s.F1,
	}
}

// MicroSpanExact は期待スパンが付いたケースだけを対象にした完全一致の
// マイクロ平均を返す。
func MicroSpanExact(results []Result) Score {
	var s Score
	for _, r := range results {
		addScore(&s, r.SpanExact)
	}
	fillScore(&s)
	return s
}

// MicroSpanRelaxed は期待スパンが付いたケースだけを対象にした重なり一致の
// マイクロ平均を返す。
func MicroSpanRelaxed(results []Result) Score {
	var s Score
	for _, r := range results {
		addScore(&s, r.SpanRelaxed)
	}
	fillScore(&s)
	return s
}

// MacroSpanExact は期待スパンが付いたルールごとの完全一致指標を平均する。
func MacroSpanExact(results []Result) Score {
	return macroSpan(results, func(r Result) Score { return r.SpanExact })
}

// MacroSpanRelaxed は期待スパンが付いたルールごとの重なり一致指標を平均する。
func MacroSpanRelaxed(results []Result) Score {
	return macroSpan(results, func(r Result) Score { return r.SpanRelaxed })
}

func macroSpan(results []Result, pick func(Result) Score) Score {
	var out Score
	var n int
	for _, r := range results {
		s := pick(r)
		if s.TP+s.FP+s.FN == 0 {
			continue
		}
		out.Precision += s.Precision
		out.Recall += s.Recall
		out.F1 += s.F1
		n++
	}
	if n > 0 {
		out.Precision /= float64(n)
		out.Recall /= float64(n)
		out.F1 /= float64(n)
	}
	return out
}

// Badge は F1 の表示文字列（小数 2 桁）と shields.io の色名を返す。
// 色は表示と同じ小数 2 桁に丸めた値で判定する（0.75 ちょうどの F1 が
// 浮動小数点誤差で 0.75 をわずかに下回り、表示 0.75 と色が食い違うのを防ぐ）。
func Badge(f1 float64) (text, color string) {
	text = fmt.Sprintf("%.2f", f1)
	f1 = math.Round(f1*100) / 100
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
