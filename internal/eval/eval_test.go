package eval

import (
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "docs/accuracy.md を再生成する")

// wantF1 は各ルールの期待 F1（評価データセットに対する実測値）。
// README の検出精度バッジと一致させること（TestReadmeBadges が検証する）。
// ルールやデータセットを変更して値が動いたら、ここを更新したうえで
// `-update` で README のバッジと docs/accuracy.md を再生成する。
var wantF1 = map[string]float64{
	"jp-my-number":        1.00,
	"jp-phone-number":     1.00,
	"jp-postal-code":      1.00,
	"jp-address":          0.89,
	"email-address":       1.00,
	"credit-card":         1.00,
	"jp-drivers-license":  1.00,
	"jp-passport":         1.00,
	"jp-pension-number":   1.00,
	"jp-residence-card":   1.00,
	"jp-bank-account":     0.80,
	"jp-health-insurance": 1.00,
	"person-name":         0.75,
	"jp-birthdate":        1.00,
}

// TestAccuracy は実測 F1 が期待値と一致することを検証する（CI の回帰ガード）。
// バッジに掲げた精度をコードと評価データセットで裏付ける。
func TestAccuracy(t *testing.T) {
	results, err := Evaluate()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range results {
		seen[r.RuleID] = true
		want, ok := wantF1[r.RuleID]
		if !ok {
			t.Errorf("ルール %q の期待 F1 が未登録（wantF1 に追加してください）", r.RuleID)
			continue
		}
		if math.Abs(r.F1-want) > 0.005 {
			t.Errorf("%s: F1 = %.3f, want %.2f（README バッジ・wantF1・docs/accuracy.md を更新してください）",
				r.RuleID, r.F1, want)
		}
	}
	for id := range wantF1 {
		if !seen[id] {
			t.Errorf("ルール %q が評価結果に存在しない", id)
		}
	}
}

func TestEvaluateCasesKeepsRowMetricsForCasesWithoutSpans(t *testing.T) {
	results, err := EvaluateCases([]Case{
		{Line: "TEL: 090-1234-5678", Want: []string{"jp-phone-number"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := findResult(t, results, "jp-phone-number")
	if r.TP != 1 || r.FP != 0 || r.FN != 0 {
		t.Fatalf("row counts = TP:%d FP:%d FN:%d, want TP:1 FP:0 FN:0", r.TP, r.FP, r.FN)
	}
	if r.SpanExact.TP != 0 || r.SpanExact.FP != 0 || r.SpanExact.FN != 0 {
		t.Fatalf("span exact counts for row-only case = TP:%d FP:%d FN:%d, want all zero",
			r.SpanExact.TP, r.SpanExact.FP, r.SpanExact.FN)
	}
}

func TestEvaluateCasesCountsExactAndRelaxedSpans(t *testing.T) {
	results, err := EvaluateCases([]Case{
		{
			Line: "TEL: 090-1234-5678",
			Spans: []Span{{
				RuleID: "jp-phone-number",
				Start:  5,
				End:    18,
				Tags:   []string{"easy"},
			}},
		},
		{
			Line: "携帯 09012345678",
			Spans: []Span{{
				RuleID: "jp-phone-number",
				Start:  2, // intentionally includes the preceding space
				End:    14,
				Tags:   []string{"hard"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := findResult(t, results, "jp-phone-number")
	if r.TP != 2 || r.FP != 0 || r.FN != 0 {
		t.Fatalf("row counts = TP:%d FP:%d FN:%d, want TP:2 FP:0 FN:0", r.TP, r.FP, r.FN)
	}
	if r.SpanExact.TP != 1 || r.SpanExact.FP != 1 || r.SpanExact.FN != 1 {
		t.Fatalf("exact span counts = TP:%d FP:%d FN:%d, want TP:1 FP:1 FN:1",
			r.SpanExact.TP, r.SpanExact.FP, r.SpanExact.FN)
	}
	if r.SpanRelaxed.TP != 2 || r.SpanRelaxed.FP != 0 || r.SpanRelaxed.FN != 0 {
		t.Fatalf("relaxed span counts = TP:%d FP:%d FN:%d, want TP:2 FP:0 FN:0",
			r.SpanRelaxed.TP, r.SpanRelaxed.FP, r.SpanRelaxed.FN)
	}
}

func TestSpanMacroAveragesScoredRules(t *testing.T) {
	results, err := EvaluateCases([]Case{
		{
			Line: "TEL: 090-1234-5678",
			Spans: []Span{{
				RuleID: "jp-phone-number",
				Start:  5,
				End:    18,
			}},
		},
		{
			Line: "勤務地: 渋谷区道玄坂2-10-7",
			Spans: []Span{{
				RuleID: "jp-address",
				Start:  5,
				End:    17,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	exact := MacroSpanExact(results)
	if exact.Precision != 0.5 || exact.Recall != 0.5 || exact.F1 != 0.5 {
		t.Fatalf("exact macro = P:%.3f R:%.3f F1:%.3f, want all 0.500",
			exact.Precision, exact.Recall, exact.F1)
	}
	relaxed := MacroSpanRelaxed(results)
	if relaxed.Precision != 0.5 || relaxed.Recall != 0.5 || relaxed.F1 != 0.5 {
		t.Fatalf("relaxed macro = P:%.3f R:%.3f F1:%.3f, want all 0.500",
			relaxed.Precision, relaxed.Recall, relaxed.F1)
	}
}

func findResult(t *testing.T, results []Result, id string) Result {
	t.Helper()
	for _, r := range results {
		if r.RuleID == id {
			return r
		}
	}
	t.Fatalf("result %q not found", id)
	return Result{}
}

func TestReport(t *testing.T) {
	results, err := Evaluate()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%-22s %4s %4s %4s  %6s %6s %6s", "rule", "TP", "FP", "FN", "prec", "rec", "F1")
	for _, r := range results {
		t.Logf("%-22s %4d %4d %4d  %.3f  %.3f  %.3f",
			r.RuleID, r.TP, r.FP, r.FN, r.Precision, r.Recall, r.F1)
		if hasSpanScore(r) {
			t.Logf("%-22s exact    %4d %4d %4d  %.3f  %.3f  %.3f",
				r.RuleID, r.SpanExact.TP, r.SpanExact.FP, r.SpanExact.FN,
				r.SpanExact.Precision, r.SpanExact.Recall, r.SpanExact.F1)
			t.Logf("%-22s relaxed  %4d %4d %4d  %.3f  %.3f  %.3f",
				r.RuleID, r.SpanRelaxed.TP, r.SpanRelaxed.FP, r.SpanRelaxed.FN,
				r.SpanRelaxed.Precision, r.SpanRelaxed.Recall, r.SpanRelaxed.F1)
		}
	}
}

func hasSpanScore(r Result) bool {
	return r.SpanExact.TP+r.SpanExact.FP+r.SpanExact.FN+
		r.SpanRelaxed.TP+r.SpanRelaxed.FP+r.SpanRelaxed.FN > 0
}

// TestGenerateDoc は -update 指定時に docs/accuracy.md を再生成する。
//
//	go test ./internal/eval -run TestGenerateDoc -update
func TestGenerateDoc(t *testing.T) {
	if !*update {
		t.Skip("-update 指定時のみ docs/accuracy.md を再生成する")
	}
	results, err := Evaluate()
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].F1 == results[j].F1 {
			return results[i].RuleID < results[j].RuleID
		}
		return results[i].F1 > results[j].F1
	})

	var b strings.Builder
	b.WriteString("# 検出精度（評価データセットに対する実測値）\n\n")
	b.WriteString("`internal/eval` のラベル付き評価データセットに対して計測した、検出ルールごとの\n")
	b.WriteString("適合率（precision）・再現率（recall）・F1 スコアです。`go test ./internal/eval` で\n")
	b.WriteString("検証され（[eval_test.go](../internal/eval/eval_test.go)）、`-update` で本ファイルを再生成します。\n\n")
	b.WriteString("> この数値は同梱の評価データセット（陽性・陰性の代表例と、実運用での限界を表す難ケース）に\n")
	b.WriteString("> 対する値であり、あらゆる入力での精度を保証するものではありません。データセットは\n")
	b.WriteString("> [internal/eval/dataset.go](../internal/eval/dataset.go) にあります。\n\n")
	b.WriteString("| ルール ID | F1 | 適合率 | 再現率 | TP | FP | FN |\n")
	b.WriteString("|---|:--:|:--:|:--:|--:|--:|--:|\n")
	for _, r := range results {
		fmt.Fprintf(&b, "| `%s` | %.2f | %.2f | %.2f | %d | %d | %d |\n",
			r.RuleID, r.F1, r.Precision, r.Recall, r.TP, r.FP, r.FN)
	}
	m := Micro(results)
	fmt.Fprintf(&b, "| **全体（マイクロ平均）** | **%.2f** | **%.2f** | **%.2f** | %d | %d | %d |\n",
		m.F1, m.Precision, m.Recall, m.TP, m.FP, m.FN)

	var spanRows []Result
	for _, r := range results {
		if hasSpanScore(r) {
			spanRows = append(spanRows, r)
		}
	}
	if len(spanRows) > 0 {
		b.WriteString("\n## スパン評価\n\n")
		b.WriteString("期待スパンが設定されたケースのみを対象にした、ルーンオフセット範囲の評価です。")
		b.WriteString("exact はルール ID と範囲の完全一致、relaxed は同じルール ID で範囲が重なる場合を一致として数えます。\n\n")
		b.WriteString("| ルール ID | exact F1 | exact 適合率 | exact 再現率 | exact TP | exact FP | exact FN | relaxed F1 | relaxed 適合率 | relaxed 再現率 | relaxed TP | relaxed FP | relaxed FN |\n")
		b.WriteString("|---|:--:|:--:|:--:|--:|--:|--:|:--:|:--:|:--:|--:|--:|--:|\n")
		for _, r := range spanRows {
			fmt.Fprintf(&b, "| `%s` | %.2f | %.2f | %.2f | %d | %d | %d | %.2f | %.2f | %.2f | %d | %d | %d |\n",
				r.RuleID,
				r.SpanExact.F1, r.SpanExact.Precision, r.SpanExact.Recall,
				r.SpanExact.TP, r.SpanExact.FP, r.SpanExact.FN,
				r.SpanRelaxed.F1, r.SpanRelaxed.Precision, r.SpanRelaxed.Recall,
				r.SpanRelaxed.TP, r.SpanRelaxed.FP, r.SpanRelaxed.FN)
		}
		exact := MicroSpanExact(results)
		relaxed := MicroSpanRelaxed(results)
		fmt.Fprintf(&b, "| **全体（マイクロ平均）** | **%.2f** | **%.2f** | **%.2f** | %d | %d | %d | **%.2f** | **%.2f** | **%.2f** | %d | %d | %d |\n",
			exact.F1, exact.Precision, exact.Recall, exact.TP, exact.FP, exact.FN,
			relaxed.F1, relaxed.Precision, relaxed.Recall, relaxed.TP, relaxed.FP, relaxed.FN)

		exactMacro := MacroSpanExact(results)
		relaxedMacro := MacroSpanRelaxed(results)
		fmt.Fprintf(&b, "\nスパン評価のマクロ平均: exact F1 %.2f（適合率 %.2f / 再現率 %.2f）、relaxed F1 %.2f（適合率 %.2f / 再現率 %.2f）。\n",
			exactMacro.F1, exactMacro.Precision, exactMacro.Recall,
			relaxedMacro.F1, relaxedMacro.Precision, relaxedMacro.Recall)
	}

	if err := os.WriteFile("../../docs/accuracy.md", []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Log("docs/accuracy.md を再生成しました")
}
