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
	"jp-drivers-license":  0.80,
	"jp-passport":         1.00,
	"jp-pension-number":   0.80,
	"jp-residence-card":   1.00,
	"jp-bank-account":     0.67,
	"jp-health-insurance": 0.80,
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

func TestReport(t *testing.T) {
	results, err := Evaluate()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%-22s %4s %4s %4s  %6s %6s %6s", "rule", "TP", "FP", "FN", "prec", "rec", "F1")
	for _, r := range results {
		t.Logf("%-22s %4d %4d %4d  %.3f  %.3f  %.3f",
			r.RuleID, r.TP, r.FP, r.FN, r.Precision, r.Recall, r.F1)
	}
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
	sort.Slice(results, func(i, j int) bool { return results[i].F1 > results[j].F1 })

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

	if err := os.WriteFile("../../docs/accuracy.md", []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Log("docs/accuracy.md を再生成しました")
}
