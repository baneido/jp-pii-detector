package eval

import (
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/piifixtures"
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
	"jp-bank-account":     0.86,
	"jp-health-insurance": 1.00,
	"person-name":         1.00,
	"jp-birthdate":        1.00,
}

// wantF1Medium は CLI 既定の min_confidence=medium での期待 F1（wantF1 と同じ
// 評価データセットに対する実測値）。低評価データセットに対する既定プロファイル
// （--high-recall 無効）の体感精度をバッジ計測と別に可視化するためのゴールデン値。
//
// person-name（internal/rule/builtin.go）は全パターンが Base: Low で、かつ
// ルールレベルの Context が未設定のため、internal/detect/detect.go の昇格処理
// （!p.RequireContext && conf < High の場合のみ Context 一致で High へ直接昇格。
// 中間の Medium 昇格経路は無い）が働かず、常に Low のまま min_confidence=medium
// のフィルタ（conf < d.minConf を除外）で全滅する。既定設定（cli の
// min_confidence=medium）では person-name が事実上 1 件も報告されないことを、
// このゴールデン値でそのまま可視化する。
//
// 他の 13 ルールは、低プロファイル（wantF1）で TP になっている検出のパターン
// Base がいずれも Medium 以上（RequireContext のパターンは昇格せず Base の
// まま、それ以外は Context 一致で High へ昇格）であるため、medium 閾値でも
// 除外されず low と同じ検出集合になる（wantF1 と同値）。
var wantF1Medium = map[string]float64{
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
	"jp-bank-account":     0.86,
	"jp-health-insurance": 1.00,
	"person-name":         0.00,
	"jp-birthdate":        1.00,
}

// TestAccuracy は実測 F1 が期待値と一致することを検証する（CI の回帰ガード）。
// バッジに掲げた精度をコードと評価データセットで裏付ける。プロファイル別
// （既定 CLI 相当の low バッジ用 / 既定 CLI の min_confidence=medium /
// --high-recall）に並行評価し、既定設定で沈黙する検出（person-name 等）を
// 公式数値として可視化する（issue #43）。
//
// low プロファイルは README バッジ・docs/accuracy.md の根拠でありゲート対象。
// medium プロファイルは wantF1Medium でゲートする。high-recall プロファイルは
// 対応する評価データセットのケース（jp-address-high-recall /
// person-name-high-recall / person-name-structured）がまだ無いため、当面は
// 計測・ログ出力のみでゲートしない（データセットにケースが揃ってから
// wantF1HighRecall を追加してゲート化する）。
func TestAccuracy(t *testing.T) {
	piifixtures.Require(t)

	profiles := []struct {
		name string
		opts Options
		want map[string]float64 // nil/空なら計測・ログのみ（ゲートしない）
	}{
		{name: "low", opts: Options{MinConfidence: "low"}, want: wantF1},
		{name: "medium", opts: Options{MinConfidence: "medium"}, want: wantF1Medium},
		{name: "high-recall", opts: Options{MinConfidence: "low", HighRecall: true}, want: nil},
	}

	for _, p := range profiles {
		t.Run(p.name, func(t *testing.T) {
			results, err := EvaluateWithOptions(p.opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(p.want) == 0 {
				for _, r := range results {
					t.Logf("%-24s F1=%.3f P=%.3f R=%.3f TP=%d FP=%d FN=%d",
						r.RuleID, r.F1, r.Precision, r.Recall, r.TP, r.FP, r.FN)
				}
				return
			}
			seen := map[string]bool{}
			for _, r := range results {
				seen[r.RuleID] = true
				want, ok := p.want[r.RuleID]
				if !ok {
					t.Errorf("ルール %q の期待 F1 が未登録（プロファイル %s の want map に追加してください）",
						r.RuleID, p.name)
					continue
				}
				if math.Abs(r.F1-want) > 0.005 {
					t.Errorf("%s [%s]: F1 = %.3f, want %.2f（README バッジ・wantF1・docs/accuracy.md を更新してください）",
						r.RuleID, p.name, r.F1, want)
				}
			}
			for id := range p.want {
				if !seen[id] {
					t.Errorf("ルール %q がプロファイル %s の評価結果に存在しない", id, p.name)
				}
			}
		})
	}
}

func TestEvaluateCasesKeepsRowMetricsForCasesWithoutSpans(t *testing.T) {
	piifixtures.Require(t)
	results, err := EvaluateCases([]Case{
		{Line: "TEL: " + piifixtures.MustGet(t, "phone.mobile"), Want: []string{"jp-phone-number"}},
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
	piifixtures.Require(t)
	results, err := EvaluateCases([]Case{
		{
			Line: "TEL: " + piifixtures.MustGet(t, "phone.mobile"),
			Spans: []Span{{
				RuleID: "jp-phone-number",
				Start:  5,
				End:    18,
				Tags:   []string{"easy"},
			}},
		},
		{
			Line: "携帯 " + piifixtures.MustGet(t, "phone.mobile_nosep"),
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

func TestEvaluateCasesScansContentWithLineAwareSpans(t *testing.T) {
	results, err := EvaluateCases([]Case{
		{
			Content: "memo\n連絡先: taro@gmail.com",
			Spans: []Span{{
				RuleID: "email-address",
				Line:   2,
				Start:  5,
				End:    19,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := findResult(t, results, "email-address")
	if r.TP != 1 || r.FP != 0 || r.FN != 0 {
		t.Fatalf("row counts = TP:%d FP:%d FN:%d, want TP:1 FP:0 FN:0", r.TP, r.FP, r.FN)
	}
	if r.SpanExact.TP != 1 || r.SpanExact.FP != 0 || r.SpanExact.FN != 0 {
		t.Fatalf("exact span counts = TP:%d FP:%d FN:%d, want TP:1 FP:0 FN:0",
			r.SpanExact.TP, r.SpanExact.FP, r.SpanExact.FN)
	}
}

func TestEvaluateCaseUsesFileOverride(t *testing.T) {
	results, err := EvaluateCases([]Case{
		{
			File:    "sample.ts",
			Content: "contact: taro@gmail.com",
			Want:    []string{"email-address"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := findResult(t, results, "email-address")
	if r.TP != 1 || r.FN != 0 {
		t.Fatalf("row counts = TP:%d FN:%d, want TP:1 FN:0", r.TP, r.FN)
	}
}

func TestEvaluateCaseFileOverrideEnablesSourceContext(t *testing.T) {
	results, err := EvaluateCases([]Case{
		{
			File:    "sample.ts",
			Content: "bankAccountNo:\n  \"1234567\"",
			Want:    []string{"jp-bank-account"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := findResult(t, results, "jp-bank-account")
	if r.TP != 1 || r.FN != 0 {
		t.Fatalf("row counts = TP:%d FN:%d, want TP:1 FN:0", r.TP, r.FN)
	}
}

func TestEvaluateCasesSpanLineMustMatch(t *testing.T) {
	results, err := EvaluateCases([]Case{
		{
			Content: "連絡先: taro@gmail.com\nmemo",
			Spans: []Span{{
				RuleID: "email-address",
				Line:   2,
				Start:  5,
				End:    19,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := findResult(t, results, "email-address")
	if r.TP != 1 || r.FP != 0 || r.FN != 0 {
		t.Fatalf("row counts = TP:%d FP:%d FN:%d, want TP:1 FP:0 FN:0", r.TP, r.FP, r.FN)
	}
	if r.SpanExact.TP != 0 || r.SpanExact.FP != 1 || r.SpanExact.FN != 1 {
		t.Fatalf("exact span counts = TP:%d FP:%d FN:%d, want TP:0 FP:1 FN:1",
			r.SpanExact.TP, r.SpanExact.FP, r.SpanExact.FN)
	}
}

func TestEvaluateCasesScansDiffAddedLines(t *testing.T) {
	results, err := EvaluateCases([]Case{
		{
			Diff: []DiffLine{
				{Text: "連絡先: old@gmail.com", Added: false},
				{Text: "連絡先: taro@gmail.com", Added: true},
			},
			Spans: []Span{{
				RuleID: "email-address",
				Line:   2,
				Start:  5,
				End:    19,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := findResult(t, results, "email-address")
	if r.TP != 1 || r.FP != 0 || r.FN != 0 {
		t.Fatalf("row counts = TP:%d FP:%d FN:%d, want only the added-line email as TP",
			r.TP, r.FP, r.FN)
	}
	if r.SpanExact.TP != 1 || r.SpanExact.FP != 0 || r.SpanExact.FN != 0 {
		t.Fatalf("exact span counts = TP:%d FP:%d FN:%d, want TP:1 FP:0 FN:0",
			r.SpanExact.TP, r.SpanExact.FP, r.SpanExact.FN)
	}
}

func TestEvaluateCasesRejectsAmbiguousInputs(t *testing.T) {
	_, err := EvaluateCases([]Case{{
		Line:    "memo",
		Content: "memo",
	}})
	if err == nil {
		t.Fatal("EvaluateCases accepted a case with both line and content set")
	}
}

func TestEvaluateCasesRejectsExpectedCaseWithoutInput(t *testing.T) {
	tests := []struct {
		name string
		c    Case
	}{
		{
			name: "want",
			c:    Case{Want: []string{"email-address"}},
		},
		{
			name: "span",
			c: Case{Spans: []Span{{
				RuleID: "email-address",
				Start:  0,
				End:    14,
			}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EvaluateCases([]Case{tt.c})
			if err == nil {
				t.Fatal("EvaluateCases accepted a case with expectations but no input")
			}
			if !strings.Contains(err.Error(), "missing eval case input") {
				t.Fatalf("error = %v, want missing input error", err)
			}
		})
	}
}

func TestEvaluateCasesErrorsDoNotEchoInput(t *testing.T) {
	_, err := EvaluateCases([]Case{{
		Line:    "連絡先: taro@gmail.com",
		Content: "memo",
	}})
	if err == nil {
		t.Fatal("EvaluateCases accepted an ambiguous case")
	}
	if strings.Contains(err.Error(), "taro@gmail.com") {
		t.Fatalf("error echoed input containing PII-like data: %v", err)
	}
}

func TestEvaluateCasesWithOptionsUsesMinConfidence(t *testing.T) {
	// 「氏名: 山田太郎」は姓名辞書に一致する（山田=姓/太郎=名）ため、強いラベル
	// パターンの Medium twin（personNameStrongLabelRe + dict.IsPersonName）が
	// 発火し、既定 min_confidence=medium で報告される（issue #44）。
	results, err := EvaluateCasesWithOptions([]Case{
		{Line: "氏名: 山田太郎", Want: []string{"person-name"}},
	}, Options{MinConfidence: "medium"})
	if err != nil {
		t.Fatal(err)
	}

	r := findResult(t, results, "person-name")
	if r.TP != 1 || r.FP != 0 || r.FN != 0 {
		t.Fatalf("row counts = TP:%d FP:%d FN:%d, want dictionary-validated name to meet medium threshold",
			r.TP, r.FP, r.FN)
	}
}

func TestEvaluateCasesWithOptionsEnablesHighRecallRules(t *testing.T) {
	results, err := EvaluateCasesWithOptions([]Case{
		{
			Content: "氏名:\n山田太郎",
			Want:    []string{"person-name-structured"},
		},
	}, Options{MinConfidence: "medium", HighRecall: true})
	if err != nil {
		t.Fatal(err)
	}

	r := findResult(t, results, "person-name-structured")
	if r.TP != 1 || r.FP != 0 || r.FN != 0 {
		t.Fatalf("row counts = TP:%d FP:%d FN:%d, want high-recall structured name to be evaluated",
			r.TP, r.FP, r.FN)
	}
}

func TestEvaluateCasesCountsNegativeCases(t *testing.T) {
	results, err := EvaluateCases([]Case{
		{Content: "memo: nothing sensitive on this line"},              // 陰性ケース（Want/Spans なし）
		{Content: "another clean memo", File: "clean.txt"},             // 陰性ケース
		{Line: "連絡先: taro@gmail.com", Want: []string{"email-address"}}, // 陽性ケース
	})
	if err != nil {
		t.Fatal(err)
	}

	r := findResult(t, results, "email-address")
	if r.Negatives != 2 {
		t.Fatalf("Negatives = %d, want 2（Want/Spans が両方とも空のケース数）", r.Negatives)
	}

	// Negatives は全ルール共通の母数のため、Micro でも同じ値になる
	// （ルール数倍に合算されないことを確認する）。
	if m := Micro(results); m.Negatives != 2 {
		t.Fatalf("Micro().Negatives = %d, want 2", m.Negatives)
	}
}

func TestEvaluateCasesCountsFindingLevelFalsePositives(t *testing.T) {
	results, err := EvaluateCases([]Case{
		{
			// 陰性ケース（Want なし）だが、email-address が 2 件誤検出される。
			Content: "memo: taro@gmail.com and hanako@gmail.com are both examples",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := findResult(t, results, "email-address")
	if r.FP != 1 {
		t.Fatalf("row FP = %d, want 1（行レベルはケースにつき最大 1 件のまま）", r.FP)
	}
	if r.FindingFP != 2 {
		t.Fatalf("FindingFP = %d, want 2（検出単位では同一ケース内の 2 件を反映する）", r.FindingFP)
	}
}

func TestEvaluateCasesFindingLevelFalsePositivesExcludeWantedRules(t *testing.T) {
	results, err := EvaluateCases([]Case{
		{
			Line: "連絡先: taro@gmail.com",
			Want: []string{"email-address"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := findResult(t, results, "email-address")
	if r.TP != 1 || r.FP != 0 {
		t.Fatalf("row counts = TP:%d FP:%d, want TP:1 FP:0", r.TP, r.FP)
	}
	if r.FindingFP != 0 {
		t.Fatalf("FindingFP = %d, want 0（期待どおりの検出は FindingFP に数えない）", r.FindingFP)
	}
}

func TestEvaluateCasesFlagsConfidenceMissAgainstWantSpan(t *testing.T) {
	// person-name は Base:Low のみで構成され、ルールレベルの Context も無いため
	// Low から昇格できない（internal/rule/builtin.go）。WantConfidence: "high" を
	// 満たさないことを ConfidenceMiss で検出できることを確認する。
	results, err := EvaluateCases([]Case{
		{
			Line: "氏名: 山田太郎",
			Spans: []Span{{
				RuleID:         "person-name",
				Start:          4,
				End:            8,
				WantConfidence: "high",
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := findResult(t, results, "person-name")
	if r.TP != 1 {
		t.Fatalf("row TP = %d, want 1（person-name は既定の min_confidence=low で検出される）", r.TP)
	}
	if r.SpanExact.TP != 1 {
		t.Fatalf("SpanExact.TP = %d, want 1", r.SpanExact.TP)
	}
	if r.ConfidenceMiss != 1 {
		t.Fatalf("ConfidenceMiss = %d, want 1（Base:Low のまま high へは昇格しない）", r.ConfidenceMiss)
	}
}

func TestEvaluateCasesWantConfidenceSatisfiedDoesNotCountAsMiss(t *testing.T) {
	results, err := EvaluateCases([]Case{
		{
			Line: "連絡先: taro@gmail.com",
			Spans: []Span{{
				RuleID:         "email-address",
				Start:          5,
				End:            19,
				WantConfidence: "high",
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := findResult(t, results, "email-address")
	if r.ConfidenceMiss != 0 {
		t.Fatalf("ConfidenceMiss = %d, want 0（email-address は常に Base:High で検出される）", r.ConfidenceMiss)
	}
}

func TestEvaluateCasesWantConfidenceOptionalWhenUnset(t *testing.T) {
	// WantConfidence を指定しないスパン（既存データセット JSON との後方互換）は
	// 信頼度チェックの対象外になる。
	results, err := EvaluateCases([]Case{
		{
			Line: "氏名: 山田太郎",
			Spans: []Span{{
				RuleID: "person-name",
				Start:  4,
				End:    8,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := findResult(t, results, "person-name")
	if r.ConfidenceMiss != 0 {
		t.Fatalf("ConfidenceMiss = %d, want 0（WantConfidence 未設定はチェック対象外）", r.ConfidenceMiss)
	}
}

func TestEvaluateCasesRejectsUnknownWantConfidence(t *testing.T) {
	_, err := EvaluateCases([]Case{
		{
			Line: "連絡先: taro@gmail.com",
			Spans: []Span{{
				RuleID:         "email-address",
				Start:          5,
				End:            19,
				WantConfidence: "hgh",
			}},
		},
	})
	if err == nil {
		t.Fatal("EvaluateCases accepted unknown want_confidence")
	}
	if !strings.Contains(err.Error(), "want_confidence") || !strings.Contains(err.Error(), "hgh") {
		t.Fatalf("error = %q, want it to mention want_confidence and the invalid value", err)
	}
}

func TestSpanMacroAveragesScoredRules(t *testing.T) {
	piifixtures.Require(t)
	results, err := EvaluateCases([]Case{
		{
			Line: "TEL: " + piifixtures.MustGet(t, "phone.mobile"),
			Spans: []Span{{
				RuleID: "jp-phone-number",
				Start:  5,
				End:    18,
			}},
		},
		{
			Line: "勤務地: " + piifixtures.MustGet(t, "address.shibuya_ward"),
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
	piifixtures.Require(t)
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
	piifixtures.Require(t)
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
	b.WriteString("適合率（precision）、再現率（recall）、F1 スコアです。`JP_PII_FIXTURES` を設定して\n")
	b.WriteString("`go test ./internal/eval` で検証され（[eval_test.go](../internal/eval/eval_test.go)）、\n")
	b.WriteString("`-update` で本ファイルを再生成します。\n\n")
	b.WriteString("README バッジと下表の主指標は、ルール自体の検出能力を見るため `min_confidence=low`、\n")
	b.WriteString("高再現率ルール無効の既存プロファイルで計測しています。評価ケースは単一行（`line`）に加え、\n")
	b.WriteString("複数行入力（`content`）と diff hunk（`diff`: 追加行のみを報告）も表現できます。\n\n")
	b.WriteString("> この数値は、実在しうる PII を含むためリポジトリ外で管理する評価データセット\n")
	b.WriteString("> （陽性と陰性の代表例と、実運用での限界を表す難ケース）に対する値であり、あらゆる\n")
	b.WriteString("> 入力での精度を保証するものではありません。データセットの取得方法は\n")
	b.WriteString("> [docs/development.md](../docs/development.md) を参照してください。\n\n")
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
		b.WriteString("期待スパンが設定されたケースのみを対象にした、行番号とルーンオフセット範囲の評価です。")
		b.WriteString("exact はルール ID・行番号・範囲の完全一致、relaxed は同じルール ID・同じ行で範囲が重なる場合を一致として数えます。\n\n")
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
