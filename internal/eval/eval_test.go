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

var update = flag.Bool("update", false, "docs/accuracy.md・docs/accuracy.json・README.md のバッジを再生成する")

// accuracyMDPath / accuracyJSONPath は、検出精度のゴールデンファイル
// （docs/accuracy.md・docs/accuracy.json）へのパス。README のバッジ・
// docs/accuracy.md・TestAccuracy の回帰ガードは、すべて同じ評価結果から
// 生成されるこの2ファイルを単一の情報源にする。
const (
	accuracyMDPath   = "../../docs/accuracy.md"
	accuracyJSONPath = "../../docs/accuracy.json"
)

// wantF1Medium は CLI 既定の min_confidence=medium での期待 F1（low プロファイル
// と同じ評価データセットに対する実測値）。低プロファイル（README バッジ・
// docs/accuracy.json のゴールデン値）に対する既定プロファイル（--high-recall
// 無効）の体感精度を、バッジ計測と別に可視化するためのゴールデン値。
//
// person-name（internal/rule/builtin.go）は、辞書検証済みマッチ（強ラベル+
// 姓名辞書一致等の twin パターン）が Base: Medium で報告されるため、既定設定
// （cli の min_confidence=medium）でも辞書検証済みの検出は残る（issue #44）。
// 辞書検証を伴わないフォールバックパターンは Base: Low のままフィルタで
// 除外されるため、low プロファイル（1.00）より F1 が下がる。この差分を
// ゴールデン値でそのまま可視化する。
//
// 他の 13 ルールは、低プロファイルで TP になっている検出のパターン Base が
// いずれも Medium 以上（RequireContext のパターンは昇格せず Base のまま、
// それ以外は Context 一致で High へ昇格）であるため、medium 閾値でも除外され
// ず low と同じ検出集合になる（docs/accuracy.json の low 値と同値）。
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
	"person-name":         0.92,
	"jp-birthdate":        1.00,
}

// TestAccuracy は CI の回帰ガード。low プロファイル（README バッジ・
// docs/accuracy.md の根拠）は、実測結果がコミット済みの docs/accuracy.json
// （ゴールデンファイル）と完全一致することを検証する。ルールやデータセットを
// 変更して数値が動いたら、
// `go test ./internal/eval -run 'TestGenerateDoc|TestReadmeBadges' -update`
// で docs/accuracy.md・docs/accuracy.json・README.md をまとめて再生成して
// コミットする。
//
// あわせて medium / high-recall プロファイルを並行評価し、既定設定で沈黙する
// 検出（person-name 等）を公式数値として可視化する（issue #43）。medium
// プロファイルは wantF1Medium で許容誤差付きにゲートする。high-recall
// プロファイルは対応する評価データセットのケース（jp-address-high-recall /
// person-name-high-recall / person-name-structured）がまだ無いため、当面は
// 計測・ログ出力のみでゲートしない（データセットにケースが揃ってから
// wantF1HighRecall を追加してゲート化する）。
func TestAccuracy(t *testing.T) {
	piifixtures.Require(t)
	results, err := Evaluate()
	if err != nil {
		t.Fatal(err)
	}
	cases, ok := piifixtures.Dataset()
	if !ok {
		t.Fatal("評価データセットを取得できません")
	}
	got := BuildGolden(results, SpanlessPositiveCount(cases))

	want, err := LoadGolden(accuracyJSONPath)
	if err != nil {
		t.Fatalf("docs/accuracy.json を読み込めません: %v"+
			"（`go test ./internal/eval -run 'TestGenerateDoc|TestReadmeBadges' -update` で生成してください）", err)
	}

	for _, msg := range DiffGolden(got, want) {
		t.Error(msg)
	}

	profiles := []struct {
		name string
		opts Options
		want map[string]float64 // nil/空なら計測・ログのみ（ゲートしない）
	}{
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
					t.Errorf("%s [%s]: F1 = %.3f, want %.2f（wantF1Medium・docs/accuracy.md を更新してください）",
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

// TestEvaluateCasesStratifiedByTag は Case.Tags 単位の層別集計（Stratified.Tags）が
// 複数ケース・複数タグにまたがって正しく合算されることを検証する。JP_PII_FIXTURES
// 不要の合成データのみを使う（P27: タグ層化評価の基盤）。
func TestEvaluateCasesStratifiedByTag(t *testing.T) {
	s, err := EvaluateCasesStratifiedWithOptions([]Case{
		{
			Line: "連絡先: taro@gmail.com",
			Want: []string{"email-address"},
			Tags: []string{"source:synthetic", "notation:halfwidth"},
		},
		{
			Content: "memo\n連絡先: hanako@gmail.com",
			Want:    []string{"email-address"},
			Tags:    []string{"source:synthetic", "layout:cross-line"},
		},
		{Line: "メモだけの行"}, // 期待も検出もない陰性ケース（タグなし）
	}, Options{MinConfidence: "low"})
	if err != nil {
		t.Fatal(err)
	}

	if got := s.Tags["source:synthetic"]; got.TP != 2 || got.FP != 0 || got.FN != 0 {
		t.Fatalf("Tags[source:synthetic] = %+v, want TP:2 FP:0 FN:0", got)
	}
	if got := s.Tags["notation:halfwidth"]; got.TP != 1 || got.FP != 0 || got.FN != 0 {
		t.Fatalf("Tags[notation:halfwidth] = %+v, want TP:1 FP:0 FN:0", got)
	}
	if got := s.Tags["layout:cross-line"]; got.TP != 1 || got.FP != 0 || got.FN != 0 {
		t.Fatalf("Tags[layout:cross-line] = %+v, want TP:1 FP:0 FN:0", got)
	}
	if _, ok := s.Tags[""]; ok {
		t.Fatal("タグなしの陰性ケースが空文字列タグのバケツを作ってはいけない")
	}
	if len(s.Tags) != 3 {
		t.Fatalf("len(s.Tags) = %d, want 3 (got %v)", len(s.Tags), s.Tags)
	}
}

// TestEvaluateCasesStratifiedByKind は line/content/diff のケース種別ごとの
// 層別集計（Stratified.Kinds）を検証する。
func TestEvaluateCasesStratifiedByKind(t *testing.T) {
	s, err := EvaluateCasesStratifiedWithOptions([]Case{
		{Line: "連絡先: taro@gmail.com", Want: []string{"email-address"}},
		{Content: "memo\n連絡先: hanako@gmail.com", Want: []string{"email-address"}},
		{
			Diff: []DiffLine{
				{Text: "連絡先: old@gmail.com", Added: false},
				{Text: "連絡先: jiro@gmail.com", Added: true},
			},
			Want: []string{"email-address"},
		},
		{Line: "メモだけの行"}, // line 種別の陰性ケース
	}, Options{MinConfidence: "low"})
	if err != nil {
		t.Fatal(err)
	}

	if got := s.Kinds["line"]; got.TP != 1 || got.FP != 0 || got.FN != 0 {
		t.Fatalf("Kinds[line] = %+v, want TP:1 FP:0 FN:0", got)
	}
	if got := s.Kinds["content"]; got.TP != 1 || got.FP != 0 || got.FN != 0 {
		t.Fatalf("Kinds[content] = %+v, want TP:1 FP:0 FN:0", got)
	}
	if got := s.Kinds["diff"]; got.TP != 1 || got.FP != 0 || got.FN != 0 {
		t.Fatalf("Kinds[diff] = %+v, want TP:1 FP:0 FN:0", got)
	}
	if len(s.Kinds) != 3 {
		t.Fatalf("len(s.Kinds) = %d, want 3 (got %v)", len(s.Kinds), s.Kinds)
	}
}

// TestEvaluateCasesWithOptionsMatchesStratifiedResults は、Stratified 集計を
// 追加してもルール別 Result（EvaluateCasesWithOptions の戻り値）が従来と
// 完全に一致することを検証する（後方互換の回帰ガード）。
func TestEvaluateCasesWithOptionsMatchesStratifiedResults(t *testing.T) {
	cases := []Case{
		{Line: "連絡先: taro@gmail.com", Want: []string{"email-address"}, Tags: []string{"source:synthetic"}},
	}
	results, err := EvaluateCasesWithOptions(cases, Options{MinConfidence: "low"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := EvaluateCasesStratifiedWithOptions(cases, Options{MinConfidence: "low"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(s.Results) {
		t.Fatalf("len(results) = %d, len(s.Results) = %d, want equal", len(results), len(s.Results))
	}
	for i := range results {
		if results[i] != s.Results[i] {
			t.Fatalf("EvaluateCasesWithOptions[%d] = %+v, EvaluateCasesStratifiedWithOptions.Results[%d] = %+v, want equal",
				i, results[i], i, s.Results[i])
		}
	}
}

// knownCaseTagPrefixes は Case.Tags の既知の語彙プレフィックス
// （docs/development.md にドキュメント化）。
var knownCaseTagPrefixes = []string{
	"notation:", "sep:", "format:", "label:", "layout:", "source:", "polarity:", "rule:",
}

// knownCaseTag は tag が既知のケースタグ語彙に従っているかを返す。
// easy/hard は Span.Tags と表記を揃えた慣用タグとして許容する。
func knownCaseTag(tag string) bool {
	if tag == "easy" || tag == "hard" {
		return true
	}
	for _, p := range knownCaseTagPrefixes {
		if strings.HasPrefix(tag, p) {
			return true
		}
	}
	return false
}

// TestCaseTagsAreKnown は評価データセットの Case.Tags が既知の語彙に従っているかを
// 緩く検査する。フェーズ1では CI を落とさない非致命的な警告（t.Logf）に留め、
// typo によるタグの分裂に早期に気づけるようにする。
func TestCaseTagsAreKnown(t *testing.T) {
	piifixtures.Require(t)
	cases, ok := piifixtures.Dataset()
	if !ok {
		t.Skip("データセットを取得できません")
	}
	unknown := map[string]int{}
	for _, c := range cases {
		for _, tag := range c.Tags {
			if !knownCaseTag(tag) {
				unknown[tag]++
			}
		}
	}
	for tag, n := range unknown {
		t.Logf("未知のケースタグ %q が %d 件（typo の可能性。既知の語彙は docs/development.md を参照）", tag, n)
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

// TestGenerateDoc は -update 指定時に docs/accuracy.md と docs/accuracy.json
// （ゴールデンファイル。TestAccuracy・TestDatasetQuality・README バッジの
// 単一の情報源）を再生成する。
//
//	go test ./internal/eval -run 'TestGenerateDoc|TestReadmeBadges' -update
func TestGenerateDoc(t *testing.T) {
	if !*update {
		t.Skip("-update 指定時のみ docs/accuracy.md・docs/accuracy.json を再生成する")
	}
	piifixtures.Require(t)
	strat, err := EvaluateStratified()
	if err != nil {
		t.Fatal(err)
	}
	results := strat.Results
	cases, ok := piifixtures.Dataset()
	if !ok {
		t.Fatal("評価データセットを取得できません")
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

	stats := ComputeDatasetStats(cases)
	b.WriteString("\n## データセットの統計（匿名）\n\n")
	b.WriteString("評価データセットはリポジトリ外（GCS）で管理され、レビュー時に中身が見えないため、\n")
	b.WriteString("PII やケース本文を含まない件数だけの統計をここに記録します。\n\n")
	fmt.Fprintf(&b, "- 総ケース数: %d\n", stats.TotalCases)
	fmt.Fprintf(&b, "- 陽性ケース数: %d（うちスパン付与 %d 件、付与率 %s）\n",
		stats.PositiveCases, stats.SpanAnnotatedCases, spanCoverageText(stats))
	fmt.Fprintf(&b, "- 陰性ケース数: %d\n\n", stats.NegativeCases)
	b.WriteString("| ルール ID | 陽性ケース数 |\n|---|--:|\n")
	for _, rc := range stats.PerRule {
		fmt.Fprintf(&b, "| `%s` | %d |\n", rc.RuleID, rc.Cases)
	}

	writeStratifiedTable(&b, "ケース種別別", "ケース種別",
		"評価ケースの入力形式（line/content/diff）別の内訳です。行レベル（Result.TP 等と同じ定義）の"+
			"TP/FP/FN で、1 ケースに複数ルールの期待・検出があれば同じ種別へ合算します。",
		strat.Kinds, kindOrder(strat.Kinds))

	if len(strat.Tags) > 0 {
		tags := make([]string, 0, len(strat.Tags))
		for tag := range strat.Tags {
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		writeStratifiedTable(&b, "タグ別（表記ゆれ等）", "タグ",
			"評価ケースの `Case.Tags`（表記ゆれ・ラベル語彙・合成データ由来などのメタデータ。"+
				"語彙は [docs/development.md](../docs/development.md) を参照）別の内訳です。"+
				"タグ未設定のケースは含まれません。",
			strat.Tags, tags)
	}

	if err := os.WriteFile(accuracyMDPath, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	golden := BuildGolden(results, SpanlessPositiveCount(cases))
	if err := SaveGolden(accuracyJSONPath, golden); err != nil {
		t.Fatal(err)
	}
	t.Log("docs/accuracy.md と docs/accuracy.json を再生成しました")
}

// spanCoverageText は陽性ケースのうちスパンが付与された割合を百分率表記で返す。
// 陽性ケースが 0 件のときはゼロ除算を避けて "-" を返す。
func spanCoverageText(stats DatasetStats) string {
	if stats.PositiveCases == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", float64(stats.SpanAnnotatedCases)/float64(stats.PositiveCases)*100)
}

// kindOrder は Stratified.Kinds の表示順（line → content → diff → その他は
// 名前順）を返す。
func kindOrder(kinds map[string]Score) []string {
	preferred := []string{"line", "content", "diff"}
	seen := map[string]bool{}
	order := make([]string, 0, len(kinds))
	for _, k := range preferred {
		if _, ok := kinds[k]; ok {
			order = append(order, k)
			seen[k] = true
		}
	}
	var rest []string
	for k := range kinds {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(order, rest...)
}

// writeStratifiedTable は Stratified.Kinds / Stratified.Tags のような
// 層別集計を Markdown 表として書き出す（キー列見出し・説明文だけ差し替え可能な
// 共通ヘルパー）。
func writeStratifiedTable(b *strings.Builder, heading, keyLabel, desc string, scores map[string]Score, keys []string) {
	if len(keys) == 0 {
		return
	}
	fmt.Fprintf(b, "\n## %s\n\n", heading)
	b.WriteString(desc + "\n\n")
	fmt.Fprintf(b, "| %s | F1 | 適合率 | 再現率 | TP | FP | FN |\n", keyLabel)
	b.WriteString("|---|:--:|:--:|:--:|--:|--:|--:|\n")
	var total Score
	for _, k := range keys {
		s := scores[k]
		fmt.Fprintf(b, "| `%s` | %.2f | %.2f | %.2f | %d | %d | %d |\n",
			k, s.F1, s.Precision, s.Recall, s.TP, s.FP, s.FN)
		addScore(&total, s)
	}
	fillScore(&total)
	fmt.Fprintf(b, "| **全体（マイクロ平均）** | **%.2f** | **%.2f** | **%.2f** | %d | %d | %d |\n",
		total.F1, total.Precision, total.Recall, total.TP, total.FP, total.FN)
}
