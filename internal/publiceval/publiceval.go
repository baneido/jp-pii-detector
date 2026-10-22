// Package publiceval は、PR 時に実行する公開合成コーパスでの精度ゲートを提供する。
//
// 非公開コーパスを使う private-eval（.github/workflows/ci.yml）は平文を PR の
// コードへ渡さないため main への push 時にしか走らず、#166 のように「ルールを
// 分割・改名したのに評価ラベルが追従していない」回帰がマージ後まで見えなかった。
// このパッケージは、ソースに PII を一切持たない決定的な合成器
// （internal/fixturegen と internal/corpusv2.PublicSynthetic）だけでコーパスを作り、
// ルール × プロファイルごとの行レベル指標をコミット済みゴールデン
// （testdata/golden.json。件数と指標だけで本文は含まない）と比較する。
package publiceval

import (
	"fmt"
	"sort"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/corpusv2"
	"github.com/baneido/jp-pii-detector/internal/eval"
	"github.com/baneido/jp-pii-detector/internal/evalcase"
	"github.com/baneido/jp-pii-detector/internal/fixturegen"
)

// DatasetID はゴールデンに記録する公開合成コーパスの識別子。生成器の構成を
// 変えたら上げる。
const DatasetID = "public-synthetic-v1"

// MinPositivesPerRule は全ルールに要求する合成陽性ケース数の下限。
const MinPositivesPerRule = corpusv2.MinPositiveCasesPerRule

// GateProfiles は公表3プロファイルに、opt-in ルール（高再現率・名簿ファイル判定）
// を全て有効にした「all-opt-in」を加えたもの。all-opt-in があることで、公表
// プロファイルでは評価されない名簿ファイル判定ルールも PR 時に検査できる。
var GateProfiles = append(append([]eval.ProfileSpec(nil), eval.PublishedProfiles...), eval.ProfileSpec{
	ID:          "all-opt-in",
	Description: "PR ゲート専用（min_confidence=low、高再現率・名簿ファイル判定を有効）",
	Options:     eval.Options{MinConfidence: "low", HighRecall: true, NameRoster: true},
})

// Cases は公開合成コーパスを返す。同じコードからは常に同じケース列になる。
func Cases() []evalcase.Case {
	cases := fixturegen.Generate()
	cases = append(cases, corpusv2.PublicSynthetic(corpusv2.PublicSyntheticSeed)...)
	return cases
}

// Evaluate は cases を GateProfiles で評価し、ゴールデン形式で返す。
func Evaluate(cases []evalcase.Case) (eval.Golden, error) {
	evaluations := make([]eval.ProfileEvaluation, 0, len(GateProfiles))
	for _, spec := range GateProfiles {
		stratified, err := eval.EvaluateCasesStratifiedWithOptions(cases, spec.Options)
		if err != nil {
			return eval.Golden{}, fmt.Errorf("profile %s: %w", spec.ID, err)
		}
		evaluations = append(evaluations, eval.ProfileEvaluation{Spec: spec, Stratified: stratified})
	}
	return eval.BuildGolden(evaluations, cases, DatasetID), nil
}

// Tolerance は回帰とみなさない許容幅。合成コーパスは決定的なので既定は小さい。
type Tolerance struct {
	// RecallDrop はルール×プロファイルごとの再現率の低下許容（絶対値）。
	RecallDrop float64
	// FPIncrease はルール×プロファイルごとの行レベル FP 件数の増加許容。
	FPIncrease int
	// FindingFPIncrease は検出単位 FP 件数の増加許容。
	FindingFPIncrease int
	// MicroF1Drop はプロファイル全体（micro）の F1 低下許容（絶対値）。
	MicroF1Drop float64
}

// DefaultTolerance は PR ゲートの既定値。件数の多いルールで 1 件程度の揺れを
// 許すため再現率だけ 0.5 ポイントの幅を持たせ、誤検出の増加は 1 件も許さない。
var DefaultTolerance = Tolerance{RecallDrop: 0.005, FPIncrease: 0, FindingFPIncrease: 0, MicroF1Drop: 0.002}

// Report は比較結果。Regressions が空でなければゲート失敗。
type Report struct {
	// Regressions は許容幅を超えた悪化。
	Regressions []string
	// Stale はゴールデンと異なるが悪化ではない差分（改善・許容内の変化）。
	// ゴールデンの再生成を促すだけで、失敗にはしない。
	Stale []string
}

const eps = 1e-9

// Compare は実測 got をゴールデン want と比較する。
func Compare(got, want eval.Golden, tol Tolerance) Report {
	var r Report
	if got.DatasetID != want.DatasetID {
		r.Regressions = append(r.Regressions, fmt.Sprintf("dataset_id: 実測 %q, ゴールデン %q（生成器を変えたらゴールデンを再生成してください）", got.DatasetID, want.DatasetID))
	}
	gotProfiles := map[string]eval.GoldenProfile{}
	for _, p := range got.Profiles {
		gotProfiles[p.ID] = p
	}
	for _, wp := range want.Profiles {
		gp, ok := gotProfiles[wp.ID]
		if !ok {
			r.Regressions = append(r.Regressions, fmt.Sprintf("profile %s: ゴールデンにあるが実測に無い", wp.ID))
			continue
		}
		compareProfile(&r, gp, wp, tol)
		delete(gotProfiles, wp.ID)
	}
	for id := range gotProfiles {
		r.Stale = append(r.Stale, fmt.Sprintf("profile %s: 実測にあるがゴールデンに無い", id))
	}
	sort.Strings(r.Regressions)
	sort.Strings(r.Stale)
	return r
}

func compareProfile(r *Report, got, want eval.GoldenProfile, tol Tolerance) {
	gotRules := map[string]eval.GoldenRule{}
	for _, rule := range got.Rules {
		gotRules[rule.RuleID] = rule
	}
	for _, w := range want.Rules {
		g, ok := gotRules[w.RuleID]
		label := fmt.Sprintf("profile %s rule %s", want.ID, w.RuleID)
		if !ok {
			// ルールの削除・改名。評価ラベル側の追従漏れ（#166 型）もここに出る。
			r.Regressions = append(r.Regressions, label+": ゴールデンにあるが実測に無い（ルールの削除・改名なら合成器とゴールデンを更新してください）")
			continue
		}
		delete(gotRules, w.RuleID)
		regressed := false
		if w.Row.TP+w.Row.FN > 0 && g.Row.Recall < w.Row.Recall-tol.RecallDrop-eps {
			r.Regressions = append(r.Regressions, fmt.Sprintf("%s: 再現率 %.4f → %.4f（TP %d→%d, FN %d→%d）",
				label, w.Row.Recall, g.Row.Recall, w.Row.TP, g.Row.TP, w.Row.FN, g.Row.FN))
			regressed = true
		}
		if g.Row.FP > w.Row.FP+tol.FPIncrease {
			r.Regressions = append(r.Regressions, fmt.Sprintf("%s: 誤検出（行）%d → %d", label, w.Row.FP, g.Row.FP))
			regressed = true
		}
		if g.Auxiliary.FindingFP > w.Auxiliary.FindingFP+tol.FindingFPIncrease {
			r.Regressions = append(r.Regressions, fmt.Sprintf("%s: 誤検出（検出単位）%d → %d", label, w.Auxiliary.FindingFP, g.Auxiliary.FindingFP))
			regressed = true
		}
		if !regressed && (g.Row != w.Row || g.Auxiliary != w.Auxiliary) {
			r.Stale = append(r.Stale, fmt.Sprintf("%s: TP/FP/FN %d/%d/%d → %d/%d/%d",
				label, w.Row.TP, w.Row.FP, w.Row.FN, g.Row.TP, g.Row.FP, g.Row.FN))
		}
	}
	for id := range gotRules {
		r.Stale = append(r.Stale, fmt.Sprintf("profile %s rule %s: 実測にあるがゴールデンに無い", want.ID, id))
	}
	if got.Micro.F1 < want.Micro.F1-tol.MicroF1Drop-eps {
		r.Regressions = append(r.Regressions, fmt.Sprintf("profile %s micro: F1 %.4f → %.4f", want.ID, want.Micro.F1, got.Micro.F1))
	}
}

// CoverageProblems は「ルールが改名・追加されたのに評価ラベルが追従していない」
// 類の不整合を、ゴールデンとの比較とは独立に検出する。
//   - 合成ケースの Want/Spans が未知のルール ID を指していないこと
//   - 全ルール（既定・高再現率・名簿ファイル判定）に MinPositivesPerRule 件以上の
//     合成陽性があること（新ルールに合成器が無い、改名で合成器の case が外れた等）
//   - all-opt-in プロファイルで全ルールが自分の合成陽性を 1 件以上検出すること
//
// メッセージにはケース本文を含めない。
func CoverageProblems(cases []evalcase.Case, got eval.Golden) []string {
	ruleIDs := corpusv2.AllRuleIDs()
	known := map[string]bool{}
	for _, id := range ruleIDs {
		known[id] = true
	}
	problems := eval.DatasetQualityProblems(cases, known)

	positives := map[string]int{}
	for _, c := range cases {
		seen := map[string]bool{}
		for _, id := range c.Want {
			seen[id] = true
		}
		for _, s := range c.Spans {
			seen[s.RuleID] = true
		}
		for id := range seen {
			positives[id]++
		}
	}
	var all eval.GoldenProfile
	for _, p := range got.Profiles {
		if p.ID == "all-opt-in" {
			all = p
		}
	}
	tp := map[string]int{}
	for _, r := range all.Rules {
		tp[r.RuleID] = r.Row.TP
	}
	for _, id := range ruleIDs {
		if positives[id] < MinPositivesPerRule {
			problems = append(problems, fmt.Sprintf("rule %s: 合成陽性が %d 件（%d 件以上必要）。internal/corpusv2 の positiveCandidates に合成器を追加してください", id, positives[id], MinPositivesPerRule))
			continue
		}
		if tp[id] == 0 {
			problems = append(problems, fmt.Sprintf("rule %s: all-opt-in プロファイルで合成陽性を 1 件も検出できない（ルール ID と合成器のラベルの不一致を疑ってください）", id))
		}
	}
	sort.Strings(problems)
	return problems
}

// Markdown は CI のジョブサマリ用の表を返す（本文は含まない）。
func Markdown(got eval.Golden, rep Report, problems []string) string {
	var b strings.Builder
	b.WriteString("## 公開合成コーパスでの精度ゲート\n\n")
	if len(rep.Regressions) == 0 && len(problems) == 0 {
		b.WriteString("✅ 回帰なし\n\n")
	} else {
		b.WriteString("❌ 回帰または評価ラベルの不整合あり\n\n")
		for _, m := range append(append([]string(nil), problems...), rep.Regressions...) {
			b.WriteString("- " + m + "\n")
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "dataset: `%s`（%d ケース、陽性 %d / 陰性 %d）\n\n", got.DatasetID, got.Dataset.TotalCases, got.Dataset.PositiveCases, got.Dataset.NegativeCases)
	b.WriteString("| profile | TP | FP | FN | precision | recall | F1 |\n|---|---:|---:|---:|---:|---:|---:|\n")
	for _, p := range got.Profiles {
		m := p.Micro
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %.4f | %.4f | %.4f |\n", p.ID, m.TP, m.FP, m.FN, m.Precision, m.Recall, m.F1)
	}
	if len(rep.Stale) > 0 {
		b.WriteString("\n<details><summary>ゴールデンとの差分（悪化ではないもの）: " + fmt.Sprint(len(rep.Stale)) + " 件</summary>\n\n")
		for _, m := range rep.Stale {
			b.WriteString("- " + m + "\n")
		}
		b.WriteString("\n`go test ./internal/publiceval -update` で再生成してコミットしてください。\n</details>\n")
	}
	return b.String()
}
