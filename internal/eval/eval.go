// Package eval はラベル付き評価データセットに対する検出精度
// （適合率・再現率・F1）を計測する。検出ルールごとの品質を
// 数値で表し、README のバッジと CI の回帰ガードの根拠にする。
package eval

import (
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/piifixtures"
)

// Case / Span は評価ケースとその期待検出範囲。実在しうる PII を含む
// 評価データセットは piifixtures（リポジトリ外 JSON）から読み込むため、
// 型定義は piifixtures に置き、ここでは型別名で参照する。
type (
	Case     = piifixtures.Case
	Span     = piifixtures.Span
	DiffLine = piifixtures.DiffLine
)

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
	// Negatives はデータセット全体で Want・Spans が両方とも空の「陰性ケース」の
	// 総数（全ルール共通の母数で、FP を正規化した偽陽性率などに使う）。
	Negatives int
	// FindingFP は行レベルの FP（ケースにつき最大 1 件、既存の FP と同じ集計）
	// とは別に、検出単位で数えた誤検出数。1 ケース内で同一ルールが複数回
	// 誤検出しても FP は 1 のままだが、FindingFP はその実数を反映する
	// （そのルールが期待されていないケースでの finding 数の合計）。
	FindingFP int
	// ConfidenceMiss は、期待スパンに WantConfidence が設定されているケースで、
	// 検出はできた（span exact 一致）ものの実際の最終信頼度が期待未満だった件数。
	// 既定設定（min_confidence=medium 等）で黙って埋もれる「実質検出漏れ」を表す。
	ConfidenceMiss int
}

// Options は評価時の検出器設定。ゼロ値では従来どおり min_confidence=low、
// high-recall ルール無効で評価する。
type Options struct {
	MinConfidence string
	HighRecall    bool
}

// Evaluate はデータセット全体を走査し、ルールごとの指標を返す。
// すべてのルールを評価対象にするため min_confidence=low で検出する。
// ErrNoDataset は評価データセット（piifixtures）が取得できないことを表す。
// 認証情報やフィクスチャ JSON が無い環境では、呼び出し側テストが Skip する。
var ErrNoDataset = errors.New("評価データセットが利用できません（" + piifixtures.EnvVar + " を設定してください）")

func Evaluate() ([]Result, error) {
	return EvaluateWithOptions(Options{MinConfidence: "low"})
}

// EvaluateWithOptions はデータセット全体を指定オプションで走査し、ルールごとの
// 指標を返す。README の既存バッジは Evaluate の low 閾値評価を使い続けるが、
// 開発時には既定 CLI 相当（medium）や high-recall 有効時の指標も同じハーネスで
// 計測できる。
func EvaluateWithOptions(opts Options) ([]Result, error) {
	cases, ok := piifixtures.Dataset()
	if !ok {
		return nil, ErrNoDataset
	}
	return EvaluateCasesWithOptions(cases, opts)
}

// EvaluateCases は指定されたケース集合を評価する。Evaluate は piifixtures から
// 読み込んだ外部データセットをこれに渡す薄いラッパーで、テストは任意のケースを渡せる。
func EvaluateCases(cases []Case) ([]Result, error) {
	return EvaluateCasesWithOptions(cases, Options{MinConfidence: "low"})
}

// EvaluateCasesWithOptions は指定されたケース集合を、指定オプションで評価する。
func EvaluateCasesWithOptions(cases []Case, opts Options) ([]Result, error) {
	s, err := EvaluateCasesStratifiedWithOptions(cases, opts)
	if err != nil {
		return nil, err
	}
	return s.Results, nil
}

// Stratified はルール別の Result に加えて、ケース単位のタグ（Case.Tags）と
// ケース種別（line/content/diff、どの入力フィールドを使ったか）で層別集計した
// 行レベル（TP/FP/FN の和集合、Result.TP 等と同じ定義）の Score を保持する。
// ルール別スコアと違い、1 ケースに複数ルールの Want/検出があれば同じタグ・
// 種別のバケツへまとめて加算する。表記ゆれ耐性の可視化・回帰検出用
// （docs/accuracy.md のタグ別・ケース種別別表、P27）。
type Stratified struct {
	Results []Result
	// Tags はケースの Tags（例: notation:fullwidth, sep:hyphen, source:synthetic）
	// をキーにした行レベル Score。タグを持たないケースは含まれない。
	Tags map[string]Score
	// Kinds は "line" / "content" / "diff" をキーにした行レベル Score。
	// すべてのケースがいずれか 1 つに属する。
	Kinds map[string]Score
}

// EvaluateStratified は piifixtures の外部データセットを Evaluate 相当の
// 既定オプション（min_confidence=low）で評価し、タグ別・ケース種別別の
// 層別集計も返す。
func EvaluateStratified() (Stratified, error) {
	return EvaluateStratifiedWithOptions(Options{MinConfidence: "low"})
}

// EvaluateStratifiedWithOptions は piifixtures の外部データセットを指定
// オプションで評価し、タグ別・ケース種別別の層別集計も返す。
func EvaluateStratifiedWithOptions(opts Options) (Stratified, error) {
	cases, ok := piifixtures.Dataset()
	if !ok {
		return Stratified{}, ErrNoDataset
	}
	return EvaluateCasesStratifiedWithOptions(cases, opts)
}

// EvaluateCasesStratifiedWithOptions は EvaluateCasesWithOptions と同じ評価を
// 1 パスで行い、ルール別 Result に加えてタグ別・ケース種別別の層別集計も返す。
func EvaluateCasesStratifiedWithOptions(cases []Case, opts Options) (Stratified, error) {
	minConfidence := opts.MinConfidence
	if minConfidence == "" {
		minConfidence = "low"
	}
	cfg, err := config.Parse(fmt.Sprintf("min_confidence = %q\n[rules]\nhigh_recall = %t\n",
		minConfidence, opts.HighRecall))
	if err != nil {
		return Stratified{}, err
	}
	d, err := detect.New(cfg)
	if err != nil {
		return Stratified{}, err
	}

	type counts struct {
		row            Score
		spanExact      Score
		spanRelaxed    Score
		findingFP      int
		confidenceMiss int
	}
	stat := map[string]*counts{}
	at := func(id string) *counts {
		if stat[id] == nil {
			stat[id] = &counts{}
		}
		return stat[id]
	}
	tagStat := map[string]*Score{}
	kindStat := map[string]*Score{}

	negatives := 0
	for _, c := range cases {
		// Want・Spans がともに空のケースは陰性（何も検出されないべき）として
		// 母数に数える。全ルール共通の母数のため、ケースループの外で
		// Result に一律付与する（ルールごとに数え直さない）。
		if len(c.Want) == 0 && len(c.Spans) == 0 {
			negatives++
		}

		want := map[string]bool{}
		for _, id := range c.Want {
			want[id] = true
			at(id) // 母数 0 のルールも結果に出す
		}
		for _, s := range c.Spans {
			if s.RuleID == "" {
				return Stratified{}, fmt.Errorf("span rule id is empty for case %q", caseLabel(c))
			}
			if s.Line < 0 || s.Start < 0 || s.End < s.Start {
				return Stratified{}, fmt.Errorf("invalid span for %s in case %q: line %d [%d,%d)",
					s.RuleID, caseLabel(c), s.Line, s.Start, s.End)
			}
			if s.WantConfidence != "" && !validConfidence(s.WantConfidence) {
				return Stratified{}, fmt.Errorf("invalid want_confidence %q for %s in case %q: want low, medium, or high",
					s.WantConfidence, s.RuleID, caseLabel(c))
			}
			want[s.RuleID] = true
			at(s.RuleID)
		}
		got := map[string]bool{}
		findingCounts := map[string]int{}
		findings, err := scanCase(d, c)
		if err != nil {
			return Stratified{}, err
		}
		for _, f := range findings {
			got[f.RuleID] = true
			findingCounts[f.RuleID]++
		}
		// 期待・検出の和集合でルールごとに TP/FP/FN を加算する（行レベル、
		// wantF1 の算出に使う既存の集計で、互換のため定義は変更しない）。
		// ケース単位のタグ・種別バケツにも同じ加算結果をまとめて足し、ケース内で
		// 複数ルールの期待・検出があれば層別スコアへ合算する。
		var caseScore Score
		for id := range want {
			if got[id] {
				at(id).row.TP++
				caseScore.TP++
			} else {
				at(id).row.FN++
				caseScore.FN++
			}
		}
		for id := range got {
			if !want[id] {
				at(id).row.FP++
				caseScore.FP++
			}
		}
		kind := caseKind(c)
		if kindStat[kind] == nil {
			kindStat[kind] = &Score{}
		}
		addScore(kindStat[kind], caseScore)
		for _, tag := range c.Tags {
			if tagStat[tag] == nil {
				tagStat[tag] = &Score{}
			}
			addScore(tagStat[tag], caseScore)
		}
		// 検出単位 FP: 期待されていないルールについては、そのケース内で実際に
		// 検出された件数をそのまま加算する（行レベル FP は 1 ケース最大 1 だが、
		// こちらは同一ケース内の多重誤検出を過小評価しない）。
		for id, n := range findingCounts {
			if !want[id] {
				at(id).findingFP += n
			}
		}

		if len(c.Spans) > 0 {
			wantSpans := map[string][]Span{}
			for _, s := range c.Spans {
				wantSpans[s.RuleID] = append(wantSpans[s.RuleID], s)
			}
			gotSpans := map[string][]Span{}
			gotConf := map[string][]string{}
			for _, f := range findings {
				s := spanFromFinding(f)
				gotSpans[s.RuleID] = append(gotSpans[s.RuleID], s)
				gotConf[s.RuleID] = append(gotConf[s.RuleID], f.Reason.FinalConfidence)
			}

			for id, spans := range wantSpans {
				gotForRule := gotSpans[id]
				confForRule := gotConf[id]
				exact, exactPairs := matchSpans(spans, gotForRule, spansEqual)
				relaxed, _ := matchSpans(spans, gotForRule, spansOverlap)
				addScore(&at(id).spanExact, exact)
				addScore(&at(id).spanRelaxed, relaxed)
				// want_confidence: exact 一致（位置の対応が一意）した検出だけを対象に、
				// 実際の最終信頼度が期待未満なら ConfidenceMiss に数える。
				for wi, gi := range exactPairs {
					if gi < 0 {
						continue // 未検出（FN）は対象外
					}
					wantConf := spans[wi].WantConfidence
					if wantConf == "" {
						continue // 信頼度チェック対象外のスパン
					}
					if confidenceRank(confForRule[gi]) < confidenceRank(wantConf) {
						at(id).confidenceMiss++
					}
				}
				delete(gotSpans, id)
				delete(gotConf, id)
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
			RuleID:         id,
			TP:             c.row.TP,
			FP:             c.row.FP,
			FN:             c.row.FN,
			Precision:      c.row.Precision,
			Recall:         c.row.Recall,
			F1:             c.row.F1,
			SpanExact:      c.spanExact,
			SpanRelaxed:    c.spanRelaxed,
			Negatives:      negatives,
			FindingFP:      c.findingFP,
			ConfidenceMiss: c.confidenceMiss,
		}
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].RuleID < results[j].RuleID })

	tags := make(map[string]Score, len(tagStat))
	for tag, s := range tagStat {
		fillScore(s)
		tags[tag] = *s
	}
	kinds := make(map[string]Score, len(kindStat))
	for kind, s := range kindStat {
		fillScore(s)
		kinds[kind] = *s
	}
	return Stratified{Results: results, Tags: tags, Kinds: kinds}, nil
}

// caseKind はケースがどの入力フィールドを使うかを "line" / "content" / "diff" で
// 返す。scanCase の分岐（diff > content > line の優先順）と一致させる。
func caseKind(c Case) string {
	switch {
	case len(c.Diff) > 0:
		return "diff"
	case c.Content != "":
		return "content"
	default:
		return "line"
	}
}

// confidenceRankOrder は rule.Confidence の順序を文字列表現のまま比較するための
// 対応表（detect.DetectReason.FinalConfidence / piifixtures.Span.WantConfidence は
// いずれも "low"|"medium"|"high" の文字列のため、ここでは internal/rule に依存しない）。
var confidenceRankOrder = map[string]int{"low": 1, "medium": 2, "high": 3}

func validConfidence(s string) bool {
	_, ok := confidenceRankOrder[s]
	return ok
}

// confidenceRank は信頼度文字列の順序値を返す。未知の文字列（空文字含む）は
// 0 を返す。WantConfidence は評価前に validConfidence で検証する。
func confidenceRank(s string) int {
	return confidenceRankOrder[s]
}

func scanCase(d *detect.Detector, c Case) ([]detect.Finding, error) {
	file := c.File
	if file == "" {
		file = "dataset"
	}
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
	if inputs > 1 {
		return nil, fmt.Errorf("ambiguous eval case %q: set only one of line, content, diff", caseLabel(c))
	}
	if inputs == 0 && (len(c.Want) > 0 || len(c.Spans) > 0) {
		return nil, fmt.Errorf("missing eval case input for expected case %q: set one of line, content, diff", caseLabel(c))
	}
	switch {
	case len(c.Diff) > 0:
		lines := make([]detect.DiffLine, len(c.Diff))
		for i, l := range c.Diff {
			lines[i] = detect.DiffLine{Text: l.Text, Added: l.Added}
		}
		return d.ScanDiffHunk(file, lines), nil
	case c.Content != "":
		return d.ScanContent(file, c.Content), nil
	default:
		return d.ScanLine(file, 1, c.Line), nil
	}
}

func caseLabel(c Case) string {
	switch {
	case len(c.Diff) > 0:
		return fmt.Sprintf("diff:%d lines", len(c.Diff))
	case c.Content != "":
		return fmt.Sprintf("content:%d runes", len([]rune(c.Content)))
	default:
		return fmt.Sprintf("line:%d runes", len([]rune(c.Line)))
	}
}

func spanFromFinding(f detect.Finding) Span {
	start := f.Column - 1
	return Span{
		RuleID: f.RuleID,
		Line:   f.Line,
		Start:  start,
		End:    start + len([]rune(f.Match)),
	}
}

// matchSpans は want の各要素を got の要素と最大二部マッチングで対応付ける。
// 戻り値の pairs は want と同じ長さで、pairs[wi] は一致した got のインデックス
// （未一致なら -1）。want_confidence の照合など、一致した検出そのもの
// （どの Span/Finding に対応したか）を参照したい呼び出し側のために返す。
func matchSpans(want, got []Span, match func(Span, Span) bool) (Score, []int) {
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
	}, matchTo
}

func spansEqual(a, b Span) bool {
	return a.RuleID == b.RuleID && spanLine(a) == spanLine(b) && a.Start == b.Start && a.End == b.End
}

func spansOverlap(a, b Span) bool {
	return a.RuleID == b.RuleID && spanLine(a) == spanLine(b) && a.Start < b.End && b.Start < a.End
}

func spanLine(s Span) int {
	if s.Line <= 0 {
		return 1
	}
	return s.Line
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
	var findingFP int
	for _, r := range results {
		s.TP += r.TP
		s.FP += r.FP
		s.FN += r.FN
		findingFP += r.FindingFP
	}
	fillScore(&s)
	var negatives int
	if len(results) > 0 {
		// Negatives は全ルール共通の母数（陰性ケース総数）なのでルール数倍に
		// 合算せず、いずれかの結果から 1 回だけ取り出す。
		negatives = results[0].Negatives
	}
	return Result{
		RuleID:    "micro",
		TP:        s.TP,
		FP:        s.FP,
		FN:        s.FN,
		Precision: s.Precision,
		Recall:    s.Recall,
		F1:        s.F1,
		Negatives: negatives,
		FindingFP: findingFP,
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
