package detect

import (
	"math"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/external"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// このファイルは MergeExternalFindings（external.go）の候補単位の検証ロジックを
// 直接テストする。internal/external.Run 自体（タイムアウト・不正 JSON 行での
// 全体破棄）は internal/external/external_test.go でモック子プロセスを使って検証済み
// のため、ここでは external.Candidate を直接組み立てて渡し、サブプロセスを起動しない
// （範囲検証・rule_id 接尾辞強制・allowlist・min_confidence・重複解決が対象）。

func TestMergeExternalFindingsEmptyCandidatesReturnsFindingsUnchanged(t *testing.T) {
	d := newDetector(t, "")
	findings := []Finding{{RuleID: "email-address", File: "f.go", Line: 1, Column: 1, Match: "AAAA"}}
	got := d.MergeExternalFindings("f.go", "AAAA is here\n", findings, nil)
	if len(got) != 1 || got[0].RuleID != "email-address" {
		t.Fatalf("got = %+v, want findings unchanged", got)
	}
}

func TestMergeExternalFindingsValidCandidateBecomesFinding(t *testing.T) {
	d := newDetector(t, "")
	content := "value XYZW appears here\n"
	cands := []external.Candidate{
		{File: "f.go", RuleID: "person-name-external", Line: 1, Column: 7, Length: 4, Confidence: "medium"},
	}
	got := d.MergeExternalFindings("f.go", content, nil, cands)
	if len(got) != 1 {
		t.Fatalf("got = %+v, want 1 finding", got)
	}
	f := got[0]
	if f.RuleID != "person-name-external" {
		t.Errorf("RuleID = %q, want person-name-external", f.RuleID)
	}
	if f.Match != "XYZW" {
		t.Errorf("Match = %q, want XYZW (extracted from content by parent, not trusted from child)", f.Match)
	}
	if f.Confidence != rule.Medium {
		t.Errorf("Confidence = %v, want Medium", f.Confidence)
	}
	if f.Line != 1 || f.Column != 7 {
		t.Errorf("Line/Column = %d/%d, want 1/7", f.Line, f.Column)
	}
	if !f.Reason.External {
		t.Error("Reason.External = false, want true")
	}
	if f.Reason.Validated {
		t.Error("Reason.Validated = true, want false（外部候補は内部検証を経ていない）")
	}
}

func TestMergeExternalFindingsIgnoresCandidatesForOtherFiles(t *testing.T) {
	d := newDetector(t, "")
	content := "value XYZW appears here\n"
	cands := []external.Candidate{
		{File: "other.go", RuleID: "person-name-external", Line: 1, Column: 7, Length: 4, Confidence: "medium"},
	}
	got := d.MergeExternalFindings("f.go", content, nil, cands)
	if len(got) != 0 {
		t.Fatalf("got = %+v, want 0 (candidate.File does not match the file being merged)", got)
	}
}

func TestMergeExternalFindingsRejectsMissingRuleIDSuffix(t *testing.T) {
	d := newDetector(t, "")
	content := "value XYZW appears here\n"
	tests := []string{
		"jp-my-number",          // 組み込みルール ID の偽装
		"person-name",           // 接尾辞なし
		"person-name-external2", // 接尾辞に見えるが違う
		"",                      // 空文字
	}
	for _, id := range tests {
		cands := []external.Candidate{{File: "f.go", RuleID: id, Line: 1, Column: 7, Length: 4, Confidence: "high"}}
		got := d.MergeExternalFindings("f.go", content, nil, cands)
		if len(got) != 0 {
			t.Errorf("rule_id=%q: got = %+v, want 0 (missing -external suffix must be rejected)", id, got)
		}
	}
}

func TestMergeExternalFindingsRejectsOutOfRangeSpans(t *testing.T) {
	d := newDetector(t, "")
	content := "12345\n67890\n" // 2 行、各 5 ルーン
	tests := []struct {
		name string
		c    external.Candidate
	}{
		{"line too small", external.Candidate{Line: 0, Column: 1, Length: 1}},
		{"line too large", external.Candidate{Line: 3, Column: 1, Length: 1}},
		{"column too small", external.Candidate{Line: 1, Column: 0, Length: 1}},
		{"length zero", external.Candidate{Line: 1, Column: 1, Length: 0}},
		{"length negative", external.Candidate{Line: 1, Column: 1, Length: -1}},
		{"span exceeds line length", external.Candidate{Line: 1, Column: 3, Length: 10}},
		{"column beyond line length", external.Candidate{Line: 1, Column: 9, Length: 1}},
		// Length は子プロセスの自己申告値（JSON 由来で任意の int）。math.MaxInt 近辺の
		// 値だと start+Length の素朴な加算がオーバーフローして負数に wrap し、範囲外
		// チェックをすり抜けたうえで runes[start:end] がスライス境界パニックを
		// 起こしうる（検出器全体をクラッシュさせる DoS）。減算ベースの比較で
		// オーバーフローなく安全に棄却できることを確認する。
		{"length near MaxInt overflows naive addition", external.Candidate{Line: 1, Column: 2, Length: math.MaxInt}},
		{"length exactly MaxInt-Column", external.Candidate{Line: 1, Column: 1, Length: math.MaxInt}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.c
			c.File = "f.go"
			c.RuleID = "x-external"
			c.Confidence = "high"
			got := d.MergeExternalFindings("f.go", content, nil, []external.Candidate{c})
			if len(got) != 0 {
				t.Errorf("got = %+v, want 0 (out-of-range span must be rejected)", got)
			}
		})
	}
	// 対照: 範囲内なら通ることを確認する（境界判定自体が壊れていないことの確認）。
	valid := external.Candidate{File: "f.go", RuleID: "x-external", Line: 2, Column: 1, Length: 5, Confidence: "high"}
	got := d.MergeExternalFindings("f.go", content, nil, []external.Candidate{valid})
	if len(got) != 1 {
		t.Fatalf("in-range candidate got = %+v, want 1 finding", got)
	}
}

func TestMergeExternalFindingsRespectsIgnoreMarker(t *testing.T) {
	d := newDetector(t, "")
	content := "value XYZW here " + IgnoreMarker + "\n"
	cands := []external.Candidate{
		{File: "f.go", RuleID: "person-name-external", Line: 1, Column: 7, Length: 4, Confidence: "high"},
	}
	got := d.MergeExternalFindings("f.go", content, nil, cands)
	if len(got) != 0 {
		t.Fatalf("got = %+v, want 0 (ignore marker on the value-bearing line must suppress the candidate)", got)
	}
}

func TestMergeExternalFindingsRespectsAllowlistStopword(t *testing.T) {
	d := newDetector(t, `
[allowlist]
stopwords = ["XYZW"]
`)
	content := "value XYZW appears here\n"
	cands := []external.Candidate{
		{File: "f.go", RuleID: "person-name-external", Line: 1, Column: 7, Length: 4, Confidence: "high"},
	}
	got := d.MergeExternalFindings("f.go", content, nil, cands)
	if len(got) != 0 {
		t.Fatalf("got = %+v, want 0 (allowlisted stopword must suppress the candidate)", got)
	}
}

func TestMergeExternalFindingsRespectsAllowlistRegex(t *testing.T) {
	d := newDetector(t, `
[allowlist]
regexes = ["^XYZ"]
`)
	content := "value XYZW appears here\n"
	cands := []external.Candidate{
		{File: "f.go", RuleID: "person-name-external", Line: 1, Column: 7, Length: 4, Confidence: "high"},
	}
	got := d.MergeExternalFindings("f.go", content, nil, cands)
	if len(got) != 0 {
		t.Fatalf("got = %+v, want 0 (allowlisted regex must suppress the candidate)", got)
	}
}

// TestMergeExternalFindingsAllowlistNormalizesWithFullLineContext は、allowlist 判定が
// 切り出した部分文字列を単独で正規化するのではなく、行全体を正規化してから同じ位置で
// 切り出すことを確認する。数字隣接の長音記号（ー）は normalize.Line では周囲の数字が
// あって初めて "-" に変換されるため（internal/normalize の不変条件）、"ー" 単体を
// 切り出してから正規化すると変換されず、行全体正規化との食い違いが生じうる。
func TestMergeExternalFindingsAllowlistNormalizesWithFullLineContext(t *testing.T) {
	d := newDetector(t, `
[allowlist]
stopwords = ["-"]
`)
	content := "12ー34\n"
	// "ー" だけを指すスパン（1 始まり: 3 列目、1 ルーン）。
	cands := []external.Candidate{
		{File: "f.go", RuleID: "x-external", Line: 1, Column: 3, Length: 1, Confidence: "high"},
	}
	got := d.MergeExternalFindings("f.go", content, nil, cands)
	if len(got) != 0 {
		t.Fatalf("got = %+v, want 0 (行全体を正規化すれば数字隣接の ー は - になり、stopword \"-\" に一致するはず)", got)
	}
}

func TestMergeExternalFindingsRespectsMinConfidence(t *testing.T) {
	d := newDetector(t, `min_confidence = "high"`)
	content := "value XYZW appears here\n"
	cands := []external.Candidate{
		{File: "f.go", RuleID: "person-name-external", Line: 1, Column: 7, Length: 4, Confidence: "medium"},
	}
	got := d.MergeExternalFindings("f.go", content, nil, cands)
	if len(got) != 0 {
		t.Fatalf("got = %+v, want 0 (medium < min_confidence=high)", got)
	}

	candsHigh := []external.Candidate{
		{File: "f.go", RuleID: "person-name-external", Line: 1, Column: 7, Length: 4, Confidence: "high"},
	}
	got = d.MergeExternalFindings("f.go", content, nil, candsHigh)
	if len(got) != 1 {
		t.Fatalf("got = %+v, want 1 (high meets min_confidence=high)", got)
	}
}

func TestMergeExternalFindingsInvalidConfidenceDefaultsToLow(t *testing.T) {
	content := "value XYZW appears here\n"

	// min_confidence の既定は medium なので、不正値→low 扱いは破棄される。
	dMedium := newDetector(t, "")
	candsInvalid := []external.Candidate{
		{File: "f.go", RuleID: "person-name-external", Line: 1, Column: 7, Length: 4, Confidence: "not-a-level"},
	}
	got := dMedium.MergeExternalFindings("f.go", content, nil, candsInvalid)
	if len(got) != 0 {
		t.Fatalf("got = %+v, want 0 (invalid confidence must default to low, which is below default min_confidence=medium)", got)
	}

	// min_confidence=low なら、low 扱いでも生存する。
	dLow := newDetector(t, `min_confidence = "low"`)
	got = dLow.MergeExternalFindings("f.go", content, nil, candsInvalid)
	if len(got) != 1 {
		t.Fatalf("got = %+v, want 1 finding at Low confidence", got)
	}
	if got[0].Confidence != rule.Low {
		t.Errorf("Confidence = %v, want Low", got[0].Confidence)
	}
}

func TestMergeExternalFindingsRespectsDisabledRules(t *testing.T) {
	d := newDetector(t, `
[rules]
disabled = ["person-name-external"]
`)
	content := "value XYZW appears here\n"
	cands := []external.Candidate{
		{File: "f.go", RuleID: "person-name-external", Line: 1, Column: 7, Length: 4, Confidence: "high"},
	}
	got := d.MergeExternalFindings("f.go", content, nil, cands)
	if len(got) != 0 {
		t.Fatalf("got = %+v, want 0 (rule_id listed in [rules] disabled must be suppressed like any built-in rule)", got)
	}
}

func TestMergeExternalFindingsOverlapResolutionUsesExistingRules(t *testing.T) {
	d := newDetector(t, "")
	content := "AAAA is the value\n"

	// 既存の高信頼 finding と重なる低信頼の外部候補は、既存の決着規則
	// （better(): 信頼度優先）により既存側が残る。
	builtin := Finding{
		RuleID: "email-address", File: "f.go", Line: 1, Column: 1, Match: "AAAA",
		Confidence: rule.High, start: 0, end: 4,
	}
	lowExternal := []external.Candidate{
		{File: "f.go", RuleID: "x-external", Line: 1, Column: 1, Length: 4, Confidence: "low"},
	}
	got := d.MergeExternalFindings("f.go", content, []Finding{builtin}, lowExternal)
	if len(got) != 1 || got[0].RuleID != "email-address" {
		t.Fatalf("got = %+v, want the higher-confidence built-in finding to win", got)
	}

	// 逆に、既存が低信頼で外部候補が高信頼なら、外部候補が残る
	// （外部候補だから優劣が付くわけではなく、通常の信頼度比較がそのまま働くことの確認）。
	lowBuiltin := Finding{
		RuleID: "person-name", File: "f.go", Line: 1, Column: 1, Match: "AAAA",
		Confidence: rule.Low, start: 0, end: 4,
	}
	highExternal := []external.Candidate{
		{File: "f.go", RuleID: "x-external", Line: 1, Column: 1, Length: 4, Confidence: "high"},
	}
	got = d.MergeExternalFindings("f.go", content, []Finding{lowBuiltin}, highExternal)
	if len(got) != 1 || got[0].RuleID != "x-external" {
		t.Fatalf("got = %+v, want the higher-confidence external candidate to win", got)
	}
}

func TestMergeExternalFindingsMultipleCandidatesNonOverlapping(t *testing.T) {
	d := newDetector(t, "")
	content := "AAAA and BBBB on one line\n"
	cands := []external.Candidate{
		{File: "f.go", RuleID: "x-external", Line: 1, Column: 1, Length: 4, Confidence: "medium"},
		{File: "f.go", RuleID: "y-external", Line: 1, Column: 11, Length: 4, Confidence: "medium"},
	}
	got := d.MergeExternalFindings("f.go", content, nil, cands)
	if len(got) != 2 {
		t.Fatalf("got = %+v, want 2 non-overlapping findings", got)
	}
}
