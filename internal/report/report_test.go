package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/baseline"
	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/rule"
	"github.com/baneido/jp-pii-detector/internal/testfixtures"
)

// sample は電話番号 1 件の検出結果を返す。実在しうる携帯番号形式はリポジトリに
// コミットしないため、Match の値はフィクスチャから受け取る。
func sample(match string) []detect.Finding {
	return []detect.Finding{{
		RuleID:      "jp-phone-number",
		Description: "電話番号",
		File:        "users.csv",
		Line:        4,
		Column:      6,
		Match:       match,
		Confidence:  rule.High,
	}}
}

func TestMask(t *testing.T) {
	tests := []struct{ in, want string }{
		{testfixtures.MustGet(t, "report.phone_for_mask"), "09*********00"}, // 090-0000-0000（13 文字: 先頭・末尾 2 文字）
		{"abc", "***"},
		{"abcdef", "a****f"},
		{"", ""},                 // 空文字
		{"abcd", "****"},         // 4 文字以下は全マスク
		{"abcde", "a***e"},       // 5 文字（先頭・末尾 1 文字）
		{"abcdefg", "a*****g"},   // 7 文字（< 8 の上限）
		{"abcdefgh", "ab****gh"}, // 8 文字（先頭・末尾 2 文字に切替）
		{testfixtures.MustGet(t, "report.phone_fullwidth_in"), "０９*******００"}, // 全角 11 文字: マルチバイトはルーン単位
	}
	for _, tt := range tests {
		if got := Mask(tt.in); got != tt.want {
			t.Errorf("Mask(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTextMasksByDefault(t *testing.T) {
	phone := testfixtures.MustGet(t, "report.phone_match")
	var buf bytes.Buffer
	Text(&buf, sample(phone), false, false, nil, false)
	out := buf.String()
	if strings.Contains(out, phone) {
		t.Error("output should be masked")
	}
	if !strings.Contains(out, "users.csv:4:6") {
		t.Errorf("missing location: %s", out)
	}
	if !strings.Contains(out, "1 件") || !strings.Contains(out, "jp-pii-detector:ignore") {
		t.Errorf("missing summary with remediation hint: %s", out)
	}
}

func TestTextNoFindingsNoSummary(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, nil, false, false, nil, false)
	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %q", buf.String())
	}
}

// TestTextExplainIncludesReason は --explain 相当の explain=true 指定で、
// text 出力にも検出理由（コンテキスト昇格・検証有無等）が付与されることを確認する。
// explain=false（既定）では従来どおり理由行が出ないことも併せて確認する。
// フィクスチャ不要（実在しうる PII 形式を含まない合成データのため）。
func TestTextExplainIncludesReason(t *testing.T) {
	fs := []detect.Finding{{
		RuleID:      "jp-phone-number",
		Description: "電話番号",
		File:        "users.csv",
		Line:        4,
		Column:      6,
		Match:       "ABCDEFGHIJK",
		Confidence:  rule.High,
		Reason: detect.DetectReason{
			BaseConfidence:  "medium",
			FinalConfidence: "high",
			ContextKeywords: []string{"tel"},
			ContextPromoted: true,
			Validated:       true,
		},
	}}

	var withExplain bytes.Buffer
	Text(&withExplain, fs, false, true, nil, false)
	out := withExplain.String()
	if !strings.Contains(out, "理由:") {
		t.Fatalf("--explain 相当の text 出力に理由が無い: %s", out)
	}
	if !strings.Contains(out, "基準信頼度=medium") || !strings.Contains(out, "最終信頼度=high") {
		t.Errorf("信頼度の遷移が理由に含まれない: %s", out)
	}
	if !strings.Contains(out, "コンテキスト昇格=true") || !strings.Contains(out, "キーワード=tel") {
		t.Errorf("コンテキスト情報が理由に含まれない: %s", out)
	}
	if strings.Contains(out, fs[0].Match) {
		t.Error("--explain でも検出値はマスクされたままであるべき")
	}

	var withoutExplain bytes.Buffer
	Text(&withoutExplain, fs, false, false, nil, false)
	if strings.Contains(withoutExplain.String(), "理由:") {
		t.Errorf("explain=false では理由行を出すべきではない: %s", withoutExplain.String())
	}
}

// TestTextExplainIncludesKind は Reason.Kind（jp-phone-number の PhoneKind 等、
// Rule.Kind が設定されたルールの下位種別）が --explain 相当の text 出力に
// 含まれることを確認する最小ケース。フィクスチャ不要（実在しうる PII 形式を
// 含まない合成データのため）。
func TestTextExplainIncludesKind(t *testing.T) {
	fs := []detect.Finding{{
		RuleID:      "jp-phone-number",
		Description: "電話番号",
		File:        "users.csv",
		Line:        4,
		Column:      6,
		Match:       "ABCDEFGHIJK",
		Confidence:  rule.Medium,
		Reason: detect.DetectReason{
			BaseConfidence:  "medium",
			FinalConfidence: "medium",
			Kind:            "service",
		},
	}}

	var buf bytes.Buffer
	Text(&buf, fs, false, true, nil, false)
	if !strings.Contains(buf.String(), "種別=service") {
		t.Errorf("--explain 相当の text 出力に種別(Kind)が無い: %s", buf.String())
	}
}

// TestTextIncludesBaselineHint はサマリ行に --update-baseline の案内が
// 含まれることを確認する（IgnoreMarker の案内と同様の形式）。フィクスチャ不要。
func TestTextIncludesBaselineHint(t *testing.T) {
	findings := []detect.Finding{{RuleID: "jp-phone-number", File: "users.csv", Line: 4, Column: 6, Match: "dummy-value-1"}}
	var buf bytes.Buffer
	Text(&buf, findings, false, false, nil, false)
	out := buf.String()
	if !strings.Contains(out, "--update-baseline") {
		t.Errorf("missing baseline remediation hint: %s", out)
	}
}

// confidence → SARIF level の対応（high=error, medium=warning, low=note）。
func TestSARIFLevels(t *testing.T) {
	phone := testfixtures.MustGet(t, "report.phone_match")
	fs := []detect.Finding{}
	for _, c := range []rule.Confidence{rule.High, rule.Medium, rule.Low} {
		f := sample(phone)[0]
		f.Confidence = c
		fs = append(fs, f)
	}
	var buf bytes.Buffer
	if err := SARIF(&buf, fs, rule.Builtin(), false); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Level string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, r := range doc.Runs[0].Results {
		got = append(got, r.Level)
	}
	want := []string{"error", "warning", "note"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("levels = %v, want %v", got, want)
			break
		}
	}
}

func TestJSON(t *testing.T) {
	phone := testfixtures.MustGet(t, "report.phone_match")
	var buf bytes.Buffer
	if err := JSON(&buf, sample(phone), true, false, nil, false); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Count    int `json:"count"`
		Findings []struct {
			Match      string `json:"match"`
			Confidence string `json:"confidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Count != 1 || got.Findings[0].Match != phone || got.Findings[0].Confidence != "high" {
		t.Errorf("unexpected JSON: %s", buf.String())
	}
}

// TestJSONOffsets は scan --stdin で付与される offset/end_offset の JSON 出力を確認する。
// 特に offset==0（テキスト先頭一致）が省略されず "offset": 0 として出ること
// （*int + omitempty をうっかり int + omitempty に戻すと 0 が欠落する回帰の防止）と、
// HasOffset でない finding には両フィールドが現れないことを検証する。フィクスチャ不要。
func TestJSONOffsets(t *testing.T) {
	findings := []detect.Finding{
		{RuleID: "a", File: "<stdin>", Line: 1, Column: 1, Match: "abc",
			HasOffset: true, Offset: 0, EndOffset: 3},
		{RuleID: "b", File: "<stdin>", Line: 1, Column: 5, Match: "de"}, // HasOffset=false
	}
	var buf bytes.Buffer
	if err := JSON(&buf, findings, true, false, nil, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"offset": 0`) {
		t.Errorf(`offset==0 が省略された（"offset": 0 が無い）: %s`, out)
	}

	var got struct {
		Findings []struct {
			Offset    *int `json:"offset"`
			EndOffset *int `json:"end_offset"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	f0 := got.Findings[0]
	if f0.Offset == nil || *f0.Offset != 0 || f0.EndOffset == nil || *f0.EndOffset != 3 {
		t.Errorf("finding[0] offsets = %v/%v, want 0/3: %s", f0.Offset, f0.EndOffset, out)
	}
	if f1 := got.Findings[1]; f1.Offset != nil || f1.EndOffset != nil {
		t.Errorf("HasOffset でない finding に offset が出ている: %s", out)
	}
}

// TestJSONFingerprint は salt を渡したときだけ internal/baseline と同じ
// アルゴリズムの fingerprint フィールドが JSON に出ること、salt を渡さない
// 既存呼び出し（後方互換）では fingerprint が出ないことを確認する。フィクスチャ不要。
func TestJSONFingerprint(t *testing.T) {
	findings := []detect.Finding{{RuleID: "jp-phone-number", File: "app/users.csv", Line: 1, Column: 1, Match: "dummy-value-1"}}

	var withoutSalt bytes.Buffer
	if err := JSON(&withoutSalt, findings, true, false, nil, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(withoutSalt.String(), "fingerprint") {
		t.Errorf("salt 未指定時は fingerprint を出力しないはず: %s", withoutSalt.String())
	}

	var withSalt bytes.Buffer
	if err := JSON(&withSalt, findings, true, false, nil, false, "test-salt"); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Findings []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(withSalt.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := baseline.FindingFingerprint("test-salt", findings[0])
	if len(got.Findings) != 1 || got.Findings[0].Fingerprint != want {
		t.Errorf("fingerprint = %+v, want %q", got.Findings, want)
	}
}

func TestJSONExplainIncludesReason(t *testing.T) {
	phone := testfixtures.MustGet(t, "report.phone_match")
	fs := sample(phone)
	fs[0].Reason = detect.DetectReason{
		BaseConfidence:  "medium",
		FinalConfidence: "high",
		ContextKeywords: []string{"tel"},
		ContextPromoted: true,
		Validated:       true,
	}
	var buf bytes.Buffer
	if err := JSON(&buf, fs, false, true, nil, false); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Findings []struct {
			Match  string              `json:"match"`
			Reason detect.DetectReason `json:"reason"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Findings[0].Match == phone {
		t.Fatalf("explain JSON should still mask match: %s", buf.String())
	}
	if got.Findings[0].Reason.BaseConfidence != "medium" || !got.Findings[0].Reason.ContextPromoted {
		t.Fatalf("reason missing: %s", buf.String())
	}
}

func TestGitHubEscapes(t *testing.T) {
	var buf bytes.Buffer
	fs := sample(testfixtures.MustGet(t, "report.phone_match"))
	fs[0].Description = "改行\nと%"
	GitHub(&buf, fs, false)
	out := buf.String()
	if !strings.HasPrefix(out, "::error file=users.csv,line=4,col=6,") {
		t.Errorf("unexpected prefix: %s", out)
	}
	if strings.Contains(out, "\n改行") || !strings.Contains(out, "%0A") || !strings.Contains(out, "%25") {
		t.Errorf("workflow command not escaped: %s", out)
	}
}

// file= プロパティの値はプロパティ区切りの "," ":" もエスケープされる。
func TestGitHubEscapesFileProperty(t *testing.T) {
	var buf bytes.Buffer
	fs := sample(testfixtures.MustGet(t, "report.phone_match"))
	fs[0].File = "a,b/c:d.csv"
	GitHub(&buf, fs, false)
	out := buf.String()
	if !strings.HasPrefix(out, "::error file=a%2Cb/c%3Ad.csv,line=4,") {
		t.Errorf("file property not escaped: %s", out)
	}
}

func TestSARIF(t *testing.T) {
	phone := testfixtures.MustGet(t, "report.phone_match")
	var buf bytes.Buffer
	if err := SARIF(&buf, sample(phone), rule.Builtin(), false); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v", doc["version"])
	}
	if strings.Contains(buf.String(), phone) {
		t.Error("SARIF output should be masked")
	}
}

type sarifDoc struct {
	Runs []struct {
		Results []struct {
			RuleID    string `json:"ruleId"`
			Locations []struct {
				PhysicalLocation struct {
					Region struct {
						StartLine   int `json:"startLine"`
						StartColumn int `json:"startColumn"`
						EndLine     int `json:"endLine"`
						EndColumn   int `json:"endColumn"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
		} `json:"results"`
	} `json:"runs"`
}

// TestSARIFRegionEndpoints は region に endLine/endColumn が付与され、
// SARIF 仕様どおり endColumn がマッチ終端の次カラム（排他境界）になることを、
// ASCII とマルチバイト（ルーン数 != バイト数）の双方で確認する。
// フィクスチャ不要（実在しうる PII 形式を含まない合成データのため）。
func TestSARIFRegionEndpoints(t *testing.T) {
	findings := []detect.Finding{
		{RuleID: "test-rule", Description: "test", File: "a.txt", Line: 3, Column: 5, Match: "ABCDE", Confidence: rule.High},
		// マルチバイト: ルーン数(4) != バイト数のケース（jp-pii-detector:ignore 対象外の合成語）。
		{RuleID: "test-rule", Description: "test", File: "a.txt", Line: 7, Column: 2, Match: "検出値ノ", Confidence: rule.High},
	}
	var buf bytes.Buffer
	if err := SARIF(&buf, findings, nil, true); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, buf.String())
	}
	results := doc.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	r0 := results[0].Locations[0].PhysicalLocation.Region
	if r0.StartLine != 3 || r0.StartColumn != 5 || r0.EndLine != 3 || r0.EndColumn != 10 {
		t.Errorf("ASCII region = %+v, want start=3:5 end=3:10 (5 runes)", r0)
	}
	r1 := results[1].Locations[0].PhysicalLocation.Region
	if r1.StartLine != 7 || r1.StartColumn != 2 || r1.EndLine != 7 || r1.EndColumn != 6 {
		t.Errorf("multi-byte region = %+v, want start=7:2 end=7:6 (4 runes)", r1)
	}
}

// TestSARIFPartialFingerprints は partialFingerprints が付与され、生の Match 値や
// 行・カラムを使わずにルール ID・ファイル・ファイル内出現順で安定することを確認する。
func TestSARIFPartialFingerprints(t *testing.T) {
	base := detect.Finding{RuleID: "test-rule", Description: "test", File: "a.txt", Line: 3, Column: 1, Match: "ABCDE", Confidence: rule.High}
	sameLocationDifferentValue := base
	sameLocationDifferentValue.Match = "VWXYZ"

	var buf1, buf2 bytes.Buffer
	if err := SARIF(&buf1, []detect.Finding{base}, nil, true); err != nil {
		t.Fatal(err)
	}
	if err := SARIF(&buf2, []detect.Finding{sameLocationDifferentValue}, nil, true); err != nil {
		t.Fatal(err)
	}
	var doc1, doc2 sarifDoc
	if err := json.Unmarshal(buf1.Bytes(), &doc1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(buf2.Bytes(), &doc2); err != nil {
		t.Fatal(err)
	}
	fp1 := doc1.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]
	fp2 := doc2.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]
	if fp1 == "" {
		t.Fatal("partialFingerprints が空")
	}
	if fp1 != fp2 {
		t.Errorf("検出値だけが変わってもフィンガープリントは同じであるべき: %s != %s", fp1, fp2)
	}

	// 周辺行の増減で位置だけが変わっても同じフィンガープリントになる。
	moved := base
	moved.Line += 10
	moved.Column += 3
	var movedBuf bytes.Buffer
	if err := SARIF(&movedBuf, []detect.Finding{moved}, nil, true); err != nil {
		t.Fatal(err)
	}
	var movedDoc sarifDoc
	if err := json.Unmarshal(movedBuf.Bytes(), &movedDoc); err != nil {
		t.Fatal(err)
	}
	fpMoved := movedDoc.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]
	if fpMoved != fp1 {
		t.Errorf("位置だけが変わってもフィンガープリントは同じであるべき: %s != %s", fpMoved, fp1)
	}

	// 同一ルール・同一ファイルの別出現は、位置に依存しない出現順で区別する。
	secondOccurrence := sameLocationDifferentValue
	secondOccurrence.Line = 20
	secondOccurrence.Column = 4
	dup := []detect.Finding{base, secondOccurrence}
	var dupBuf bytes.Buffer
	if err := SARIF(&dupBuf, dup, nil, true); err != nil {
		t.Fatal(err)
	}
	var dupDoc sarifDoc
	if err := json.Unmarshal(dupBuf.Bytes(), &dupDoc); err != nil {
		t.Fatal(err)
	}
	fpA := dupDoc.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]
	fpB := dupDoc.Runs[0].Results[1].PartialFingerprints["primaryLocationLineHash"]
	if fpA == fpB {
		t.Errorf("同一ファイルの別出現は異なるフィンガープリントになるべき: %s == %s", fpA, fpB)
	}
	if fpA != fp1 {
		t.Errorf("ファイル内 1 件目のフィンガープリントは単独時と一致するべき: %s != %s", fpA, fp1)
	}
}

// TestGitHubLevelByConfidence は信頼度で workflow command が
// error（high）/warning（medium）/notice（low）に分かれることを確認する。
// 以前は信頼度に関わらず常に ::error だったため、min_confidence を下げて
// 可視化した medium/low 検出まで一律「エラー」表示になっていた。
// フィクスチャ不要（実在しうる PII 形式を含まない合成データのため）。
func TestGitHubLevelByConfidence(t *testing.T) {
	tests := []struct {
		conf rule.Confidence
		want string
	}{
		{rule.High, "::error "},
		{rule.Medium, "::warning "},
		{rule.Low, "::notice "},
	}
	for _, tt := range tests {
		f := detect.Finding{RuleID: "test-rule", Description: "test", File: "a.txt", Line: 1, Column: 1, Match: "ABCDE", Confidence: tt.conf}
		var buf bytes.Buffer
		GitHub(&buf, []detect.Finding{f}, true)
		if !strings.HasPrefix(buf.String(), tt.want) {
			t.Errorf("confidence=%s: out = %q, want prefix %q", tt.conf, buf.String(), tt.want)
		}
	}
}

// --- --explain-dropped 相当（dropped/droppedTruncated 引数）の出力テスト ---
// issue #43 段階4。DroppedCandidate は生の検出値を持たないため、フィクスチャは
// 不要（実在しうる PII 形式を含まない合成データのみ使う）。

func sampleDropped() []detect.DroppedCandidate {
	return []detect.DroppedCandidate{
		{RuleID: "jp-bank-account", File: "users.csv", Line: 7, Column: 3,
			Reason: "require-context-missing", PatternBase: rule.Medium},
	}
}

// TestTextDroppedSection は dropped 非空のとき、通常の findings 出力の後に
// 棄却候補セクションが追加されること、dropped が nil（既定・未指定相当）なら
// 追加が一切無い（出力が 4 引数時代と完全に同一）ことを確認する。
func TestTextDroppedSection(t *testing.T) {
	findings := sample("dummy-value-1")

	var withDropped bytes.Buffer
	Text(&withDropped, findings, false, false, sampleDropped(), false)
	out := withDropped.String()
	if !strings.Contains(out, "棄却候補") {
		t.Fatalf("--explain-dropped 相当の text 出力に棄却候補セクションが無い: %s", out)
	}
	if !strings.Contains(out, "jp-bank-account") || !strings.Contains(out, "require-context-missing") {
		t.Errorf("棄却候補の内容が出力に無い: %s", out)
	}

	var withoutDropped bytes.Buffer
	Text(&withoutDropped, findings, false, false, nil, false)
	if strings.Contains(withoutDropped.String(), "棄却候補") {
		t.Errorf("dropped 未指定では棄却候補セクションを出すべきではない: %s", withoutDropped.String())
	}
	var legacyEquivalent bytes.Buffer
	Text(&legacyEquivalent, findings, false, false, nil, false)
	if legacyEquivalent.String() != withoutDropped.String() {
		t.Errorf("dropped=nil の出力が不安定: %q != %q", legacyEquivalent.String(), withoutDropped.String())
	}
}

// TestTextDroppedTruncatedNote は droppedTruncated=true のとき、上限到達を
// 示す注記が出力されることを確認する。
func TestTextDroppedTruncatedNote(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, nil, false, false, sampleDropped(), true)
	if !strings.Contains(buf.String(), "上限") {
		t.Errorf("droppedTruncated=true のとき打ち切りの注記が無い: %s", buf.String())
	}
}

// TestJSONDroppedField は dropped 非空のとき JSON 出力に
// rule_id/file/line/column/reason/base_confidence を持つ dropped 配列が
// 追加されること、dropped=nil（既定・未指定相当）では "dropped" キー自体が
// 出力に現れない（出力スキーマが 6 引数化前と完全に不変）ことを確認する。
func TestJSONDroppedField(t *testing.T) {
	findings := sample("dummy-value-1")

	var withDropped bytes.Buffer
	if err := JSON(&withDropped, findings, true, false, sampleDropped(), false); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Dropped []struct {
			RuleID         string `json:"rule_id"`
			File           string `json:"file"`
			Line           int    `json:"line"`
			Column         int    `json:"column"`
			Reason         string `json:"reason"`
			BaseConfidence string `json:"base_confidence"`
		} `json:"dropped"`
		DroppedTruncated bool `json:"dropped_truncated"`
	}
	if err := json.Unmarshal(withDropped.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Dropped) != 1 {
		t.Fatalf("dropped の件数 = %d, want 1: %s", len(got.Dropped), withDropped.String())
	}
	d := got.Dropped[0]
	if d.RuleID != "jp-bank-account" || d.File != "users.csv" || d.Line != 7 || d.Column != 3 ||
		d.Reason != "require-context-missing" || d.BaseConfidence != "medium" {
		t.Errorf("dropped[0] = %+v, 期待値と不一致", d)
	}
	if got.DroppedTruncated {
		t.Error("droppedTruncated=false のはずが true になっている")
	}

	var withoutDropped bytes.Buffer
	if err := JSON(&withoutDropped, findings, true, false, nil, false); err != nil {
		t.Fatal(err)
	}
	out := withoutDropped.String()
	if strings.Contains(out, `"dropped"`) {
		t.Errorf("dropped=nil なのに \"dropped\" キーが出力に現れている: %s", out)
	}
	if strings.Contains(out, `"dropped_truncated"`) {
		t.Errorf("droppedTruncated=false なのに \"dropped_truncated\" キーが出力に現れている: %s", out)
	}
}

// TestJSONDroppedTruncated は droppedTruncated=true のとき
// "dropped_truncated": true が出力されることを確認する。
func TestJSONDroppedTruncated(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, nil, true, false, sampleDropped(), true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"dropped_truncated": true`) {
		t.Errorf("droppedTruncated=true が出力に反映されていない: %s", buf.String())
	}
}

// TestJSONDroppedNoRawValue は dropped 配列の各要素が
// rule_id/file/line/column/reason/base_confidence のみを持ち、生の検出値
// （match 相当のフィールド）が一切含まれないことを確認する
// （DroppedCandidate 自体が生値を持たない安全境界の出力層での再確認）。
func TestJSONDroppedNoRawValue(t *testing.T) {
	dropped := []detect.DroppedCandidate{
		{RuleID: "jp-my-number", File: "f.go", Line: 1, Column: 1, Reason: "validate-failed", PatternBase: rule.Medium},
	}
	var buf bytes.Buffer
	if err := JSON(&buf, nil, true, false, dropped, false); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	entries, ok := doc["dropped"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("dropped 配列が想定形式でない: %s", buf.String())
	}
	entry, ok := entries[0].(map[string]any)
	if !ok {
		t.Fatalf("dropped[0] が object でない: %s", buf.String())
	}
	wantKeys := map[string]bool{"rule_id": true, "file": true, "line": true, "column": true, "reason": true, "base_confidence": true}
	for k := range entry {
		if !wantKeys[k] {
			t.Errorf("dropped[0] に想定外のキー %q がある（生値混入の疑い）: %s", k, buf.String())
		}
	}
	if len(entry) != len(wantKeys) {
		t.Errorf("dropped[0] のキー数 = %d, want %d: %+v", len(entry), len(wantKeys), entry)
	}
}
