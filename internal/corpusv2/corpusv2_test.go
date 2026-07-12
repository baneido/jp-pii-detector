package corpusv2

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/checksum"
	"github.com/baneido/jp-pii-detector/internal/evalcase"
)

func TestBuildMeetsV2CoverageContract(t *testing.T) {
	base := []evalcase.Case{{
		ID: "legacy-negative-1", SourceClass: "legacy-curated", Line: "識別情報を含まない行",
	}}
	got, summary, err := Build(base)
	if err != nil {
		t.Fatal(err)
	}
	if summary.SpanlessPairs != 0 || summary.AddedNegatives < 40 {
		t.Fatalf("unexpected quality summary: %+v", summary)
	}
	for _, id := range allRuleIDs() {
		if n := summary.PerRulePositive[id]; n < MinPositiveCasesPerRule {
			t.Errorf("%s positive cases = %d, want >= %d", id, n, MinPositiveCasesPerRule)
		}
	}

	var content, diff, csv, sql, json bool
	for _, c := range got {
		content = content || c.Content != ""
		diff = diff || len(c.Diff) > 0
		csv = csv || strings.HasSuffix(c.File, ".csv")
		sql = sql || strings.HasSuffix(c.File, ".sql")
		json = json || strings.HasSuffix(c.File, ".json")
	}
	if !content || !diff || !csv || !sql || !json {
		t.Fatalf("input coverage: content=%t diff=%t csv=%t sql=%t json=%t", content, diff, csv, sql, json)
	}
	if !reflect.DeepEqual(base, []evalcase.Case{{
		ID: "legacy-negative-1", SourceClass: "legacy-curated", Line: "識別情報を含まない行",
	}}) {
		t.Fatal("Build mutated its input")
	}
}

func TestUpgradePublishedV2AddsEAIAndConfusableCoverageIdempotently(t *testing.T) {
	complete, _, err := Build([]evalcase.Case{{
		ID: "legacy-negative-1", SourceClass: "legacy-curated", Line: "識別情報を含まない行",
	}})
	if err != nil {
		t.Fatal(err)
	}
	var base []evalcase.Case
	hardNegatives := 0
	for _, c := range complete {
		if c.SourceClass == "hard-negative" {
			hardNegatives++
		}
		remove := false
		for _, id := range c.Want {
			remove = remove || id == "email-address-eai" || id == "email-address-confusable"
		}
		if !remove {
			base = append(base, c)
		}
	}
	got, err := UpgradePublishedV2(base)
	if err != nil {
		t.Fatal(err)
	}
	counts := positiveCounts(got)
	if counts["email-address-eai"] != MinPositiveCasesPerRule ||
		counts["email-address-confusable"] != MinPositiveCasesPerRule ||
		len(got) != len(base)+2*MinPositiveCasesPerRule {
		t.Fatalf("missing coverage was not supplemented: counts=%v len=%d base=%d", counts, len(got), len(base))
	}
	gotHardNegatives := 0
	for _, c := range got {
		if c.SourceClass == "hard-negative" {
			gotHardNegatives++
		}
	}
	if gotHardNegatives != hardNegatives {
		t.Fatalf("hard negatives = %d, want unchanged %d", gotHardNegatives, hardNegatives)
	}
	again, err := UpgradePublishedV2(got)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, got) {
		t.Fatal("UpgradePublishedV2 must be idempotent after filling missing coverage")
	}
}

func TestHardNegativePANsAreTheExplicitKnownTestSet(t *testing.T) {
	seen := map[string]bool{}
	for _, pan := range wellKnownTestPANs() {
		if seen[pan] || !checksum.Luhn(pan) || !checksum.KnownTestPAN(pan) || checksum.CreditCard(pan) {
			t.Fatalf("公知テストPAN集合に重複または構造不正な値がある")
		}
		seen[pan] = true
	}
	if len(seen) != 5 {
		t.Fatalf("known test PAN count = %d, want 5", len(seen))
	}
}

func TestUpgradePublishedV2ReclassifiesKnownTestPANAndRefillsCoverage(t *testing.T) {
	pan := strings.Join([]string{"4242", "4242", "4242", "4242"}, "")
	prefix := "カード番号: "
	base := []evalcase.Case{{
		ID: "legacy-test-pan", SourceClass: "legacy-curated", Line: prefix + pan,
		Want: []string{"credit-card"},
		Spans: []evalcase.Span{{
			RuleID: "credit-card", Line: 1,
			Start: utf8.RuneCountInString(prefix), End: utf8.RuneCountInString(prefix) + len(pan),
		}},
	}}
	wantInput := cloneCases(base)

	got, err := UpgradePublishedV2(base)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(base, wantInput) {
		t.Fatal("UpgradePublishedV2 が入力を変更した")
	}
	if len(got[0].Want) != 0 || len(got[0].Spans) != 0 || !hasTag(got[0].Tags, "polarity:negative") {
		t.Fatalf("公知テストPANが陰性へ再分類されていない: %+v", got[0])
	}
	if n := positiveCounts(got)["credit-card"]; n < MinPositiveCasesPerRule {
		t.Fatalf("credit-card positives = %d, want >= %d", n, MinPositiveCasesPerRule)
	}
	if len(got) <= len(base) {
		t.Fatal("不足した陽性カバレッジが補完されていない")
	}
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

// singleAddressCase は Want=[jp-address-high-recall] 単独・対応するSpan 1件を
// 持つ単純な Line ケースを組み立てるテスト用ヘルパー。addr は line 内に含まれる
// 住所値そのもの（ラベル・区切りを含まない部分文字列）。
func singleAddressCase(t *testing.T, id, line, addr string) evalcase.Case {
	t.Helper()
	return evalcase.Case{
		ID: id, SourceClass: "legacy-curated", Line: line,
		Want:  []string{"jp-address-high-recall"},
		Spans: []evalcase.Span{addressSpanFor(t, line, "jp-address-high-recall", addr)},
	}
}

// addressSpanFor は line 内で addr が最初に現れる位置から ruleID 用の Span を
// 組み立てる（ルーン位置は evalcase.Span の契約どおり0始まり半開区間）。
func addressSpanFor(t *testing.T, line, ruleID, addr string) evalcase.Span {
	t.Helper()
	start := strings.Index(line, addr)
	if start < 0 {
		t.Fatalf("%q に %q が見つかりません", line, addr)
	}
	runeStart := utf8.RuneCountInString(line[:start])
	return evalcase.Span{
		RuleID: ruleID, Line: 1,
		Start: runeStart, End: runeStart + utf8.RuneCountInString(addr),
	}
}

// TestUpgradePublishedV2ReassignsLabeledNoPrefectureAddressWant は
// reassignLabeledNoPrefectureAddressWant（PR #148 の jp-address 第3エントリ追加に
// 伴うWant帰属の読み替え）の述語を固定する。判定ロジック自体は
// rule.MatchesLabeledNoPrefectureAddress に委譲しているため、ここでは
// 「どのケース形が書き換え対象になるか」という述語の境界だけを確認する
// （正規表現・辞書照合そのものの詳細は internal/rule 側のテストが持つ）。
func TestUpgradePublishedV2ReassignsLabeledNoPrefectureAddressWant(t *testing.T) {
	tests := []struct {
		name        string
		c           evalcase.Case
		wantRewrite bool
	}{
		{
			name:        "ラベル付き都道府県なし住所は jp-address へ書き換わる",
			c:           singleAddressCase(t, "native-1", "住所: 渋谷区神南1-2-3", "渋谷区神南1-2-3"), // jp-pii-detector:ignore
			wantRewrite: true,
		},
		{
			name:        "第3エントリの語彙にないラベル(勤務地)は書き換わらない",
			c:           singleAddressCase(t, "native-2", "勤務地: 渋谷区神南1-2-3", "渋谷区神南1-2-3"),
			wantRewrite: false,
		},
		{
			name:        "ラベルなし形は書き換わらない",
			c:           singleAddressCase(t, "native-3", "渋谷区神南1-2-3", "渋谷区神南1-2-3"),
			wantRewrite: false,
		},
		{
			name:        "全角コロンでも normalize.Line 経由で書き換わる",
			c:           singleAddressCase(t, "native-4", "住所：渋谷区神南1-2-3", "渋谷区神南1-2-3"), // jp-pii-detector:ignore
			wantRewrite: true,
		},
		{
			name:        "実在しない市区町村ラベル付きは辞書ゲートで書き換わらない",
			c:           singleAddressCase(t, "native-5", "住所: 通学区1-2-3", "通学区1-2-3"),
			wantRewrite: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := []evalcase.Case{tt.c}
			wantInput := cloneCases(base)

			got, err := UpgradePublishedV2(base)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(base, wantInput) {
				t.Fatal("UpgradePublishedV2 が入力を変更した")
			}

			gotCase := got[0]
			if tt.wantRewrite {
				if !reflect.DeepEqual(gotCase.Want, []string{"jp-address"}) {
					t.Fatalf("Want = %v, want [jp-address]", gotCase.Want)
				}
				if len(gotCase.Spans) != 1 || gotCase.Spans[0].RuleID != "jp-address" {
					t.Fatalf("Spans = %+v, want single jp-address span", gotCase.Spans)
				}
				if gotCase.Spans[0].Start != tt.c.Spans[0].Start || gotCase.Spans[0].End != tt.c.Spans[0].End {
					t.Fatalf("span位置が変わった: got %+v, original %+v", gotCase.Spans[0], tt.c.Spans[0])
				}
			} else {
				if !reflect.DeepEqual(gotCase.Want, tt.c.Want) {
					t.Fatalf("Want が書き換わってしまった: got %v, want %v", gotCase.Want, tt.c.Want)
				}
				if !reflect.DeepEqual(gotCase.Spans, tt.c.Spans) {
					t.Fatalf("Spans が書き換わってしまった: got %+v, want %+v", gotCase.Spans, tt.c.Spans)
				}
			}
		})
	}
}

// TestUpgradePublishedV2DoesNotReassignMultiWantCase は、Want が複数ルールに
// またがるケース（他ルールの帰属まで巻き添えで変えないための安全側ガード）が
// 書き換え対象にならないことを、2 span を持つケースで個別に確認する。
func TestUpgradePublishedV2DoesNotReassignMultiWantCase(t *testing.T) {
	line := "住所: 渋谷区神南1-2-3 山田太郎" // jp-pii-detector:ignore
	c := evalcase.Case{
		ID: "native-multi-want", SourceClass: "legacy-curated", Line: line,
		Want: []string{"jp-address-high-recall", "person-name"},
		Spans: []evalcase.Span{
			addressSpanFor(t, line, "jp-address-high-recall", "渋谷区神南1-2-3"),
			addressSpanFor(t, line, "person-name", "山田太郎"),
		},
	}
	base := []evalcase.Case{c}
	wantInput := cloneCases(base)

	got, err := UpgradePublishedV2(base)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(base, wantInput) {
		t.Fatal("UpgradePublishedV2 が入力を変更した")
	}
	if !reflect.DeepEqual(got[0].Want, c.Want) || !reflect.DeepEqual(got[0].Spans, c.Spans) {
		t.Fatalf("Want が複数あるケースが書き換わってしまった: Want=%v Spans=%+v", got[0].Want, got[0].Spans)
	}
}

// TestUpgradePublishedV2RefillsJPAddressHighRecallAfterReassignment は、
// jp-address-high-recall のnative陽性が全件jp-addressへ読み替えられて10件を
// 下回っても、fillPositiveCoverageによる既存の合成補完（ラベルなし形。
// positiveCandidatesの"jp-address-high-recall"節参照）が自動的に10件まで
// 埋め戻すことを確認する。TestBuildMeetsV2CoverageContract等の既存カバレッジ
// 契約を壊さないことの直接確認でもある。
func TestUpgradePublishedV2RefillsJPAddressHighRecallAfterReassignment(t *testing.T) {
	var base []evalcase.Case
	for i := 0; i < MinPositiveCasesPerRule; i++ {
		addr := fmt.Sprintf("渋谷区神南%d-%d-%d", i+1, i+2, i+3)
		line := "住所: " + addr
		base = append(base, singleAddressCase(t, fmt.Sprintf("native-labeled-%02d", i+1), line, addr))
	}

	got, err := UpgradePublishedV2(base)
	if err != nil {
		t.Fatal(err)
	}

	for i, c := range got[:len(base)] {
		if !reflect.DeepEqual(c.Want, []string{"jp-address"}) {
			t.Fatalf("case %d: Want = %v, want [jp-address]", i, c.Want)
		}
		if len(c.Spans) != 1 || c.Spans[0].RuleID != "jp-address" {
			t.Fatalf("case %d: Spans = %+v, want single jp-address span", i, c.Spans)
		}
	}

	counts := positiveCounts(got)
	if counts["jp-address-high-recall"] != MinPositiveCasesPerRule {
		t.Fatalf("jp-address-high-recall positives = %d, want %d (fillPositiveCoverageによる埋め戻し)",
			counts["jp-address-high-recall"], MinPositiveCasesPerRule)
	}
	if counts["jp-address"] < MinPositiveCasesPerRule {
		t.Fatalf("jp-address positives = %d, want >= %d", counts["jp-address"], MinPositiveCasesPerRule)
	}

	// 埋め戻されたjp-address-high-recallの合成陽性は、新第3エントリと衝突しない
	// ラベルなし形であること（帰属衝突が再発しないことの確認）。
	for _, c := range got {
		wantsHighRecall := false
		for _, id := range c.Want {
			if id == "jp-address-high-recall" {
				wantsHighRecall = true
			}
		}
		if wantsHighRecall && strings.Contains(c.Line, "住所") {
			t.Fatalf("補完されたjp-address-high-recallケースがラベル付きになっている: %+v", c)
		}
	}
}

func TestGeneratedDigitsDependDeterministicallyOnPrivateBase(t *testing.T) {
	a := []evalcase.Case{{ID: "a", Line: "private-base-a"}}
	b := []evalcase.Case{{ID: "b", Line: "private-base-b"}}
	seedA := corpusSeed(a)
	if seedA != corpusSeed(a) {
		t.Fatal("same private base produced a different seed")
	}
	if seedA == corpusSeed(b) {
		t.Fatal("different private bases produced the same test seed")
	}
	if digitRun(seedA, 20) == digitRun(corpusSeed(b), 20) {
		t.Fatal("generated digits do not depend on the private base")
	}
}
