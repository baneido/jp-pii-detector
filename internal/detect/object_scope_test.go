package detect

import (
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/rule"
	"github.com/baneido/jp-pii-detector/internal/testfixtures"
)

// --- YAML: 親キー（object_scope.go の yamlObjectScope）---

// phone: 配下の home: 0466221111 が電話文脈で昇格する、その下地となる
// 親キーマージ（PositiveText への追記）を低レベルで確認する。
func TestYAMLObjectScopeMergesParentIntoPositiveText(t *testing.T) {
	ctxs := sourceLineContexts("config.yaml", []string{
		"phone:",
		"  home: 0466221111",
	})
	// line2 は自己文脈（home、extractLineStatements 由来）に加え、
	// addCrossLineSourceContexts（既存の「key:\n value」隣接行機構、
	// 本 PR の対象外）由来のもう 1 つの statement を持ちうる。value の実際の
	// 位置に対する statementFor の解決は先に追加された自己文脈側
	// （index 0、値をタイトに包む方）を返すため、そちらだけを検証する。
	if len(ctxs) != 2 || len(ctxs[1].Statements) == 0 {
		t.Fatalf("contexts = %#v, want line2 に 1 個以上の statement", ctxs)
	}
	stmt := ctxs[1].Statements[0]
	if !strings.Contains(stmt.PositiveText, "phone") {
		t.Errorf("PositiveText = %q, want to contain %q（親キー）", stmt.PositiveText, "phone")
	}
	if !strings.Contains(stmt.PositiveText, "home") {
		t.Errorf("PositiveText = %q, want to contain %q（自己文脈も保持）", stmt.PositiveText, "home")
	}
}

// order: 配下の id: 1234567 の NegativeText に親キー "order" が追記される
// ことを確認する（口座番号として出ないことは統合テストで確認する）。
func TestYAMLObjectScopeMergesParentIntoNegativeText(t *testing.T) {
	ctxs := sourceLineContexts("config.yaml", []string{
		"order:",
		"  id: 1234567",
	})
	// TestYAMLObjectScopeMergesParentIntoPositiveText と同じ理由で、
	// 自己文脈側（index 0）だけを検証する。
	if len(ctxs) != 2 || len(ctxs[1].Statements) == 0 {
		t.Fatalf("contexts = %#v, want line2 に 1 個以上の statement", ctxs)
	}
	stmt := ctxs[1].Statements[0]
	if !strings.Contains(stmt.NegativeText, "order") {
		t.Errorf("NegativeText = %q, want to contain %q（親キー）", stmt.NegativeText, "order")
	}
	if !strings.Contains(stmt.NegativeText, "id") {
		t.Errorf("NegativeText = %q, want to contain %q（自己文脈も保持）", stmt.NegativeText, "id")
	}
}

// フロー形式（`key: {`）が複数物理行にまたがる場合、内部の行には親を付けない
// （誤帰属なし）。
func TestYAMLObjectScopeFlowStyleSkipsParent(t *testing.T) {
	ctxs := sourceLineContexts("config.yaml", []string{
		"phone: {",
		"  home: 0466221111",
		"}",
	})
	if len(ctxs) != 3 || len(ctxs[1].Statements) != 1 {
		t.Fatalf("contexts = %#v, want line2 に 1 statement", ctxs)
	}
	if got := ctxs[1].Statements[0].PositiveText; strings.Contains(got, "phone") {
		t.Errorf("PositiveText = %q, フロー形式の継続行に親を付けない想定", got)
	}
}

// 単一行で閉じるフロー形式（`key: {a: 1}`）は複数行継続とみなさない
// （yamlFlowDepthDelta の delta が 0 になり従来どおり同一行の key=value 抽出に
// 委ねる）ことを、次の行への誤伝播が無いことで確認する。
func TestYAMLObjectScopeSingleLineFlowDoesNotLeakToNextLine(t *testing.T) {
	ctxs := sourceLineContexts("config.yaml", []string{
		"phone: {home: 1}",
		"id: 1234567",
	})
	if len(ctxs) != 2 || len(ctxs[1].Statements) != 1 {
		t.Fatalf("contexts = %#v, want line2 に 1 statement", ctxs)
	}
	if got := ctxs[1].Statements[0].PositiveText; strings.Contains(got, "phone") {
		t.Errorf("PositiveText = %q, 単一行フローの次の行に親が漏れてはいけない", got)
	}
}

// 配列項目（`- `）は保守的にスキップし、親を付けない（値自体は自己文脈
// （home）は従来どおり保持する）。
func TestYAMLObjectScopeArrayItemSkipsParent(t *testing.T) {
	ctxs := sourceLineContexts("config.yaml", []string{
		"phone:",
		"  - home: 0466221111",
	})
	// TestYAMLObjectScopeMergesParentIntoPositiveText と同じ理由で、
	// 自己文脈側（index 0）だけを検証する。
	if len(ctxs) != 2 || len(ctxs[1].Statements) == 0 {
		t.Fatalf("contexts = %#v, want line2 に 1 個以上の statement", ctxs)
	}
	stmt := ctxs[1].Statements[0]
	if strings.Contains(stmt.PositiveText, "phone") {
		t.Errorf("PositiveText = %q, 配列項目に親を付けない想定", stmt.PositiveText)
	}
	if !strings.Contains(stmt.PositiveText, "home") {
		t.Errorf("PositiveText = %q, 自己文脈（home）は保持される想定", stmt.PositiveText)
	}
}

// 複数行ブロックスカラー（`key: |`）の本文は不透明なテキストとして扱い、
// 親を付けない。
func TestYAMLObjectScopeBlockScalarSkipsParent(t *testing.T) {
	ctxs := sourceLineContexts("config.yaml", []string{
		"phone: |",
		"  home: 0466221111",
		"memo: done",
	})
	if len(ctxs) != 3 {
		t.Fatalf("contexts len = %d, want 3", len(ctxs))
	}
	for _, st := range ctxs[1].Statements {
		if strings.Contains(st.PositiveText, "phone") {
			t.Errorf("PositiveText = %q, ブロックスカラー本文に親を付けない想定", st.PositiveText)
		}
	}
	// ブロックスカラーの外に戻った行（memo）は通常どおり処理される
	// （親が無いこと自体は自然。ここではクラッシュ・巻き込みが無いことを見る）。
	if len(ctxs[2].Statements) != 1 || ctxs[2].Statements[0].PositiveText != "memo" {
		t.Errorf("line3 statements = %#v, want memo self-context", ctxs[2].Statements)
	}
}

// 祖父母チェーンは付けない（親は 1 段のみ）。孫キーの親は直近の親（中間キー）
// であり、祖父母キーの文脈は含まれない。
func TestYAMLObjectScopeOnlyOneParentLevel(t *testing.T) {
	ctxs := sourceLineContexts("config.yaml", []string{
		"customer:",
		"  phone:",
		"    home: 0466221111",
	})
	// TestYAMLObjectScopeMergesParentIntoPositiveText と同じ理由で、
	// 自己文脈側（index 0）だけを検証する。
	if len(ctxs) != 3 || len(ctxs[2].Statements) == 0 {
		t.Fatalf("contexts = %#v, want line3 に 1 個以上の statement", ctxs)
	}
	got := ctxs[2].Statements[0].PositiveText
	if !strings.Contains(got, "phone") {
		t.Errorf("PositiveText = %q, want to contain %q（直近の親）", got, "phone")
	}
	if strings.Contains(got, "customer") {
		t.Errorf("PositiveText = %q, 祖父母キー（customer）は含まれない想定", got)
	}
}

// --- YAML: RecordID ---

// トップレベルキー（インデント 0 の value-less な key:）ごとに異なる
// RecordID が割り当てられる。
func TestYAMLObjectScopeRecordIDsPerTopLevelKey(t *testing.T) {
	_, recordIDs := yamlObjectScope([]string{
		"customer1:",
		"  phone: 090-1234-5678", // jp-pii-detector:ignore
		"customer2:",
		"  name: 架空太郎",
	})
	r1, r2 := recordIDs[1], recordIDs[3]
	if r1 == 0 || r2 == 0 {
		t.Fatalf("recordIDs = %v, want both non-zero", recordIDs)
	}
	if r1 == r2 {
		t.Fatalf("recordIDs = %v, want distinct records for distinct top-level keys", recordIDs)
	}
}

// フラットな単一レコード（トップレベルキーが全て葉ノード）は、各キーごとに
// 分断されず RecordID=0（レコード情報なし。従来の ±5 行窓へフォールバック）の
// ままであることを確認する（分断すると同一実体内の共起すら検出できなくなる
// ため、意図的にレコード境界にしない設計）。
func TestYAMLObjectScopeFlatTopLevelHasNoRecord(t *testing.T) {
	_, recordIDs := yamlObjectScope([]string{
		"id: 123",
		"name: 架空太郎",
		"phone: 090-1234-5678", // jp-pii-detector:ignore
	})
	for i, rid := range recordIDs {
		if rid != 0 {
			t.Errorf("line %d recordID = %d, want 0（フラットな単一レコードは非分断）", i+1, rid)
		}
	}
}

// --- JSON: 親キー（object_scope.go の jsonObjectScope）---

// ネストしたオブジェクトの親キーが直近 1 段だけ子に伝播する。
func TestJSONObjectScopeNestedParentKey(t *testing.T) {
	parents, _ := jsonObjectScope([]string{
		`{`,
		`  "phone": {`,
		`    "home": "0466221111"`,
		`  }`,
		`}`,
	})
	if parents[2] != "phone" {
		t.Fatalf("parents[2] = %q, want %q", parents[2], "phone")
	}
}

// 文字列リテラル内の '{'/'}'/'['/']' は構造として解釈しない
// （深さ追跡が壊れない）。
func TestJSONObjectScopeBracesInsideStringIgnored(t *testing.T) {
	parents, recordIDs := jsonObjectScope([]string{
		`{`,
		`  "note": "a{b}c[d]e, x: y",`,
		`  "phone": {`,
		`    "home": "0466221111"`,
		`  }`,
		`}`,
	})
	if parents[3] != "phone" || recordIDs[3] == 0 {
		t.Fatalf("parents[3]=%q recordIDs[3]=%d, want phone/non-zero（文字列内の記号に惑わされない）", parents[3], recordIDs[3])
	}
}

// パース不能・不整合（対応しない余分な閉じ括弧）を検出した行以降は、
// 親キー・RecordID を一切付与しない（安全側）。
func TestJSONObjectScopeBrokenStopsAssignment(t *testing.T) {
	lines := []string{
		`{`,
		`  "phone": {`,
		`    "home": "0466221111"`,
		`  }`,
		`}`,
		`}`, // 対応する開き括弧が無い余分な閉じ括弧（不整合）
		`  "trailing": "1234567"`,
	}
	parents, recordIDs := jsonObjectScope(lines)
	if parents[2] != "phone" || recordIDs[2] == 0 {
		t.Fatalf("parents[2]=%q recordIDs[2]=%d, want phone/non-zero（不整合検出前は通常どおり）", parents[2], recordIDs[2])
	}
	for i := 5; i < len(lines); i++ {
		if parents[i] != "" || recordIDs[i] != 0 {
			t.Errorf("line %d: parent=%q recordID=%d, want empty/0（不整合検出後は付与しない）", i+1, parents[i], recordIDs[i])
		}
	}
}

// --- JSON: RecordID ---

// トップレベル配列直下の各オブジェクトが異なる RecordID を持つ。
func TestJSONObjectScopeRecordIDsPerArrayElement(t *testing.T) {
	_, recordIDs := jsonObjectScope([]string{
		`[`,
		`  {`,
		`    "phone": "090-1234-5678"`, // jp-pii-detector:ignore
		`  },`,
		`  {`,
		`    "name": "架空太郎"`,
		`  }`,
		`]`,
	})
	r1, r2 := recordIDs[2], recordIDs[5]
	if r1 == 0 || r2 == 0 {
		t.Fatalf("recordIDs = %v, want both non-zero", recordIDs)
	}
	if r1 == r2 {
		t.Fatalf("recordIDs = %v, want distinct records per array element", recordIDs)
	}
}

// トップレベルオブジェクト直下の各値オブジェクト（map-of-records 形）も、
// 配列と同様に異なる RecordID を持つ。
func TestJSONObjectScopeRecordIDsPerTopLevelValueObject(t *testing.T) {
	_, recordIDs := jsonObjectScope([]string{
		`{`,
		`  "customer1": {`,
		`    "phone": "090-1234-5678"`, // jp-pii-detector:ignore
		`  },`,
		`  "customer2": {`,
		`    "name": "架空太郎"`,
		`  }`,
		`}`,
	})
	r1, r2 := recordIDs[2], recordIDs[5]
	if r1 == 0 || r2 == 0 || r1 == r2 {
		t.Fatalf("recordIDs = %v, want distinct non-zero records", recordIDs)
	}
}

// --- sourceLineContexts への統合（lineContext.RecordID・拡張子ディスパッチ）---

func TestSourceLineContextsSetsRecordIDForYAML(t *testing.T) {
	ctxs := sourceLineContexts("config.yaml", []string{
		"customer1:",
		"  phone: 090-1234-5678", // jp-pii-detector:ignore
		"customer2:",
		"  name: 架空太郎",
	})
	if ctxs[1].RecordID == 0 || ctxs[3].RecordID == 0 || ctxs[1].RecordID == ctxs[3].RecordID {
		t.Fatalf("RecordID = (%d, %d), want distinct non-zero", ctxs[1].RecordID, ctxs[3].RecordID)
	}
}

func TestSourceLineContextsSetsRecordIDForJSON(t *testing.T) {
	ctxs := sourceLineContexts("data.json", []string{
		`[`,
		`  {`,
		`    "phone": "090-1234-5678"`, // jp-pii-detector:ignore
		`  },`,
		`  {`,
		`    "name": "架空太郎"`,
		`  }`,
		`]`,
	})
	if ctxs[2].RecordID == 0 || ctxs[5].RecordID == 0 || ctxs[2].RecordID == ctxs[5].RecordID {
		t.Fatalf("RecordID = (%d, %d), want distinct non-zero", ctxs[2].RecordID, ctxs[5].RecordID)
	}
}

// .go 等（object_scope の対象外拡張子）では RecordID が常に 0 のままで、
// 親キーのマージも起きない（.jsonc も対象外に含める — JSON5 風コメントは
// 未対応のため）。
func TestSourceLineContextsNoObjectScopeForOtherExtensions(t *testing.T) {
	for _, file := range []string{"service.go", "data.jsonc"} {
		ctxs := sourceLineContexts(file, []string{
			"phone:",
			`  "home": "0466221111",`,
		})
		for i, c := range ctxs {
			if c.RecordID != 0 {
				t.Errorf("%s line %d: RecordID = %d, want 0（object_scope 対象外）", file, i+1, c.RecordID)
			}
		}
	}
}

// --- 統合（ScanContent）: 親キーによる昇格・抑制 ---

// phone: 配下の home: <固定電話・区切りなし> は、単独では RequireContext
// （コンテキストキーワード必須）を満たさず検出されないが、親キー "phone" が
// マージされることで検出できるようになる。
func TestScanContentYAMLParentKeyPromotesPhoneDetection(t *testing.T) {
	d := newDetector(t, "")
	fixedNoSep := strings.ReplaceAll(testfixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")

	withoutParent := "home: " + fixedNoSep
	assertRules(t, d.ScanContent("config.yaml", withoutParent))

	withParent := "phone:\n  home: " + fixedNoSep
	assertRules(t, d.ScanContent("config.yaml", withParent), "jp-phone-number")
}

// JSON 版（ネストしたオブジェクト）でも同様に昇格する。
func TestScanContentJSONParentKeyPromotesPhoneDetection(t *testing.T) {
	d := newDetector(t, "")
	fixedNoSep := strings.ReplaceAll(testfixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")

	content := "{\n  \"phone\": {\n    \"home\": \"" + fixedNoSep + "\"\n  }\n}"
	assertRules(t, d.ScanContent("data.json", content), "jp-phone-number")
}

// order: 配下の id: 1234567 は口座番号として出ない（親キー "order" の
// NegativeText マージが既存の自己文脈（id）による抑制を壊さないことの
// 回帰確認）。
func TestScanContentYAMLOrderIDNotDetectedAsBankAccount(t *testing.T) {
	d := newDetector(t, "")
	content := "order:\n  id: 1234567"
	assertRules(t, d.ScanContent("config.yaml", content))
}

// --- 共起（cooccurrence_boost）: RecordID によるレコードスコープ ---
//
// detect_test.go は編集禁止のため、既存の P23 共起ブーストテスト（同ファイル）
// と同じ inline literal 方式（testfixtures を使わず、氏名は辞書未収録の
// 「架空太郎」、電話は区切りあり携帯 090-1234-5678 を高信頼アンカーに使う）を // jp-pii-detector:ignore
// このファイルに集約する。

// 同一オブジェクト（同一 RecordID）内の氏名候補は、高信頼アンカーとの距離が
// 従来の ±5 行窓を超えていても昇格する（RecordID が距離より強い構造的証拠に
// なる）。
func TestCooccurrenceBoostSameRecordPromotesBeyondWindow(t *testing.T) {
	d := newDetector(t, `
min_confidence = "medium"

[rules]
cooccurrence_boost = true
`)
	// phone と name の行差は 7（cooccurrenceWindowLines=5 の窓外）だが、
	// 両方とも customer1: の同一レコードに属する。
	content := "customer1:\n" +
		"  phone: 090-1234-5678\n" + // jp-pii-detector:ignore
		"  filler1: x\n" +
		"  filler2: x\n" +
		"  filler3: x\n" +
		"  filler4: x\n" +
		"  filler5: x\n" +
		"  filler6: x\n" +
		"  氏名: 架空太郎\n"
	fs := d.ScanContent("config.yaml", content)
	assertRules(t, fs, "jp-phone-number", "person-name")
	for _, f := range fs {
		if f.RuleID != "person-name" {
			continue
		}
		if f.Confidence != rule.Medium {
			t.Errorf("person-name confidence = %v, want %v（Low→Medium の昇格）", f.Confidence, rule.Medium)
		}
		if !f.Reason.CooccurrenceBoosted {
			t.Error("Reason.CooccurrenceBoosted = false, want true")
		}
	}
}

// 別オブジェクト（異なる RecordID）の氏名候補は、±5 行窓の内側であっても
// 昇格しない（RecordID が異なれば構造的に無関係と判断する）。
func TestCooccurrenceBoostDifferentRecordDoesNotPromoteWithinWindow(t *testing.T) {
	d := newDetector(t, `
min_confidence = "medium"

[rules]
cooccurrence_boost = true
`)
	// customer1（phone アンカー）と customer2（氏名候補）は行差 2 で
	// 従来の ±5 行窓の内側だが、別レコードのため昇格しない。
	content := "customer1:\n" +
		"  phone: 090-1234-5678\n" + // jp-pii-detector:ignore
		"customer2:\n" +
		"  氏名: 架空太郎\n"
	assertRules(t, d.ScanContent("config.yaml", content), "jp-phone-number")
}

// JSON 版（トップレベル配列の別要素）でも同様に、別オブジェクトへは
// 昇格しない。
func TestCooccurrenceBoostDifferentJSONRecordDoesNotPromote(t *testing.T) {
	d := newDetector(t, `
min_confidence = "medium"

[rules]
cooccurrence_boost = true
`)
	content := "[\n" +
		"  {\n" +
		"    \"phone\": \"090-1234-5678\"\n" + // jp-pii-detector:ignore
		"  },\n" +
		"  {\n" +
		"    \"氏名\": \"架空太郎\"\n" +
		"  }\n" +
		"]\n"
	assertRules(t, d.ScanContent("data.json", content), "jp-phone-number")
}

// 候補行・アンカー行のどちらか一方でも RecordID を持たない場合（ここでは
// 氏名候補がレコード構造の外側にある）は、従来どおり ±5 行窓へフォールバック
// して昇格する。
func TestCooccurrenceBoostFallsBackToWindowWhenEitherSideHasNoRecord(t *testing.T) {
	d := newDetector(t, `
min_confidence = "medium"

[rules]
cooccurrence_boost = true
`)
	// 氏名（トップレベルの葉ノード、RecordID=0）と customer1:（value-less な
	// トップレベルキー、電話は RecordID を持つ）が近接する。
	content := "氏名: 架空太郎\ncustomer1:\n  phone: 090-1234-5678\n" // jp-pii-detector:ignore
	fs := d.ScanContent("config.yaml", content)
	assertRules(t, fs, "jp-phone-number", "person-name")
	for _, f := range fs {
		if f.RuleID == "person-name" && !f.Reason.CooccurrenceBoosted {
			t.Error("Reason.CooccurrenceBoosted = false, want true（片側 RecordID 無しは窓へフォールバック）")
		}
	}
}

// RecordID を持たないプレーンテキスト（.txt。object_scope の対象外で常に
// RecordID=0）は、従来どおり ±5 行窓で共起判定する（既存挙動の非退行確認）。
func TestCooccurrenceBoostPlainTextUsesTraditionalWindow(t *testing.T) {
	tests := []struct {
		name  string
		gap   int
		boost bool
	}{
		{"ウィンドウ内（5行差）", 4, true},
		{"ウィンドウ外（6行差）", 5, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newDetector(t, `
min_confidence = "medium"

[rules]
cooccurrence_boost = true
`)
			content := "氏名: 架空太郎\n" + strings.Repeat("\n", tt.gap) + "電話: 090-1234-5678" // jp-pii-detector:ignore
			fs := d.ScanContent("f.txt", content)
			hasName := false
			for _, f := range fs {
				if f.RuleID == "person-name" {
					hasName = true
				}
			}
			if hasName != tt.boost {
				t.Errorf("person-name present = %v, want %v (findings=%v)", hasName, tt.boost, ruleIDs(fs))
			}
		})
	}
}
