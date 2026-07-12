package detect

import (
	"reflect"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/testfixtures"
)

// object_scope_diff_test.go は ScanDiffHunkOpts 経由のオブジェクトスコープ diff
// 対応（applyObjectScopeContextForDiff、internal/detect/object_scope.go、
// issue #134）のテスト。internal/source/gitdiff_test.go には、実 git リポジトリを
// 使った end-to-end（post-image の git show 取得を含む）テストがある。
//
// PII 形サンプルについて: このファイルは *_test.go のため、Base が Medium かつ
// RequireContext なパターン（jp-phone-number の区切りなし固定電話・
// jp-bank-account 等）は dogfooding のパス降格（path_profile.go、既定 ON）で
// Low に降格され、既定の min_confidence=medium では非表示になる（0466221111・
// 1234567 のような値に行末マーカーが無いのはそのため。object_scope_test.go と
// 同じ前提）。一方 jp-yucho-account の別行ペア検出は Base が常に High
// （path_profile.go の対象外）のため、記号・番号の値には行末マーカーを付ける。

// --- 後方互換: ScanDiffHunk/ScanDiffHunkWithCSVHeader は
// ScanDiffHunkOpts(..., DiffScanOptions{...}) への薄い委譲のまま ---

func TestScanDiffHunkIsThinDelegationToScanDiffHunkOpts(t *testing.T) {
	d := newDetector(t, "")
	phone := strings.ReplaceAll(testfixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")
	lines := []DiffLine{
		{Text: "電話番号:", Added: false},
		{Text: phone, Added: true},
	}
	got := d.ScanDiffHunk("pii.txt", lines)
	want := d.ScanDiffHunkOpts("pii.txt", lines, DiffScanOptions{})
	if len(got) == 0 {
		t.Fatal("want at least 1 finding to make the equivalence check meaningful")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ScanDiffHunk = %+v, want == ScanDiffHunkOpts(..., DiffScanOptions{}) = %+v", got, want)
	}
}

func TestScanDiffHunkWithCSVHeaderIsThinDelegationToScanDiffHunkOpts(t *testing.T) {
	d := newDetector(t, "")
	phone := strings.ReplaceAll(testfixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")
	lines := []DiffLine{
		{Text: "dummy,1000", Added: false},
		{Text: phone + "," + phone, Added: true},
	}
	const header = "電話番号,金額"
	got := d.ScanDiffHunkWithCSVHeader("data.csv", lines, header)
	want := d.ScanDiffHunkOpts("data.csv", lines, DiffScanOptions{CSVHeader: header})
	if len(got) == 0 {
		t.Fatal("want at least 1 finding to make the equivalence check meaningful")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ScanDiffHunkWithCSVHeader = %+v, want == ScanDiffHunkOpts(..., DiffScanOptions{CSVHeader:...}) = %+v", got, want)
	}
}

// --- (a) 親キーが hunk 外でも post-image から復元されて検出・非検出 ---

// phone: 配下の home: <区切りなし固定電話> が、hunk 自体には "phone:" が
// 含まれない（filler 行だけが文脈行）場合でも、PostImage 全文からの親キー
// 再構成で検出できる。"filler: x" は key=value 行（key-only ではない）なので
// 既存の addCrossLineSourceContexts（隣接 key:\nvalue 行）による混入がなく、
// 検出できるかどうかが純粋に本 PR のオブジェクトスコープ diff 対応の有無に
// かかっていることを保証する。
func TestScanDiffHunkOptsYAMLParentKeyOutsideHunkPromotesPhone(t *testing.T) {
	d := newDetector(t, "")
	fixedNoSep := strings.ReplaceAll(testfixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")
	const fillerLine = "  filler: x"
	homeLine := "  home: " + fixedNoSep
	postImage := "phone:\n" + fillerLine + "\n" + homeLine + "\n"

	// ベースライン: PostImage を渡さなければ（＝親キー復元なし）検出されない。
	withoutPostImage := d.ScanDiffHunkOpts("config.yaml", []DiffLine{
		{Text: fillerLine, Added: false},
		{Text: homeLine, Added: true},
	}, DiffScanOptions{})
	assertRules(t, withoutPostImage)

	// PostImage + HunkStartLine を渡すと、"phone:" が hunk に含まれなくても検出される。
	withPostImage := d.ScanDiffHunkOpts("config.yaml", []DiffLine{
		{Text: fillerLine, Added: false},
		{Text: homeLine, Added: true},
	}, DiffScanOptions{PostImage: postImage, HunkStartLine: 2})
	assertRules(t, withPostImage, "jp-phone-number")
	if f := withPostImage[0]; f.Line != 2 {
		t.Errorf("finding.Line = %d, want 2（hunk 内 1 始まりの行番号）", f.Line)
	}
}

// JSON 版（ネストしたオブジェクト）でも同様に、"phone" 親キーが hunk 外でも
// post-image から復元されて検出できる。"phone" キー自体は hunk にすら含めない
// （filler 行を挟む）。仮に `"phone": {` が hunk 内の文脈行として直接隣接して
// いると、本 PR とは無関係な既存の隣接行相関（scanAdjacentLinesDiff、40 ルーン
// 窓でラベルを探す汎用機構）だけでも "phone" を拾ってしまい、オブジェクトスコープ
// diff 対応の効果を正しく切り分けられない。
func TestScanDiffHunkOptsJSONParentKeyOutsideHunkPromotesPhone(t *testing.T) {
	d := newDetector(t, "")
	fixedNoSep := strings.ReplaceAll(testfixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")
	fillerLine := `    "filler": "x",`
	homeLine := `    "home": "` + fixedNoSep + `"`
	postImage := "{\n" + `  "phone": {` + "\n" + fillerLine + "\n" + homeLine + "\n  }\n}\n"

	hunkLines := []DiffLine{
		{Text: fillerLine, Added: false},
		{Text: homeLine, Added: true},
	}
	// この hunk 自体は "phone" キーを一切含まない。jsonObjectScope は post-image
	// 全文の先頭から深さを積み上げる必要があるため、PostImage なしでは深さの
	// 復元に失敗し検出できない。
	withoutPostImage := d.ScanDiffHunkOpts("data.json", hunkLines, DiffScanOptions{})
	assertRules(t, withoutPostImage)

	withPostImage := d.ScanDiffHunkOpts("data.json", hunkLines, DiffScanOptions{PostImage: postImage, HunkStartLine: 3})
	assertRules(t, withPostImage, "jp-phone-number")
}

// order: 配下の id: <7桁> は口座番号として検出されない（親キー "order" の
// NegativeText マージが既存の自己文脈（id）による抑制を壊さないことの回帰確認。
// ScanContent 側の TestScanContentYAMLOrderIDNotDetectedAsBankAccount と対称）。
// "phone:" 側と同じく "order:" 自体は hunk 外に置く。
func TestScanDiffHunkOptsYAMLOrderIDNotDetectedAsBankAccount(t *testing.T) {
	d := newDetector(t, "")
	acct := testfixtures.MustGet(t, "detect.bank_account")
	const fillerLine = "  filler: x"
	idLine := "  id: " + acct
	postImage := "order:\n" + fillerLine + "\n" + idLine + "\n"

	fs := d.ScanDiffHunkOpts("config.yaml", []DiffLine{
		{Text: fillerLine, Added: false},
		{Text: idLine, Added: true},
	}, DiffScanOptions{PostImage: postImage, HunkStartLine: 2})
	assertRules(t, fs)
}

// --- (b) post-image 行不一致時のフォールバック ---

// hunk 側の行テキストと、対応するはずの postImage 側の行テキストが食い違う場合
// （呼び出し側の取得ずれ・作業ツリーと index の乖離等）、その行以降は親キーを
// マージしない。ミスマッチより前の行は通常どおりマージされ、ミスマッチ以降は
// マージされない（安全側に倒れて処理を打ち切る）ことを、2 つの親ブロックを
// またぐ hunk で確認する。
func TestScanDiffHunkOptsPostImageMismatchStopsPropagation(t *testing.T) {
	d := newDetector(t, "")
	fixedNoSep := strings.ReplaceAll(testfixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")
	homeLine := "  home: " + fixedNoSep
	noteLine := "  note: " + fixedNoSep
	// postImage: phone: (1) / home (2, 一致) / memo: (3) / note (4)
	postImage := "phone:\n" + homeLine + "\nmemo:\n" + noteLine + "\n"

	hunkLines := []DiffLine{
		{Text: homeLine, Added: true},         // idx0 → postIdx=1 (0-based)=homeLine 一致
		{Text: "memo-CHANGED:", Added: false}, // idx1 → postIdx=2 (0-based)="memo:" 不一致
		{Text: noteLine, Added: true},         // idx2 → 到達しない（打ち切り後）
	}
	// HunkStartLine=2: hunk の 1 行目（homeLine）が postImage の 2 行目
	// （"phone:" の次、homeLine 自身）に対応する。
	fs := d.ScanDiffHunkOpts("config.yaml", hunkLines, DiffScanOptions{PostImage: postImage, HunkStartLine: 2})

	foundLines := map[int]bool{}
	for _, f := range fs {
		if f.RuleID != "jp-phone-number" {
			t.Errorf("unexpected rule %q in findings: %+v", f.RuleID, fs)
			continue
		}
		foundLines[f.Line] = true
	}
	if !foundLines[1] {
		t.Errorf("findings = %+v, want line 1 detected（不一致より前は通常どおりマージ）", fs)
	}
	if foundLines[3] {
		t.Errorf("findings = %+v, want line 3 not detected"+
			"（不一致以降はマージを打ち切るため note の自己文脈だけでは検出されない）", fs)
	}
}

// --- (c) HunkStartLine ずれの境界 ---

// post-image の最終行にちょうど一致する境界（オフバイワンではない）では、
// 正しくマージされて検出できる。
func TestScanDiffHunkOptsHunkStartLineExactBoundary(t *testing.T) {
	d := newDetector(t, "")
	fixedNoSep := strings.ReplaceAll(testfixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")
	const fillerLine = "  filler: x"
	homeLine := "  home: " + fixedNoSep
	// postImage: phone:(1) / filler(2) / home(3, 最終行)
	postImage := "phone:\n" + fillerLine + "\n" + homeLine + "\n"

	fs := d.ScanDiffHunkOpts("config.yaml", []DiffLine{
		{Text: homeLine, Added: true},
	}, DiffScanOptions{PostImage: postImage, HunkStartLine: 3})
	assertRules(t, fs, "jp-phone-number")
}

// HunkStartLine が実際より 1 大きい（オフバイワン）場合、対応する post-image
// 側の行が範囲外になり、安全側にフォールバックして検出されない
// （パニックもしない）。
func TestScanDiffHunkOptsHunkStartLineOffByOneFallsBack(t *testing.T) {
	d := newDetector(t, "")
	fixedNoSep := strings.ReplaceAll(testfixtures.MustGet(t, "detect.phone_fixed_tokyo"), "-", "")
	const fillerLine = "  filler: x"
	homeLine := "  home: " + fixedNoSep
	postImage := "phone:\n" + fillerLine + "\n" + homeLine + "\n"

	fs := d.ScanDiffHunkOpts("config.yaml", []DiffLine{
		{Text: homeLine, Added: true},
	}, DiffScanOptions{PostImage: postImage, HunkStartLine: 4}) // 正しくは 3
	assertRules(t, fs)
}

// --- 低レベル: applyObjectScopeContextForDiff 単体 ---
//
// object_scope_test.go の TestYAMLObjectScopeMergesParentIntoPositiveText 等と
// 同じ流儀で、ScanDiffHunkOpts を経由せず直接呼んで statementContext への反映を
// 確認する。

func TestApplyObjectScopeContextForDiffMergesParentFromOutsideHunk(t *testing.T) {
	postImage := "phone:\n  filler: x\n  home: dummy\n"
	hunkLines := []string{"  filler: x", "  home: dummy"}
	ctxs := []lineContext{
		{Statements: []statementContext{{Start: 0, End: len(hunkLines[0]), PositiveText: "filler"}}},
		{Statements: []statementContext{{Start: 0, End: len(hunkLines[1]), PositiveText: "home"}}},
	}
	applyObjectScopeContextForDiff(ctxs, "config.yaml", hunkLines, postImage, 2)

	if got := ctxs[1].Statements[0].PositiveText; !strings.Contains(got, "phone") {
		t.Errorf("PositiveText = %q, want to contain %q（hunk 外の親キー）", got, "phone")
	}
	if !strings.Contains(ctxs[1].Statements[0].PositiveText, "home") {
		t.Errorf("PositiveText = %q, want to contain %q（自己文脈も保持）", ctxs[1].Statements[0].PositiveText, "home")
	}
	// RecordID は diff 走査では一切設定しない（cooccurrence_boost は ScanContent 専用）。
	for i, c := range ctxs {
		if c.RecordID != 0 {
			t.Errorf("ctxs[%d].RecordID = %d, want 0（diff 走査では設定しない）", i, c.RecordID)
		}
	}
}

// postImage が空文字列（未取得・対象外・サイズ超過等）なら何もしない。
func TestApplyObjectScopeContextForDiffNoOpWithEmptyPostImage(t *testing.T) {
	hunkLines := []string{"  home: dummy"}
	ctxs := []lineContext{
		{Statements: []statementContext{{Start: 0, End: len(hunkLines[0]), PositiveText: "home"}}},
	}
	applyObjectScopeContextForDiff(ctxs, "config.yaml", hunkLines, "", 1)
	if got := ctxs[0].Statements[0].PositiveText; got != "home" {
		t.Errorf("PositiveText = %q, want unchanged %q", got, "home")
	}
}

// .json/.yaml/.yml 以外の拡張子では、PostImage を渡しても何もしない
// （objectScopeKindForPath が対象外を返す。.go・.jsonc も含めて確認する）。
func TestApplyObjectScopeContextForDiffNoOpForNonObjectScopeExtension(t *testing.T) {
	for _, file := range []string{"service.go", "data.jsonc"} {
		postImage := "phone:\n  home: dummy\n"
		hunkLines := []string{"  home: dummy"}
		ctxs := []lineContext{
			{Statements: []statementContext{{Start: 0, End: len(hunkLines[0]), PositiveText: "home"}}},
		}
		applyObjectScopeContextForDiff(ctxs, file, hunkLines, postImage, 2)
		if got := ctxs[0].Statements[0].PositiveText; got != "home" {
			t.Errorf("%s: PositiveText = %q, want unchanged %q（object scope 対象外）", file, got, "home")
		}
	}
}

// HunkStartLine が未設定（ゼロ値）の場合も安全にフォールバックする
// （PostImage を渡し忘れた・対象外ファイルで意図的にゼロ値のままの経路を想定）。
func TestApplyObjectScopeContextForDiffNoOpWithZeroHunkStartLine(t *testing.T) {
	postImage := "phone:\n  home: dummy\n"
	hunkLines := []string{"  home: dummy"}
	ctxs := []lineContext{
		{Statements: []statementContext{{Start: 0, End: len(hunkLines[0]), PositiveText: "home"}}},
	}
	applyObjectScopeContextForDiff(ctxs, "config.yaml", hunkLines, postImage, 0)
	if got := ctxs[0].Statements[0].PositiveText; got != "home" {
		t.Errorf("PositiveText = %q, want unchanged %q（HunkStartLine 未設定は安全側）", got, "home")
	}
}
