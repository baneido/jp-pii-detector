package detect

import (
	"testing"

	"github.com/baneido/jp-pii-detector/internal/rule"
)

// yucho_pair_diff_test.go は ScanDiffHunkOpts 経由のゆうちょ別行ペア diff 対応
// （scanCrossLineYuchoPairsDiff、internal/detect/yucho_pair.go、issue #134）の
// テスト。internal/source/gitdiff_test.go には実 git リポジトリを使った
// end-to-end テストがある。yucho_pair_test.go（ScanContent 版）と同じ記号
// "14040"・番号 "12345671" を使う（テスト間で検出値の実値を揃えるため）。
//
// PII 形サンプルについて: jp-yucho-account の別行ペア検出は Base が常に High
// （path_profile.go のパス降格対象外）なので、記号・番号の値を含む行には
// 行末に jp-pii-detector:ignore を付ける（yucho_pair_test.go と同じ方針）。

// --- (d) ゆうちょペアの追加行のみ報告・文脈行ペア非報告 ---

// 記号行が文脈行（未変更）、番号行が追加行の場合、番号側の値だけが報告される
// （記号側は「既存 PII」として報告しない）。
func TestScanDiffHunkOptsYuchoPairSymbolContextNumberAdded(t *testing.T) {
	d := newDetector(t, "")
	lines := []DiffLine{
		{Text: "記号: 14040", Added: false},   // jp-pii-detector:ignore
		{Text: "番号: 12345671", Added: true}, // jp-pii-detector:ignore
	}
	fs := d.ScanDiffHunkOpts("f.txt", lines, DiffScanOptions{})
	if len(fs) != 1 {
		t.Fatalf("len(fs) = %d, want 1 (findings=%v)", len(fs), ruleIDs(fs))
	}
	f := fs[0]
	if f.RuleID != "jp-yucho-account" || f.Confidence != rule.High || !f.Reason.Validated {
		t.Fatalf("finding = %+v, want jp-yucho-account/high/validated", f)
	}
	if f.Line != 2 || f.Match != "12345671" {
		t.Fatalf("finding = line=%d match=%q, want line=2 match=12345671", f.Line, f.Match)
	}
}

// 記号行が追加行、番号行が文脈行（未変更）の場合、記号側の値だけが報告される
// （逆の組み合わせでも対称に振る舞う）。
func TestScanDiffHunkOptsYuchoPairSymbolAddedNumberContext(t *testing.T) {
	d := newDetector(t, "")
	lines := []DiffLine{
		{Text: "記号: 14040", Added: true},     // jp-pii-detector:ignore
		{Text: "番号: 12345671", Added: false}, // jp-pii-detector:ignore
	}
	fs := d.ScanDiffHunkOpts("f.txt", lines, DiffScanOptions{})
	if len(fs) != 1 {
		t.Fatalf("len(fs) = %d, want 1 (findings=%v)", len(fs), ruleIDs(fs))
	}
	f := fs[0]
	if f.RuleID != "jp-yucho-account" || f.Line != 1 || f.Match != "14040" {
		t.Fatalf("finding = %+v, want jp-yucho-account line=1 match=14040", f)
	}
}

// 記号行・番号行の両方が追加行の場合、両方とも報告される（ScanContent の基本
// ケースと同じ結果になることの確認）。
func TestScanDiffHunkOptsYuchoPairBothAdded(t *testing.T) {
	d := newDetector(t, "")
	lines := []DiffLine{
		{Text: "記号: 14040", Added: true},    // jp-pii-detector:ignore
		{Text: "番号: 12345671", Added: true}, // jp-pii-detector:ignore
	}
	fs := d.ScanDiffHunkOpts("f.txt", lines, DiffScanOptions{})
	if len(fs) != 2 {
		t.Fatalf("len(fs) = %d, want 2 (findings=%v)", len(fs), ruleIDs(fs))
	}
	for _, f := range fs {
		if f.RuleID != "jp-yucho-account" {
			t.Errorf("unexpected rule %q in findings: %+v", f.RuleID, fs)
		}
	}
	if fs[0].Line != 1 || fs[0].Match != "14040" {
		t.Errorf("fs[0] = %+v, want line=1 match=14040", fs[0])
	}
	if fs[1].Line != 2 || fs[1].Match != "12345671" {
		t.Errorf("fs[1] = %+v, want line=2 match=12345671", fs[1])
	}
}

// 記号行・番号行の両方が文脈行（未変更）の場合、検証まで通っても双方とも
// 報告しない（「文脈行に乗る値は報告しない」という diff 走査全体の原則）。
func TestScanDiffHunkOptsYuchoPairBothContextNotReported(t *testing.T) {
	d := newDetector(t, "")
	lines := []DiffLine{
		{Text: "記号: 14040", Added: false},    // jp-pii-detector:ignore
		{Text: "番号: 12345671", Added: false}, // jp-pii-detector:ignore
	}
	fs := d.ScanDiffHunkOpts("f.txt", lines, DiffScanOptions{})
	assertRules(t, fs)
}

// 間に空行を 1 つ挟んだ論理隣接（既存の scanCrossLineYuchoPairs の隣接規則）でも
// 追加行のみ報告される規則が同様に働く。
func TestScanDiffHunkOptsYuchoPairAdjacentWithBlankLine(t *testing.T) {
	d := newDetector(t, "")
	lines := []DiffLine{
		{Text: "記号: 14040", Added: false}, // jp-pii-detector:ignore
		{Text: "", Added: false},
		{Text: "番号: 12345671", Added: true}, // jp-pii-detector:ignore
	}
	fs := d.ScanDiffHunkOpts("f.txt", lines, DiffScanOptions{})
	if len(fs) != 1 {
		t.Fatalf("len(fs) = %d, want 1 (findings=%v)", len(fs), ruleIDs(fs))
	}
	if f := fs[0]; f.Line != 3 || f.Match != "12345671" {
		t.Fatalf("finding = %+v, want line=3 match=12345671", f)
	}
}

// scanCrossLineYuchoPairs 自体が検出しない組み合わせ（不正な形状・ValidCrossLineYuchoPair
// 不成立等）は、diff 版でも当然報告されない（ScanDiffHunkOpts に委譲するだけの
// フィルタが余計な検出を作り出さないことの確認）。
func TestScanDiffHunkOptsYuchoPairInvalidPairNotReported(t *testing.T) {
	d := newDetector(t, "")
	// 記号・番号とも全桁同一のダミー値。ValidCrossLineYuchoPair が AllSame を棄却する。
	lines := []DiffLine{
		{Text: "記号: 11111", Added: true},    // jp-pii-detector:ignore
		{Text: "番号: 11111111", Added: true}, // jp-pii-detector:ignore
	}
	fs := d.ScanDiffHunkOpts("f.txt", lines, DiffScanOptions{})
	assertRules(t, fs)
}

// --- 低レベル: scanCrossLineYuchoPairsDiff 単体 ---

func TestScanCrossLineYuchoPairsDiffFiltersToAddedLines(t *testing.T) {
	d := newDetector(t, "")
	texts := []string{"記号: 14040", "番号: 12345671"} // jp-pii-detector:ignore
	tests := []struct {
		name  string
		added []bool
		want  []int // 期待される finding の Line 一覧
	}{
		{"両方追加", []bool{true, true}, []int{1, 2}},
		{"記号のみ追加", []bool{true, false}, []int{1}},
		{"番号のみ追加", []bool{false, true}, []int{2}},
		{"両方文脈行", []bool{false, false}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.scanCrossLineYuchoPairsDiff("f.txt", texts, tt.added)
			if len(fs) != len(tt.want) {
				t.Fatalf("len(fs) = %d, want %d (fs=%+v)", len(fs), len(tt.want), fs)
			}
			for i, f := range fs {
				if f.Line != tt.want[i] {
					t.Errorf("fs[%d].Line = %d, want %d", i, f.Line, tt.want[i])
				}
			}
		})
	}
}
