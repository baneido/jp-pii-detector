package detect

import (
	"testing"

	"github.com/baneido/jp-pii-detector/internal/rule"
)

// 構造化・複数行の氏名検出のうち、姓+名が別行の弱いラベル付きフィールドに
// 分かれるケース（姓: ...\n名: ... 等）のテスト。internal/rule/structured.go の
// CrossLineSurnameLabelRe / CrossLineGivenLabelRe / ValidCrossLineSurnameGivenPair
// と、internal/detect/structured_pair.go の scanCrossLineSurnameGivenPairs が
// 対象。値は埋め込み姓名辞書に含まれる一般的な姓・名のリテラルを使い、外部
// フィクスチャ無しでも実行できるようにしている（dict/names_test.go・
// detect_test.go の TestCrossLineName* と同じ方針）。

// TestCrossLineSurnameGivenPairAdjacent は姓行・名行が論理隣接する基本ケース
// （直接隣接、および間に空行を 1 つ挟むケース）を確認する。
//
// 姓・名がいずれも辞書収録の 2 文字以上の値（山田・太郎）のため、単独行の
// 弱いラベル検出（person-name、Medium）も同一スパンで独立に成立し、
// ScanContent の resolveOverlapsPerLine のタイブレーク（信頼度・スパン長が
// 同点のとき RuleID の辞書順で決着。"person-name" は "person-name-structured" の
// 真の接頭辞で文字列として小さいため勝つ）で "person-name" 側が残る。これは
// 想定どおりの挙動で、値そのものは変わらず Medium で報告される（実害はない）。
// 姓+名ペア相関が単独行検出には無い検出力を追加する、タイブレークなしの
// "クリーンな勝ち" の具体例は TestCrossLineSurnameGivenPairCleanWinOverWeakLabel
// を参照。
func TestCrossLineSurnameGivenPairAdjacent(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	tests := []struct {
		name      string
		content   string
		wantLine2 int
	}{
		{"直接隣接", "姓: 山田\n名: 太郎\n", 2},     // jp-pii-detector:ignore
		{"空行1つ挟み", "姓: 山田\n\n名: 太郎\n", 3}, // jp-pii-detector:ignore
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanContent("f.txt", tt.content)
			if len(fs) != 2 {
				t.Fatalf("len(fs) = %d, want 2", len(fs))
			}
			for _, f := range fs {
				// タイブレークで person-name が残る（上記コメント参照）。
				if f.RuleID != "person-name" || f.Confidence != rule.Medium {
					t.Fatalf("finding: rule=%s confidence=%s, want person-name/medium", f.RuleID, f.Confidence)
				}
			}
			if fs[0].Line != 1 || fs[0].Column != 4 || fs[0].Match != "山田" {
				t.Fatalf("fs[0] = line=%d col=%d match=%q, want 1/4/山田", fs[0].Line, fs[0].Column, fs[0].Match)
			}
			if fs[1].Line != tt.wantLine2 || fs[1].Column != 4 || fs[1].Match != "太郎" {
				t.Fatalf("fs[1] = line=%d col=%d match=%q, want %d/4/太郎", fs[1].Line, fs[1].Column, fs[1].Match, tt.wantLine2)
			}
		})
	}
}

// TestCrossLineSurnameGivenPairAltLabels は姓側の別ラベル語（名字）でもペア検出が
// 機能することを確認する。値は佐藤・花子でいずれも 2 文字の辞書名のため、
// TestCrossLineSurnameGivenPairAdjacent と同様に person-name とのタイブレークで
// person-name が残る。
func TestCrossLineSurnameGivenPairAltLabels(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	fs := d.ScanContent("f.txt", "名字: 佐藤\n名: 花子\n") // jp-pii-detector:ignore
	if len(fs) != 2 {
		t.Fatalf("len(fs) = %d, want 2", len(fs))
	}
	if fs[0].RuleID != "person-name" || fs[0].Line != 1 || fs[0].Match != "佐藤" {
		t.Fatalf("fs[0] = rule=%s line=%d match=%q", fs[0].RuleID, fs[0].Line, fs[0].Match)
	}
	if fs[1].RuleID != "person-name" || fs[1].Line != 2 || fs[1].Match != "花子" {
		t.Fatalf("fs[1] = rule=%s line=%d match=%q", fs[1].RuleID, fs[1].Line, fs[1].Match)
	}
}

// TestCrossLineSurnameGivenPairJSON は JSON 風のキー引用符付き表記
// （"last_name": "値"）でもペア検出が機能することを確認する。
func TestCrossLineSurnameGivenPairJSON(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	fs := d.ScanContent("f.txt", "\"last_name\": \"山田\"\n\"first_name\": \"太郎\"\n") // jp-pii-detector:ignore
	if len(fs) != 2 {
		t.Fatalf("len(fs) = %d, want 2", len(fs))
	}
	if fs[0].Line != 1 || fs[0].Match != "山田" {
		t.Fatalf("fs[0] = line=%d match=%q, want 1/山田", fs[0].Line, fs[0].Match)
	}
	if fs[1].Line != 2 || fs[1].Match != "太郎" {
		t.Fatalf("fs[1] = line=%d match=%q, want 2/太郎", fs[1].Line, fs[1].Match)
	}
}

// TestCrossLineSurnameGivenPairCleanWinOverWeakLabel は、単独行では検出できない
// 1 文字の辞書収録名（明）が、姓とペアになったときにだけ検出できることを確認
// する。単独行の弱いラベル検出（validGivenField、internal/rule/builtin.go）は
// 1 文字の名を明示的に棄却する（田中等との衝突を避けるため）ため、この値は
// ペア相関検証だけが拾える。resolveOverlapsPerLine のタイブレークの影響を受け
// ない、person-name-structured の「クリーンな勝ち」の具体例でもある。
func TestCrossLineSurnameGivenPairCleanWinOverWeakLabel(t *testing.T) {
	d := newDetector(t, highRecallTOML)

	// ベースライン確認: 単独行では 1 文字の名は拾えない。
	assertRules(t, d.ScanContent("f.txt", "名: 明\n")) // jp-pii-detector:ignore

	// 姓とペアになると person-name-structured で検出できる。
	fs := d.ScanContent("f.txt", "苗字: 山田\nfirst_name: 明\n") // jp-pii-detector:ignore
	assertRules(t, fs, "person-name", "person-name-structured")
	if fs[0].RuleID != "person-name" || fs[0].Line != 1 || fs[0].Column != 5 || fs[0].Match != "山田" || fs[0].Confidence != rule.Medium {
		t.Fatalf("fs[0] = rule=%s line=%d col=%d match=%q confidence=%s",
			fs[0].RuleID, fs[0].Line, fs[0].Column, fs[0].Match, fs[0].Confidence)
	}
	if fs[1].RuleID != "person-name-structured" || fs[1].Line != 2 || fs[1].Column != 13 || fs[1].Match != "明" || fs[1].Confidence != rule.Medium {
		t.Fatalf("fs[1] = rule=%s line=%d col=%d match=%q confidence=%s",
			fs[1].RuleID, fs[1].Line, fs[1].Column, fs[1].Match, fs[1].Confidence)
	}
}

// TestCrossLineSurnameGivenPairDisabledByDefault は高再現率モードでなければ
// 姓+名ペア相関検証が走らないことを確認する（既定挙動を変えない）。単独行では
// 拾えない 1 文字の名（明）を使い、person-name-structured が出ないことを厳密に
// 確認する。
func TestCrossLineSurnameGivenPairDisabledByDefault(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("f.txt", "苗字: 山田\nfirst_name: 明\n") // jp-pii-detector:ignore
	assertRules(t, fs, "person-name")
}

// TestCrossLineSurnameGivenPairNegativeCases はペア相関検証が対象外とすべき
// ケースをまとめて確認する。want が nil のケースは検出ゼロ、非 nil のケースは
// 単独行の弱いラベル検出（person-name）のみが残り、person-name-structured は
// 出ないことを意味する。
func TestCrossLineSurnameGivenPairNegativeCases(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		// 姓のみ（隣接する名行が無い）。単独行の弱いラベル検出のみ残る。
		{"姓のみ", "姓: 山田\n", []string{"person-name"}}, // jp-pii-detector:ignore
		// 名のみ（隣接する姓行が無い）。1 文字の名は単独行では拾えない。
		{"名のみ", "名: 明\n", nil}, // jp-pii-detector:ignore
		// プレースホルダ（姓側）。ValidCrossLineSurnameGivenPair・単独行検出の
		// notPlaceholderName の両方で棄却される。
		{"姓がプレースホルダ", "姓: 未定\n名: 明\n", nil}, // jp-pii-detector:ignore
		// 姓・名辞書のいずれにも無い組。
		{"辞書に無い組", "姓: 会議\n名: 資料\n", nil}, // jp-pii-detector:ignore
		// 名→姓の逆順は対象外（姓ラベル行を起点に、その直後の非空白行だけを
		// 名ラベル行として調べるため、逆順ペアは走査対象に入らない）。姓行は
		// 単独行検出で引き続き拾われる。
		{"名→姓の逆順", "名: 明\n姓: 山田\n", []string{"person-name"}}, // jp-pii-detector:ignore
		// 4 行以上離れたペア（間に空行 3 つ）は maxAdjacentLineGap（j-i<=3）を
		// 超えるため論理隣接とみなさない。
		{"4行以上離れたペア", "姓: 山田\n\n\n\n名: 明\n", []string{"person-name"}}, // jp-pii-detector:ignore
		// 値行（名側）に ignore マーカー。CrossLineGivenLabelRe は行全体を
		// アンカーするため、行末の何か（ignore マーカーを含む）でマッチしなく
		// なり、ペアとして成立しない。姓行は単独行検出で引き続き拾われる。
		{"値行にignoreマーカー", "姓: 山田\n名: 明 // jp-pii-detector:ignore\n", []string{"person-name"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanContent("f.txt", tt.content)
			assertRules(t, fs, tt.want...)
		})
	}
}
