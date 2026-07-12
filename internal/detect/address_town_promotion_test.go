package detect

import (
	"testing"

	"github.com/baneido/jp-pii-detector/internal/rule"
	"github.com/baneido/jp-pii-detector/internal/testfixtures"
)

// このファイルは jp-address-high-recall の町字辞書（ABR 町字マスター由来、
// internal/dict/towns.go）による昇格専用 twin パターンを検証する
// （internal/rule/builtin.go の jp-address-high-recall 節、
// dict.MunicipalityThenTownMatch を参照）。
//
// コンテキスト昇格（TestPromotionContextWindowBoundary 等）と切り離して
// 町字辞書由来の昇格だけを観測するため、ラベル（"住所" 等）を直接
// 隣接させないサンプル行を使う（ラベルが近傍にあると、コンテキスト窓に
// よる昇格と町字辞書による昇格のどちらが効いたか区別できないため）。
//
// PII 形のサンプル値を含む行は、行末に jp-pii-detector:ignore を付けて
// dogfooding から除外する（sql_context_test.go と同じ方針。
// detect_test.go 等と異なりこのファイルは .jp-pii.toml の allowlist に
// 含まれないため、ファイル単位ではなく行単位で明示する）。

// TestAddressHighRecallPromotesWithRealTown は、市区町村マッチ直後のギャップが
// ABR 町字マスターに実在する町字名で始まる住所（マーカー付き番地・漢数字番地の
// 2 形）が Medium ではなく High で検出されることを確認する。
func TestAddressHighRecallPromotesWithRealTown(t *testing.T) {
	d := newDetector(t, highRecallTOML)

	t.Run("マーカー付き番地（神南、fixture 経由）", func(t *testing.T) {
		// 神南は towns.txt に実在する町字名。fixture 経由の値なので、
		// このソース行自体に PII 形の完全な文字列は現れない。
		line := testfixtures.MustGet(t, "detect.address_shibuya_ward")
		fs := d.ScanLine("f.txt", 1, line)
		assertRules(t, fs, "jp-address-high-recall")
		if fs[0].Confidence != rule.High {
			t.Errorf("confidence = %v, want %v（神南は実在町字名のため昇格するはず）", fs[0].Confidence, rule.High)
		}
	})

	t.Run("漢数字番地（神南）", func(t *testing.T) {
		line := "渋谷区神南一丁目十九番十一号" // jp-pii-detector:ignore
		fs := d.ScanLine("f.txt", 1, line)
		assertRules(t, fs, "jp-address-high-recall")
		if fs[0].Confidence != rule.High {
			t.Errorf("confidence = %v, want %v（神南は実在町字名のため昇格するはず）", fs[0].Confidence, rule.High)
		}
	})

	t.Run("文中に埋め込まれていてもラベル無しで昇格する", func(t *testing.T) {
		// "住所"等のラベルが一切ないため、コンテキスト窓昇格ではなく
		// 町字辞書昇格だけが働く。
		line := "社内メモ 渋谷区神南1丁目2番3号 の物件を検討中" // jp-pii-detector:ignore
		fs := d.ScanLine("f.txt", 1, line)
		assertRules(t, fs, "jp-address-high-recall")
		if fs[0].Confidence != rule.High {
			t.Errorf("confidence = %v, want %v", fs[0].Confidence, rule.High)
		}
	})
}

// TestAddressHighRecallUnknownTownStaysMedium は、市区町村は実在するが続く語が
// ABR 町字マスターに存在しない住所（通学区域・団地名等の一般語）が、
// 昇格せず Medium のまま検出される（＝棄却されない）ことを確認する。
// 町字辞書は昇格専用のエビデンスであり、不一致は Medium への据え置きに
// しかならない（recall には影響しない）という設計を直接検証する。
func TestAddressHighRecallUnknownTownStaysMedium(t *testing.T) {
	d := newDetector(t, highRecallTOML)

	tests := []struct {
		name string
		line string
	}{
		{"マーカー付き番地・辞書にない語（通学区域）", "渋谷区通学区域1丁目2番3号"},     // jp-pii-detector:ignore
		{"マーカー付き番地・辞書にない語（ニュータウン）", "渋谷区ニュータウン1丁目2番3号"}, // jp-pii-detector:ignore
		{"漢数字番地・辞書にない語（ニュータウン）", "渋谷区ニュータウン一丁目十九番十一号"},  // jp-pii-detector:ignore
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanLine("f.txt", 1, tt.line)
			// 棄却されていない（Medium で検出され続けている）ことがまず重要。
			assertRules(t, fs, "jp-address-high-recall")
			if fs[0].Confidence != rule.Medium {
				t.Errorf("confidence = %v, want %v（辞書にない語尾は昇格しないが、棄却もされないはず）",
					fs[0].Confidence, rule.Medium)
			}
		})
	}
}

// TestAddressHighRecallDashFormNotPromoted は、マーカーなしダッシュ連結の番地
// （banchiDash）には町字辞書の昇格 twin を適用していないことを記録する
// 回帰テスト。実在町字名（神南）であっても Medium のまま昇格しない。
//
// 理由: このダッシュ形パターンに twin を追加すると、
// TestPromotionContextWindowBoundary（detect_test.go）が固定サンプルに使う
// 住所の町字部分が ABR 町字マスターの実在町字名と一致し、
// コンテキスト窓の内外を問わず常に High へ昇格してしまう。同テストはコンテキスト
// 窓のちょうど外側で「昇格しない」ことを検証しており、internal/detect は変更禁止
// のためサンプル値の差し替えによる回避もできない。マーカー付き番地・漢数字番地の
// 2 形には同種の衝突がないことを確認済みで、双方には twin を適用している
// （internal/rule/builtin.go の該当コメントも参照）。
func TestAddressHighRecallDashFormNotPromoted(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	line := "渋谷区神南2-1-5" // jp-pii-detector:ignore
	fs := d.ScanLine("f.txt", 1, line)
	assertRules(t, fs, "jp-address-high-recall")
	if fs[0].Confidence != rule.Medium {
		t.Errorf("confidence = %v, want %v（ダッシュ形は twin 非適用のため、実在町字名でも Medium のまま）",
			fs[0].Confidence, rule.Medium)
	}
}
