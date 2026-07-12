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
// しかならない（recall には影響しない）という設計を直接検証する。マーカー付き
// 番地・漢数字番地・マーカーなしダッシュ連結の 3 形すべてを対象にする
// （3 形とも同じ twin 方式のため）。
func TestAddressHighRecallUnknownTownStaysMedium(t *testing.T) {
	d := newDetector(t, highRecallTOML)

	tests := []struct {
		name string
		line string
	}{
		{"マーカー付き番地・辞書にない語（通学区域）", "渋谷区通学区域1丁目2番3号"},     // jp-pii-detector:ignore
		{"マーカー付き番地・辞書にない語（ニュータウン）", "渋谷区ニュータウン1丁目2番3号"}, // jp-pii-detector:ignore
		{"漢数字番地・辞書にない語（ニュータウン）", "渋谷区ニュータウン一丁目十九番十一号"},  // jp-pii-detector:ignore
		{"ダッシュ形・辞書にない語（ニュータウン）", "渋谷区ニュータウン2-1-5"},      // jp-pii-detector:ignore
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

// TestAddressHighRecallDashFormPromotesWithRealTown は、マーカーなしダッシュ
// 連結の番地（banchiDash）にも町字辞書の昇格 twin が適用され、市区町村マッチ
// 直後が ABR 町字マスターの実在町字名（神南）で始まる場合は Medium ではなく
// High で検出されることを確認する（TestAddressHighRecallPromotesWithRealTown の
// マーカー付き・漢数字番地の 2 形と同じ性質を、ダッシュ形についても検証する）。
//
// 背景（旧 TestAddressHighRecallDashFormNotPromoted からの反転）: PR #127
// 時点ではこのダッシュ形 twin は意図的に見送られていた。
// TestPromotionContextWindowBoundary（detect_test.go）がコンテキスト窓境界の
// 検証に使う固定サンプルの町字部分（旧サンプルの町名）が ABR 町字マスターの
// 実在町字名と偶然一致しており、無条件の辞書昇格を追加すると、同テストが
// 検証する「窓のちょうど外側では昇格しない」が辞書昇格経路の混入で壊れて
// いたためである。同テストのサンプル値を、町字マスターに前方一致しない架空の
// 町名（「架空坂」。go run で機械確認済み）へ差し替えたことでこの衝突が解消され、
// 他の 2 形と同じ twin をダッシュ形にも適用できるようになった
// （internal/rule/builtin.go の addressHighRecallDashRe 節のコメントも参照）。
func TestAddressHighRecallDashFormPromotesWithRealTown(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	line := "渋谷区神南2-1-5" // jp-pii-detector:ignore
	fs := d.ScanLine("f.txt", 1, line)
	assertRules(t, fs, "jp-address-high-recall")
	if fs[0].Confidence != rule.High {
		t.Errorf("confidence = %v, want %v（神南は実在町字名のため、ダッシュ形でも昇格するはず）",
			fs[0].Confidence, rule.High)
	}
}

// TestAddressHighRecallDashFormRejectsCalendarDateDespiteRealTown は、末尾が
// 実在暦日形（notCalendarDateBanchi が棄却する「YYYY-MM-DD」形）のダッシュ形
// 番地は、市区町村マッチ直後が実在町字名（神南）であっても High へ昇格しない
// （＝棄却され続ける）ことを確認する固定テスト。
//
// ダッシュ形 High 側の Validate は notCalendarDateBanchiAndRealTown
// （internal/rule/builtin.go）で、notCalendarDateBanchi と
// dict.MunicipalityThenTownMatch を AND 合成している。もし誤って
// dict.MunicipalityThenTownMatch 単体を High 側の Validate にしていた場合、
// 「渋谷区神南2025-07-02」のように市区町村直後が実在町字名（神南）で始まり
// つつ番地部分が実在暦日形（2025-07-02）の値が、ISO 日付棄却をすり抜けて
// High と誤検出されてしまう。Medium 側は元々 notCalendarDateBanchi 単体で
// 同じ値を棄却しているため、この AND 合成が抜けると High 側「だけ」
// 日付棄却が効かなくなる非対称なリグレッションになる。この値は
// jp-address-high-recall のどのパターンにも一致しない（Medium 側も同じ理由で
// 棄却されるため）ことをあわせて確認する。
func TestAddressHighRecallDashFormRejectsCalendarDateDespiteRealTown(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	line := "渋谷区神南2025-07-02" // jp-pii-detector:ignore
	fs := d.ScanLine("f.txt", 1, line)
	for _, f := range fs {
		if f.RuleID == "jp-address-high-recall" {
			t.Errorf("jp-address-high-recall が検出された: confidence = %v, want 非検出（実在暦日形は棄却されるはず）", f.Confidence)
		}
	}
}
