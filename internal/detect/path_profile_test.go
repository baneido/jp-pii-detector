package detect

import (
	"testing"

	"github.com/baneido/jp-pii-detector/internal/rule"
)

// isTestPath はディレクトリ成分・ファイル名だけで判定する。code/data/doc の
// 拡張子違いを含めて確認し、判定が拡張子ではなくパス／ファイル名に基づくことを示す。
func TestIsTestPathPositive(t *testing.T) {
	paths := []string{
		"testdata/sample.go",                  // コード系拡張子 + testdata/
		"testdata/sample.csv",                 // データ系拡張子 + testdata/
		"testdata/README.md",                  // ドキュメント系拡張子 + testdata/
		"internal/foo/testdata/bar.json",      // ネストした testdata/
		"fixtures/users.json",
		"src/__tests__/App.test.tsx",
		"spec/user_spec.rb",
		"internal/mocks/client.go",
		"db/seed/users.sql",
		"db/seeds/users.sql",
		"internal/handler_test.go",
		"src/App.spec.ts",
		"src/App.test.js",
		"a/b/c/testdata/d/e.txt",
	}
	for _, p := range paths {
		if !isTestPath(p) {
			t.Errorf("isTestPath(%q) = false, want true", p)
		}
	}
}

func TestIsTestPathNegative(t *testing.T) {
	paths := []string{
		"internal/handler.go",       // 通常のコード
		"src/App.tsx",               // 通常のコード
		"internal/config/config.go", // "spec" と関係ない
		"specialcase.go",            // "spec" は部分文字列で、ディレクトリ成分ではない
		"internal/inspector/x.go",   // 同上（ディレクトリ名が "inspector"）
		"respected/file.go",         // "spec" の部分文字列を含むが無関係
		"mockingbird/data.go",       // ディレクトリ名は "mockingbird"（"mocks" ではない）
		"seedling/data.go",          // ディレクトリ名は "seedling"（"seed"/"seeds" ではない）
		"testdatabase/x.go",         // ディレクトリ名は "testdatabase"（"testdata" ではない）
		"README.md",
		"user_test_helper.go", // _test.go で終わらない
	}
	for _, p := range paths {
		if isTestPath(p) {
			t.Errorf("isTestPath(%q) = true, want false", p)
		}
	}
}

// jp-bank-account（RequireContext: true, Base: Medium）はテスト経路の Medium 系
// 降格対象。既定の min_confidence=medium では非表示になり、min_confidence=low なら
// 降格後の Low で見える（除外ではなく降格であることの確認）。
func TestPathDemotionDowngradesMediumRequireContextInTestPath(t *testing.T) {
	content := "口座番号: 1234567"

	d := newDetector(t, "")
	assertRules(t, d.ScanContent("testdata/sample.go", content))

	dLow := newDetector(t, `min_confidence = "low"`)
	fs := dLow.ScanContent("testdata/sample.go", content)
	assertRules(t, fs, "jp-bank-account")
	if fs[0].Confidence != rule.Low {
		t.Fatalf("confidence = %v, want low", fs[0].Confidence)
	}
	if !fs[0].Reason.PathDemoted {
		t.Fatal("Reason.PathDemoted = false, want true")
	}
}

// 通常のソースパス（testdata/ 等ではない）では降格しない。
func TestPathDemotionDoesNotAffectNonTestPath(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("src/sample.go", "口座番号: 1234567")
	assertRules(t, fs, "jp-bank-account")
	if fs[0].Confidence != rule.Medium {
		t.Fatalf("confidence = %v, want medium", fs[0].Confidence)
	}
	if fs[0].Reason.PathDemoted {
		t.Fatal("Reason.PathDemoted = true, want false for non-test path")
	}
}

// jp-health-insurance・jp-postal-code の Medium・RequireContext パターンも同様に
// テスト経路で降格する。
func TestPathDemotionAppliesToOtherMediumRequireContextRules(t *testing.T) {
	d := newDetector(t, `min_confidence = "low"`)
	tests := []struct {
		name, file, content, wantRule string
	}{
		{"健康保険", "testdata/sample.go", "保険者番号: 12345678", "jp-health-insurance"},
		// 150-0043 は実在の郵便番号（渋谷区道玄坂）。internal/dict/postal_test.go と同じ値。
		{"郵便番号", "testdata/sample.go", "郵便番号: 150-0043", "jp-postal-code"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanContent(tt.file, tt.content)
			assertRules(t, fs, tt.wantRule)
			if fs[0].Confidence != rule.Low {
				t.Fatalf("confidence = %v, want low (demoted)", fs[0].Confidence)
			}
			if !fs[0].Reason.PathDemoted {
				t.Fatal("Reason.PathDemoted = false, want true")
			}
		})
	}
}

// Base が High 固定の RequireContext ルール（jp-drivers-license 等）はテスト経路でも
// 降格しない。実データがテストパスに混入したときの検出力を落とさないための安全側の設計。
func TestPathDemotionExcludesHighBaseRequireContextRule(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("testdata/sample.go", "免許証番号: 123456789012")
	assertRules(t, fs, "jp-drivers-license")
	if fs[0].Confidence != rule.High {
		t.Fatalf("confidence = %v, want high (not demoted)", fs[0].Confidence)
	}
	if fs[0].Reason.PathDemoted {
		t.Fatal("Reason.PathDemoted = true, want false for Base=high rule")
	}
}

// RequireContext を持たないルール（email-address 等、コンテキストで昇格するだけの
// ルール）はテスト経路でも対象外。
func TestPathDemotionDoesNotAffectRulesWithoutRequireContext(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("testdata/sample.go", "email: user@acme-corp.com")
	assertRules(t, fs, "email-address")
	if fs[0].Confidence != rule.High {
		t.Fatalf("confidence = %v, want high", fs[0].Confidence)
	}
	if fs[0].Reason.PathDemoted {
		t.Fatal("Reason.PathDemoted = true, want false (rule has no RequireContext)")
	}
}

// [rules] path_demotion = false でテスト経路降格自体を無効化できる。
func TestPathDemotionDisabledViaConfig(t *testing.T) {
	d := newDetector(t, "[rules]\npath_demotion = false\n")
	fs := d.ScanContent("testdata/sample.go", "口座番号: 1234567")
	assertRules(t, fs, "jp-bank-account")
	if fs[0].Confidence != rule.Medium {
		t.Fatalf("confidence = %v, want medium (path_demotion disabled)", fs[0].Confidence)
	}
	if fs[0].Reason.PathDemoted {
		t.Fatal("Reason.PathDemoted = true, want false when disabled")
	}
}

// ScanDiffHunk（git diff 走査）でも同じ降格が働く。
func TestPathDemotionAppliesToScanDiffHunk(t *testing.T) {
	lines := []DiffLine{{Text: "口座番号: 1234567", Added: true}}

	d := newDetector(t, "")
	assertRules(t, d.ScanDiffHunk("testdata/sample.go", lines))

	dLow := newDetector(t, `min_confidence = "low"`)
	fs := dLow.ScanDiffHunk("testdata/sample.go", lines)
	assertRules(t, fs, "jp-bank-account")
	if fs[0].Confidence != rule.Low {
		t.Fatalf("confidence = %v, want low", fs[0].Confidence)
	}
	if !fs[0].Reason.PathDemoted {
		t.Fatal("Reason.PathDemoted = false, want true")
	}
}
