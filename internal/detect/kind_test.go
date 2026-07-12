package detect

import "testing"

// このファイルは Rule.Kind（internal/rule）による下位種別分類と
// [rules] exclude_kinds（internal/config）による除外の、ルールをまたいだ挙動を
// 確認する。jp-phone-number 固有の分類（PhoneKind）は detect_test.go の
// TestPhoneKindDefaultReportsBothWithReasonKind / TestPhoneKindExcludeKinds が、
// jp-invoice-number 固有の分類（PublicBusinessKind、internal/rule/identifier_kind.go）は
// このファイルが担当する。detect_test.go 自体は .jp-pii.toml の allowlist で
// dogfooding から除外されているため既存の PII 形サンプルにマーカーが無いが、
// このファイルは対象外のため、値を持つ行には jp-pii-detector:ignore を付けている。

// invoiceKindSampleValue は T + 13 桁の適格請求書発行事業者登録番号のダミー値。
// 基礎番号 555666777888（法人番号と同じ 12 桁）に対し、checksum.CorporateNumber
// （internal/checksum、法人番号の検査用数字アルゴリズム）を満たす検査用数字 1 を
// 総当たりで求めて自作した（実在の登録番号との一致は意図していない）。
const invoiceKindSampleValue = "T1555666777888" // jp-pii-detector:ignore ダミー登録番号

// phoneKindSampleValue は jp-phone-number の携帯番号パターンに一致するダミー値
// （detect_test.go の TestPhoneKindDefaultReportsBothWithReasonKind と同じ値）。
const phoneKindSampleValue = "090-1234-5678" // jp-pii-detector:ignore ダミー電話番号

// TestInvoiceNumberKindIsPublicBusiness は適格請求書発行事業者登録番号
// （jp-invoice-number）の検出結果に Reason.Kind="public-business" が記録されることを
// 確認する。登録番号は国税庁の公表サイトで公開される情報であり、マイナンバー等の
// 機微な PII と同列に扱わずオプトアウトできるようにするための分類。
func TestInvoiceNumberKindIsPublicBusiness(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanLine("f.txt", 1, "登録番号: "+invoiceKindSampleValue)
	assertRules(t, fs, "jp-invoice-number")
	if fs[0].Reason.Kind != "public-business" {
		t.Errorf("Reason.Kind = %q, want %q", fs[0].Reason.Kind, "public-business")
	}
}

// TestInvoiceNumberKindExcludeKindsDoesNotAffectPhone は
// [rules] exclude_kinds = ["public-business"] を設定すると jp-invoice-number
// （Reason.Kind="public-business"）だけが除外され、kind の語彙が衝突しない
// jp-phone-number（PhoneKind の mobile 等）は従来どおり検出されることを確認する。
func TestInvoiceNumberKindExcludeKindsDoesNotAffectPhone(t *testing.T) {
	d := newDetector(t, `
[rules]
exclude_kinds = ["public-business"]
`)

	fs := d.ScanLine("f.txt", 1, "登録番号: "+invoiceKindSampleValue)
	assertRules(t, fs) // public-business は除外され検出なし

	fs = d.ScanLine("f.txt", 1, "電話: "+phoneKindSampleValue)
	assertRules(t, fs, "jp-phone-number") // exclude_kinds に無い kind は影響を受けない
}
