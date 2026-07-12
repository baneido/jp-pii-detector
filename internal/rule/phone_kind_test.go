package rule

import "testing"

// このファイルは電話番号ルール（jp-phone-number）の検出値を下位種別に分類する
// PhoneKind（phone_kind.go）のテスト。docs/detection-methods.md の対象外表と
// 実装の不整合（フリーダイヤル等のサービス番号も実際には jp-phone-number として
// 検出される）を解消するための分類機能で、値はいずれも組み立てたダミー値
// （実在しうる番号空間との偶然一致は考慮しない、他の rule テストと同じ方針）。
func TestPhoneKind(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		// ---- service: フリーダイヤル・ナビダイヤル・ダイヤルQ2・テレドーム ----
		{"0120 フリーダイヤル", "0120-333-906", "service"},
		{"0800 フリーダイヤル", "0800-123-4567", "service"},
		{"0570 ナビダイヤル", "0570-064-556", "service"},
		{"0990 ダイヤルQ2", "0990-51-2345", "service"},
		{"0180 テレドーム", "0180-99-1234", "service"},
		// ---- ip: 050 IP電話 ----
		{"050 IP電話", "050-1234-5678", "ip"},
		// ---- mobile: 060/070/080/090 ----
		{"090 携帯", "090-1234-5678", "mobile"},
		{"080 携帯", "080-1234-5678", "mobile"},
		{"070 携帯", "070-1234-5678", "mobile"},
		{"060 は FMC だが mobile 側に分類", "060-1234-5678", "mobile"},
		// ---- fixed: それ以外の固定電話 ----
		{"固定電話（東京 03、区切りあり）", "03-1234-5678", "fixed"},
		{"固定電話（区切りなし）", "0312345678", "fixed"},
		{"固定電話（大阪 06。060 と先頭3桁が異なるため mobile ではない）", "06-6345-1234", "fixed"},
		// ---- international: +81 表記でどの下位分類にも該当しない ----
		{"+81 固定電話は international", "+81-3-1234-5678", "international"},
		// +81 表記でも service/ip/mobile に該当する場合はそちらを優先する。
		{"+81 携帯は mobile を優先", "+81-90-1234-5678", "mobile"},
		{"+81 IP電話は ip を優先", "+81-50-1234-5678", "ip"},
		// ---- 全角由来（PhoneKind に渡る時点では normalize.Line 済みの半角前提） ----
		{"全角由来（呼び出し前に半角化済みの入力を想定）", "080-9876-5432", "mobile"},
		// ---- 裸の "81"（"+" なし）は "+81" と異なり international にフォールバックしない ----
		{"裸の81始まり・携帯相当は mobile", "81-90-1234-5678", "mobile"},
		{"裸の81始まり・固定相当は fixed（+ が無いため international にならない）", "81-3-1234-5678", "fixed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PhoneKind(tt.in); got != tt.want {
				t.Errorf("PhoneKind(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
