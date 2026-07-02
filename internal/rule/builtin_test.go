package rule

import (
	"testing"

	"github.com/baneido/jp-pii-detector/internal/piifixtures"
)

// このファイルは internal/rule のヘルパー関数（validPhone / validEmail /
// stripSeparators / containsASCIIAlnum）の「現状の振る舞い」を固定する
// 安全網テスト。値は internal/detect/detect_test.go と
// internal/eval/dataset.go の既存ケースから採っており、新しい仕様は
// 発明していない。ルール本体をいじる前のリグレッション検知を目的とする。

// validPhone はマッチ文字列を受け取り、区切り文字（- / 半角スペース）や先頭の "+" を除去した上で、
// 桁数・先頭桁・国番号（+81）規則を満たす電話番号だけを有効とする。
func TestValidPhone(t *testing.T) {
	piifixtures.Require(t)
	tests := []struct {
		name string
		in   string
		want bool
	}{
		// ---- 有効（実在形式の値はフィクスチャから取得）----
		{"携帯 区切りあり", piifixtures.MustGet(t, "rule.phone_mobile_sep"), true},
		{"携帯 区切りなし", piifixtures.MustGet(t, "rule.phone_mobile_nosep"), true},
		{"固定 10 桁", piifixtures.MustGet(t, "rule.phone_landline_sep"), true},
		{"IP 電話", piifixtures.MustGet(t, "rule.phone_ip_sep"), true},
		{"国際表記 携帯", piifixtures.MustGet(t, "rule.phone_mobile_intl"), true},
		{"国際表記 固定 9 桁", piifixtures.MustGet(t, "rule.phone_landline_intl"), true},
		// ---- 無効（意図的に不正な値・実在 PII ではないため inline）----
		{"桁数不正（9 桁）", "0123-456-78", false},
		{"第 2 桁が 0", "00-1234-5678", false},
		{"11 桁の固定様式は実在しない", "0123-456-7890", false},
		{"国際表記 +81 + 10 桁で携帯以外は不正", "+81-12-3456-7890", false},
		{"全桁同一はダミー値として棄却", "00000000000", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validPhone(tt.in); got != tt.want {
				t.Errorf("validPhone(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// validEmail は予約済みドメイン（RFC 2606/6761）・未登録 TLD・ローカル部の
// 不正なドット配置などのダミー値を除外する。
func TestValidEmail(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		// ---- 有効 ----
		{"通常", "taro.yamada@gmail.com", true},
		{"ドット・プラス・サブドメイン", "user.name+tag@sub-domain.company.co.jp", true},
		{"IANA 登録済み TLD", "user@service.dev", true},
		// ---- 無効: 予約済みドメイン/TLD ----
		{"example ラベルは除外", "user@example.com", false},
		{"サブドメインの example も除外", "user@sub.example.co.jp", false},
		{"予約 TLD test", "user@foo.test", false},
		{"予約 TLD invalid", "user@foo.invalid", false},
		{"予約 TLD localhost", "user@foo.localhost", false},
		{"予約 TLD local", "user@host.local", false},
		{"未登録 TLD", "user@service.notatld", false},
		// ---- 無効: ローカル部 ----
		{"連続ドット", "taro..yamada@gmail.com", false},
		{"先頭ドット", ".taro@gmail.com", false},
		{"末尾ドット", "taro.@gmail.com", false},
		{"英数字を含まないローカル部", "_@gmail.com", false},
		// ---- 無効: ドメインのラベル境界 ----
		{"ラベル先頭のハイフン", "user@-foo.com", false},
		{"ラベル末尾のハイフン", "user@foo-.com", false},
		// ---- 無効: 構造不正（防御的ガード）----
		{"@ が先頭", "@gmail.com", false},
		{"@ が末尾", "user@", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validEmail(tt.in); got != tt.want {
				t.Errorf("validEmail(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// validBirthdate は形式が成立する生年月日のうち、実在する暦日だけを有効とする。
// 西暦・和暦の双方で、無効な月日（暦上ありえない値）と和暦の元号年範囲外を棄却する。
func TestValidBirthdate(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		// ---- 有効: 西暦 ----
		{"西暦 ハイフン", "2023-03-15", true},
		{"西暦 年月日", "2000年1月1日", true},
		{"西暦 スラッシュ", "1995/12/31", true},
		{"閏年の2月29日", "2000-02-29", true},
		// ---- 無効: 西暦の暦日 ----
		{"月が99", "2023-99-99", false},
		{"非閏年の2月29日", "2023-02-29", false},
		{"100で割れる非閏年(1900)の2月29日", "1900-02-29", false},
		{"13月", "2023-13-01", false},
		{"0月", "2023-00-10", false},
		{"4月31日", "2023-04-31", false},
		{"0日", "2023-05-00", false},
		// ---- 有効: 和暦 ----
		{"平成 元号年", "平成5年4月1日", true},
		{"令和", "令和3年12月31日", true},
		{"昭和の最終年(64)", "昭和64年1月1日", true},
		// ---- 無効: 和暦の元号年範囲外 ----
		{"昭和65年は存在しない", "昭和65年1月1日", false},
		{"平成32年は存在しない", "平成32年1月1日", false},
		{"大正16年は存在しない", "大正16年1月1日", false},
		// ---- 無効: 和暦でも暦日が不正 ----
		{"和暦で2月30日", "令和2年2月30日", false},
		// ---- 有効: 元号の単字アルファベット略記（免許証・保険証転記で一般的）----
		{"昭和 単字略記 ドット区切り", "S60.1.2", true},
		{"平成 単字略記 スラッシュ区切り", "H5/4/1", true},
		{"明治 単字略記の最終年", "M45.7.30", true},
		// ---- 有効: 元年（改元年）表記 ----
		{"令和元年", "令和元年5月1日", true},
		{"平成元年", "平成元年1月8日", true},
		{"単字略記 + 元年", "R元.5.1", true},
		// ---- 無効: 元号の単字アルファベット略記だが範囲外・非対応 ----
		{"単字略記 昭和65年は存在しない", "S65.1.1", false},
		{"未対応の単字略記", "X60.1.1", false},
		// ---- 有効: 区切りなし8桁（YYYYMMDD）----
		{"区切りなし8桁", "19850102", true},
		{"区切りなし8桁 西暦2000年代", "20230315", true},
		// ---- 無効: 区切りなし8桁だが暦日が不正 ----
		{"区切りなし8桁 存在しない2月30日", "20230230", false},
		{"区切りなし8桁 月が13", "20231301", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validBirthdate(tt.in); got != tt.want {
				t.Errorf("validBirthdate(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// stripSeparators はハイフンと半角スペースのみを除去し、その他の文字
// （'+' を含む）は保持する。
func TestStripSeparators(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"000-0000-0000", "00000000000"},
		{"1234 5678 9018", "123456789018"},
		{"+81-90-0000-0000", "+819000000000"},
		{"AB12345678CD", "AB12345678CD"},
		{"", ""},
		{"- -", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := stripSeparators(tt.in); got != tt.want {
				t.Errorf("stripSeparators(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// containsASCIIAlnum はローカル部に ASCII 英数字が 1 文字以上あるかを返す。
func TestContainsASCIIAlnum(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"taro", true},
		{"user.name+tag", true},
		{"123", true},
		{"", false},
		{"___", false},
		{".+%-", false},
		{"あいう", false}, // マルチバイト非 ASCII は英数字とみなさない
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := containsASCIIAlnum(tt.in); got != tt.want {
				t.Errorf("containsASCIIAlnum(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
