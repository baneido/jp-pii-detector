package rule

import "testing"

// このファイルは internal/rule のヘルパー関数（validPhone / validEmail /
// stripSeparators / containsASCIIAlnum）の「現状の振る舞い」を固定する
// 安全網テスト。値は internal/detect/detect_test.go と
// internal/eval/dataset.go の既存ケースから採っており、新しい仕様は
// 発明していない。ルール本体をいじる前のリグレッション検知を目的とする。

// validPhone はマッチ文字列を受け取り、区切り文字（- / 半角スペース）や先頭の "+" を除去した上で、
// 桁数・先頭桁・国番号（+81）規則を満たす電話番号だけを有効とする。
func TestValidPhone(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		// ---- 有効 ----
		{"携帯 区切りあり", "090-1234-5678", true},
		{"携帯 区切りなし", "09012345678", true},
		{"固定 10 桁", "03-1234-5678", true},
		{"IP 電話", "050-1234-5678", true},
		{"国際表記 携帯", "+81-90-1234-5678", true},
		{"国際表記 固定 9 桁", "+81-1-2345-6789", true},
		// ---- 無効 ----
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

// stripSeparators はハイフンと半角スペースのみを除去し、その他の文字
// （'+' を含む）は保持する。
func TestStripSeparators(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"090-1234-5678", "09012345678"},
		{"1234 5678 9018", "123456789018"},
		{"+81-90-1234-5678", "+819012345678"},
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
