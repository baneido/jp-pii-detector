package dict

import (
	"testing"
)

func mustReadBankNames(t *testing.T) string {
	t.Helper()
	data, err := bankNamesFS.ReadFile("bank_names.txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestBankNameDictIntegrity は銀行名辞書の整合性（ファイル内重複がないこと）を保証する。
func TestBankNameDictIntegrity(t *testing.T) {
	seen := map[string]bool{}
	for line := range splitLines(mustReadBankNames(t)) {
		if seen[line] {
			t.Errorf("bank_names.txt に重複エントリ: %q", line)
		}
		seen[line] = true
	}
	if len(seen) == 0 {
		t.Fatal("bank_names.txt にエントリが 1 件もない")
	}
}

func TestIsBankName(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"三菱UFJ銀行", true},
		{"みずほ銀行", true},
		{"ゆうちょ銀行", true},
		{"京都銀行", true},
		{"楽天銀行", true},
		{"中央労働金庫", true},
		{"京都信用金庫", true},
		// 収録外（代表サブセットのため false になりうる）
		{"架空銀行", false},
		{"三菱UFJ", false}, // サフィックスなしの部分文字列は不一致
		{"", false},
		// 業態サフィックスの取り違え（辞書はサフィックス込みの完全一致）
		{"京都労働金庫", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := IsBankName(tt.in); got != tt.want {
				t.Errorf("IsBankName(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
