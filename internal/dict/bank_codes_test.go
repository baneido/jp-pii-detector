package dict

import "testing"

func TestValidBankCode(t *testing.T) {
	tests := []struct {
		code string
		want bool
	}{
		{"0001", true},
		{"0005", true},
		{"0009", true},
		{"0010", true},
		{"0017", true},
		{"0033", true},
		{"9900", true},
		{"9999", false},
		{"005", false},
		{"00050", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			if got := ValidBankCode(tt.code); got != tt.want {
				t.Errorf("ValidBankCode(%q) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

func TestBankCodesIntegrity(t *testing.T) {
	for code := range bankCodes {
		if len(code) != 4 {
			t.Errorf("銀行コードは4桁でなければならない: %q", code)
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Errorf("銀行コードに数字以外が含まれる: %q", code)
			}
		}
	}
}
