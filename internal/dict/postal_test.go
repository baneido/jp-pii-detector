package dict

import "testing"

func TestValidPostalCodePrefix(t *testing.T) {
	tests := []struct {
		code string
		want bool
	}{
		{"150-0043", true},
		{"〒530-0001", true},
		{"000-0000", false},
		{"150-004", false},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			if got := ValidPostalCodePrefix(tt.code); got != tt.want {
				t.Errorf("ValidPostalCodePrefix(%q) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}
