package dict

import "testing"

func TestValidTLD(t *testing.T) {
	tests := []struct {
		tld  string
		want bool
	}{
		{"jp", true},
		{"DEV", true},
		{"notatld", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.tld, func(t *testing.T) {
			if got := ValidTLD(tt.tld); got != tt.want {
				t.Errorf("ValidTLD(%q) = %v, want %v", tt.tld, got, tt.want)
			}
		})
	}
}
