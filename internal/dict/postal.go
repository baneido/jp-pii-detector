package dict

import (
	"embed"
	"strings"
)

//go:embed postal_prefixes.txt
var postalFS embed.FS

var validPostalPrefixes = loadPostalPrefixes()

func loadPostalPrefixes() map[string]bool {
	data, err := postalFS.ReadFile("postal_prefixes.txt")
	if err != nil {
		panic(err)
	}
	out := map[string]bool{}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out[line] = true
		}
	}
	return out
}

// ValidPostalCodePrefix は 7 桁郵便番号の上位 3 桁が実在するかを返す。
func ValidPostalCodePrefix(postalCode string) bool {
	digits := digitsOnly(postalCode)
	return len(digits) == 7 && validPostalPrefixes[digits[:3]]
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
