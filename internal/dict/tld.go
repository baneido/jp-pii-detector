// Package dict は実在性検証に使う小さな静的辞書を提供する。
package dict

import (
	"embed"
	"strings"
)

//go:embed tlds-alpha-by-domain.txt
var tldFS embed.FS

var validTLDs = loadTLDs()

func loadTLDs() map[string]bool {
	data, err := tldFS.ReadFile("tlds-alpha-by-domain.txt")
	if err != nil {
		panic(err)
	}
	out := map[string]bool{}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[strings.ToLower(line)] = true
	}
	return out
}

// ValidTLD は IANA の root zone database に存在する TLD かを返す。
func ValidTLD(tld string) bool {
	return validTLDs[strings.ToLower(tld)]
}
