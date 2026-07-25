// Package dict は実在性検証に使う小さな静的辞書を提供する。
package dict

import (
	"embed"
	"strings"
	"sync"
)

//go:embed tlds-alpha-by-domain.txt
var tldFS embed.FS

// tldSet は TLD 一覧の遅延ロード（sync.OnceValue）。パッケージ変数の初期化で
// マップ化すると、TLD 判定を一切使わないプロセス（version サブコマンド等）でも
// 起動時に必ずコストを払うことになるため、初回参照時に一度だけ構築する。
// sync.OnceValue は並行安全なので、並列走査のワーカーから同時に呼んでもよい。
var tldSet = sync.OnceValue(loadTLDs)

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
	return tldSet()[strings.ToLower(tld)]
}
