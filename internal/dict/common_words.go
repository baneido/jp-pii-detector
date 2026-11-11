package dict

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed common_words.txt
var commonWordsTxt string

// commonWordSet は IPADIC の一般語（固有名詞を除く）の集合。初回の照合時に作る。
var commonWordSet = sync.OnceValue(func() map[string]bool {
	m := make(map[string]bool, 140000)
	for _, l := range strings.Split(commonWordsTxt, "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			m[l] = true
		}
	}
	return m
})

// IsCommonWord は s が一般語（IPADIC の固有名詞以外の語）かを返す。辞書にない姓名を形だけで
// 受けるとき、「別紙 参照」「同上 同上」のような一般語の組を除くために使う。
func IsCommonWord(s string) bool { return commonWordSet()[foldNameVariants(s)] }
