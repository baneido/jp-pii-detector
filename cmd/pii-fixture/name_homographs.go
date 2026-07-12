package main

import (
	"fmt"
	"io"
	"sort"
	"unicode"

	"github.com/baneido/jp-pii-detector/internal/dict"
	"github.com/baneido/jp-pii-detector/internal/evalcase"
	"github.com/baneido/jp-pii-detector/internal/privatecorpus"
)

type homographCandidate struct {
	Value, Surname, Given string
	Count                 int
}

// runNameHomographs は R01 の非公開コーパスのうち、期待 finding を 1 件も持たない
// 陰性ケースだけから「姓+名」に分割できる漢字列を頻度順に抽出する。出力は候補で
// あって自動 denylist ではない。実在人名との衝突を人手確認してから
// internal/dict/name_homographs.txt へ採用する。
func runNameHomographs(minCount, maxRunes int, stdout io.Writer) error {
	corpus, configured, err := privatecorpus.FromEnv()
	if err != nil {
		return err
	}
	if !configured {
		return fmt.Errorf("%s を設定してください", privatecorpus.EnvVar)
	}
	candidates := collectNameHomographs(corpus.Dataset, minCount, maxRunes)
	fmt.Fprintln(stdout, "count\tcandidate\tsurname\tgiven")
	for _, c := range candidates {
		fmt.Fprintf(stdout, "%d\t%s\t%s\t%s\n", c.Count, c.Value, c.Surname, c.Given)
	}
	return nil
}

func collectNameHomographs(cases []evalcase.Case, minCount, maxRunes int) []homographCandidate {
	type split struct{ surname, given string }
	counts := map[string]int{}
	splits := map[string]split{}
	for _, c := range cases {
		// Want/Spans のある陽性ケースは実在人名を候補へ混ぜうるため走査しない。
		if len(c.Want) != 0 || len(c.Spans) != 0 {
			continue
		}
		texts := []string{c.Line, c.Content}
		for _, dl := range c.Diff {
			texts = append(texts, dl.Text)
		}
		for _, text := range texts {
			for _, candidate := range nameSplitSubstrings(text, maxRunes) {
				surname, given, ok := dict.SplitFullNameCandidate(candidate)
				if !ok {
					continue
				}
				counts[candidate]++
				splits[candidate] = split{surname, given}
			}
		}
	}
	out := make([]homographCandidate, 0, len(counts))
	for value, count := range counts {
		if count < minCount {
			continue
		}
		s := splits[value]
		out = append(out, homographCandidate{Value: value, Surname: s.surname, Given: s.given, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func nameSplitSubstrings(text string, maxRunes int) []string {
	rs := []rune(text)
	var out []string
	for start := 0; start < len(rs); {
		if !unicode.Is(unicode.Han, rs[start]) {
			start++
			continue
		}
		end := start
		for end < len(rs) && unicode.Is(unicode.Han, rs[end]) {
			end++
		}
		for i := start; i < end; i++ {
			limit := end
			if i+maxRunes < limit {
				limit = i + maxRunes
			}
			for j := i + 3; j <= limit; j++ {
				out = append(out, string(rs[i:j]))
			}
		}
		start = end
	}
	return out
}
