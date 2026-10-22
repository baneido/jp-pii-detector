package suppression

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// WriteJSON は Report を整形 JSON で書き出す。
func WriteJSON(w io.Writer, rep Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// WriteMarkdown は Issue やジョブサマリにそのまま貼れる Markdown を書き出す。
// ルール ID と件数だけで、マッチ値は含まない。
func WriteMarkdown(w io.Writer, rep Report) error {
	var b strings.Builder
	b.WriteString("### 抑制の利用状況（ルール別）\n\n")
	if len(rep.Rules) == 0 {
		b.WriteString("検出も抑制もありませんでした。\n")
	} else {
		b.WriteString("| rule | 報告 | ignore マーカー | allowlist paths | allowlist regexes | allowlist stopwords | その他 | 抑制率 |\n")
		b.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|\n")
		for _, r := range rep.Rules {
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d | %d | %.0f%% |\n",
				r.RuleID, r.Reported, r.IgnoredByMarker, r.AllowlistPaths, r.AllowlistRegexes,
				r.AllowlistStopwords, r.AllowlistOther, 100*r.SuppressionRate())
		}
	}
	b.WriteString("\n### ignore マーカー\n\n")
	markers := make([]string, 0, len(rep.MarkerLines))
	for m := range rep.MarkerLines {
		markers = append(markers, m)
	}
	sort.Strings(markers)
	fmt.Fprintf(&b, "- マーカーを含むファイル: %d\n", rep.FilesWithMarkers)
	for _, m := range markers {
		fmt.Fprintf(&b, "- `%s` の行: %d\n", m, rep.MarkerLines[m])
	}
	fmt.Fprintf(&b, "- 外しても何も検出されない（不要になった可能性がある）行: %d\n", rep.StaleMarkerLines)
	if len(rep.Allowlist) > 0 {
		b.WriteString("\n### allowlist の要素別\n\n| 要素 | 抑制件数 | 内訳 |\n|---|---:|---|\n")
		for _, e := range rep.Allowlist {
			fmt.Fprintf(&b, "| %s | %d | %s |\n", escapeCell(e.Entry), e.Findings, byRule(e.ByRule))
		}
	}
	if len(rep.Files) > 0 {
		b.WriteString("\n### マーカー行の多いファイル\n\n| ファイル | 行数 |\n|---|---:|\n")
		for _, f := range rep.Files {
			fmt.Fprintf(&b, "| %s | %d |\n", escapeCell(f.Path), f.MarkerLines)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func byRule(m map[string]int) string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if m[ids[i]] != m[ids[j]] {
			return m[ids[i]] > m[ids[j]]
		}
		return ids[i] < ids[j]
	})
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%s: %d", id, m[id])
	}
	return strings.Join(parts, ", ")
}

func escapeCell(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s)
}
