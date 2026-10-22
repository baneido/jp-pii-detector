package suppression

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/config"
)

// dummy はダミーの携帯電話番号を実行時に組み立てる（このソース自体が dogfood
// スキャンで検出されないよう、リテラルとしては書かない）。
func dummy(last string) string { return strings.Join([]string{"090", "0000", last}, "-") }

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunAttributesSuppressions(t *testing.T) {
	dir := t.TempDir()
	marker := "jp-pii-detector" + ":ignore"
	writeFile(t, filepath.Join(dir, "a.txt"), strings.Join([]string{
		"電話: " + dummy("0001") + " # " + marker,
		"メモ: 特になし # " + marker, // 何も抑制していないマーカー
		"電話: " + dummy("0002"), // stopwords で抑制
		"電話: " + dummy("0003"), // 報告される
	}, "\n")+"\n")
	writeFile(t, filepath.Join(dir, "skip", "b.txt"), "電話: "+dummy("0004")+"\n")

	cfg, err := config.Parse("[allowlist]\npaths = ['/skip/']\nstopwords = ['" + dummy("0002") + "']\n")
	if err != nil {
		t.Fatal(err)
	}
	rep, warnings, err := Run(cfg, []string{dir}, Options{IncludeFiles: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) > 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	var phone *RuleRow
	for i := range rep.Rules {
		if rep.Rules[i].RuleID == "jp-phone-number" {
			phone = &rep.Rules[i]
		}
	}
	if phone == nil {
		t.Fatalf("jp-phone-number の行がない: %+v", rep.Rules)
	}
	want := RuleRow{RuleID: "jp-phone-number", Reported: 1, IgnoredByMarker: 1, AllowlistPaths: 1, AllowlistStopwords: 1}
	if *phone != want {
		t.Errorf("got %+v, want %+v", *phone, want)
	}
	if rep.MarkerLines[marker] != 2 || rep.StaleMarkerLines != 1 || rep.FilesWithMarkers != 1 {
		t.Errorf("marker stats: lines=%v stale=%d files=%d", rep.MarkerLines, rep.StaleMarkerLines, rep.FilesWithMarkers)
	}
	if len(rep.Files) != 1 || rep.Files[0].MarkerLines != 2 {
		t.Errorf("files: %+v", rep.Files)
	}
	entries := map[string]int{}
	for _, e := range rep.Allowlist {
		entries[e.Entry] = e.Findings
	}
	if entries["paths: /skip/"] != 1 || entries["stopwords[0]"] != 1 {
		t.Errorf("allowlist entries: %+v", rep.Allowlist)
	}

	// 出力にマッチ値（ダミーでも）が含まれないこと。stopwords は要素番号で出す。
	for _, write := range []func(*bytes.Buffer) error{
		func(b *bytes.Buffer) error { return WriteMarkdown(b, rep) },
		func(b *bytes.Buffer) error { return WriteJSON(b, rep) },
	} {
		var b bytes.Buffer
		if err := write(&b); err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{"0001", "0002", "0003", "0004"} {
			if strings.Contains(b.String(), v) {
				t.Errorf("出力にマッチ値の一部 %q が含まれる", v)
			}
		}
	}
}

func TestBlankMarkerTokenBoundary(t *testing.T) {
	tests := []struct {
		line, marker string
		found        bool
	}{
		{"x # pii-allow", "pii-allow", true},
		{"pii-allowlist.txt", "pii-allow", false},
		{"a jp-pii-detector:ignore b", "jp-pii-detector:ignore", true},
		{"xjp-pii-detector:ignore", "jp-pii-detector:ignore", false},
	}
	for _, tt := range tests {
		got, found := blankMarker(tt.line, tt.marker)
		if found != tt.found {
			t.Errorf("blankMarker(%q) found=%v, want %v", tt.line, found, tt.found)
		}
		if len(got) != len(tt.line) {
			t.Errorf("blankMarker(%q) が長さを変えた: %q", tt.line, got)
		}
		if found && strings.Contains(got, tt.marker) {
			t.Errorf("blankMarker(%q) がマーカーを残した: %q", tt.line, got)
		}
	}
}
