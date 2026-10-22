package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelpAndBadFormat(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--help"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "使い方") {
		t.Fatalf("--help: code=%d out=%q", code, out.String())
	}
	out.Reset()
	if code := run([]string{"--format", "sarif"}, &out, &errOut); code != 2 {
		t.Fatalf("unknown format: code=%d", code)
	}
}

func TestRunJSONOnEmptyDir(t *testing.T) {
	var out, errOut bytes.Buffer
	dir := t.TempDir()
	if code := run([]string{"--format", "json", dir}, &out, &errOut); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"stale_marker_lines": 0`) {
		t.Fatalf("unexpected json: %s", out.String())
	}
}
