package main

import (
	"flag"
	"slices"
	"testing"
)

// TestReorderArgs は位置引数の順序を保ちつつ、既知の bool/value フラグだけを
// 前方へ移動することと、"--" 以降には一切手を加えないことを直接検証する。
func TestReorderArgs(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Bool("bool", false, "")
	fs.String("value", "", "")

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "未定義フラグ風トークンと後続値は位置引数",
			args: []string{"path-a", "-weird.txt", "value", "--bool", "path-b"},
			want: []string{"--bool", "--", "path-a", "-weird.txt", "value", "path-b"},
		},
		{
			name: "値ありフラグ",
			args: []string{"path-a", "--value", "json", "path-b"},
			want: []string{"--value", "json", "--", "path-a", "path-b"},
		},
		{
			name: "等号形式の値ありフラグ",
			args: []string{"path-a", "--value=json", "path-b"},
			want: []string{"--value=json", "--", "path-a", "path-b"},
		},
		{
			name: "double dash以降はすべて位置引数",
			args: []string{"path-a", "--", "--bool", "-weird.txt"},
			want: []string{"--", "path-a", "--bool", "-weird.txt"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reorderArgs(fs, tt.args); !slices.Equal(got, tt.want) {
				t.Errorf("reorderArgs(%q) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}
