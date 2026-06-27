package dict

import (
	"iter"
	"strings"
	"testing"
)

func mustRead(name string) string {
	data, err := namesFS.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return string(data)
}

// splitLines は loadNameSet と同じ規則（# 行・空行を除く）で有効な行を列挙する。
func splitLines(raw string) iter.Seq[string] {
	return func(yield func(string) bool) {
		for line := range strings.SplitSeq(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !yield(line) {
				return
			}
		}
	}
}

// TestNameDictIntegrity は姓名辞書の整合性を保証する（ファイル内重複・
// 姓名の相互重複がないこと）。macOS の BSD comm/sort/uniq は CJK で誤検出
// するため、シェルではなく Go で確実に検査する。
func TestNameDictIntegrity(t *testing.T) {
	dupCheck := func(name, raw string) {
		// map は重複を吸収するため、生データを再走査して重複行を検出する。
		seen := map[string]bool{}
		for line := range splitLines(raw) {
			if seen[line] {
				t.Errorf("%s に重複エントリ: %q", name, line)
			}
			seen[line] = true
		}
	}
	dupCheck("surnames.txt", mustRead("surnames.txt"))
	dupCheck("given_names.txt", mustRead("given_names.txt"))

	for s := range surnames {
		if givenNames[s] {
			t.Errorf("%q が姓・名の両方に収録されている（どちらかに統一すること）", s)
		}
	}
}

func TestIsSurnameAndGivenName(t *testing.T) {
	if !IsSurname("山田") {
		t.Errorf("IsSurname(山田) = false, want true")
	}
	if IsSurname("太郎") {
		t.Errorf("IsSurname(太郎) = true, want false")
	}
	if !IsGivenName("太郎") {
		t.Errorf("IsGivenName(太郎) = false, want true")
	}
	if IsGivenName("山田") {
		t.Errorf("IsGivenName(山田) = true, want false")
	}
}

func TestIsPersonName(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		// 単独の姓・名
		{"山田", true},
		{"高橋", true},
		{"太郎", true},
		{"花子", true},
		// 姓 + 名（区切りなし）
		{"山田太郎", true},
		{"高橋健太", true},
		{"佐藤花子", true},
		// 姓 + 名（空白区切り）
		{"山田 太郎", true},
		{"佐藤　花子", true}, // 全角スペース
		// 非人名（組織・一般名詞）
		{"田中商事", false},
		{"山田商事株式会社", false},
		{"一覧", false},
		{"重要", false},
		{"", false},
		// 3 要素以上の空白区切りは不可
		{"山田 太郎 様", false},
		// 名 + 姓 の順は不可（姓 + 名のみ）
		{"太郎山田", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := IsPersonName(tt.in); got != tt.want {
				t.Errorf("IsPersonName(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestExpandedNameDictionaryExamples(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"一ノ瀬", true},
		{"越智", true},
		{"凪沙", true},
		{"伊織", true},
		{"越智凪沙", true},
		{"一ノ瀬 伊織", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := IsPersonName(tt.in); got != tt.want {
				t.Errorf("IsPersonName(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
