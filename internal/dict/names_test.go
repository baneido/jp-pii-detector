package dict

import (
	"iter"
	"reflect"
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

// TestSurnameSampleAndGivenNameSample は SurnameSample/GivenNameSample が
// 辞書に実在する値だけを、決定的な順序・重複なしで返すことを検証する
// （internal/fixturegen が計算合成の材料として使う列挙用エクスポート関数）。
func TestSurnameSampleAndGivenNameSample(t *testing.T) {
	s1 := SurnameSample(10)
	s2 := SurnameSample(10)
	if len(s1) != 10 {
		t.Fatalf("len(SurnameSample(10)) = %d, want 10", len(s1))
	}
	if !reflect.DeepEqual(s1, s2) {
		t.Fatalf("SurnameSample(10) is not deterministic: %v != %v", s1, s2)
	}
	seen := map[string]bool{}
	for _, s := range s1 {
		if !IsSurname(s) {
			t.Errorf("SurnameSample returned %q, which is not in the surname dictionary", s)
		}
		if seen[s] {
			t.Errorf("SurnameSample returned duplicate %q", s)
		}
		seen[s] = true
	}

	g1 := GivenNameSample(10)
	for _, g := range g1 {
		if !IsGivenName(g) {
			t.Errorf("GivenNameSample returned %q, which is not in the given-name dictionary", g)
		}
	}

	// n が辞書サイズを超えたら全件（パニックしない）。
	all := SurnameSample(1 << 30)
	if len(all) == 0 || len(all) != len(surnameList) {
		t.Fatalf("SurnameSample(oversized) len = %d, want %d (full dictionary)", len(all), len(surnameList))
	}
	if got := SurnameSample(0); got != nil {
		t.Fatalf("SurnameSample(0) = %v, want nil", got)
	}
	if got := SurnameSample(-1); got != nil {
		t.Fatalf("SurnameSample(-1) = %v, want nil", got)
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

// TestMatchPersonNameMinimalComponentConstraint は issue #59 段階1: 区切りなし
// （空白なし）の姓+名分割で、姓・名の両方が 1 ルーンになる分割を不成立とすることを
// 確認する。関心=関+心、東大=東+大、森永=森+永 はいずれも姓・名の各要素が単独で
// 辞書に載るため、この制約がないと人名分割が成立してしまう（実測の誤検出）。
// 関心・東大は分割以外の根拠も持たないため MatchPersonName も NoMatch になる。
// 森永は分割とは独立に姓の辞書へ直接収録されている実在の姓（例: 森永製菓）でも
// あるため、分割不成立の確認は SplitsAsFullName で行う（MatchPersonName は
// 単独の姓一致として SurnameOnly のまま）。
func TestMatchPersonNameMinimalComponentConstraint(t *testing.T) {
	for _, in := range []string{"関心", "東大"} {
		t.Run(in, func(t *testing.T) {
			if got := MatchPersonName(in); got != NoMatch {
				t.Errorf("MatchPersonName(%q) = %v, want NoMatch", in, got)
			}
			if SplitsAsFullName(in) {
				t.Errorf("SplitsAsFullName(%q) = true, want false", in)
			}
		})
	}
	if SplitsAsFullName("森永") {
		t.Errorf(`SplitsAsFullName("森永") = true, want false（分割（森+永）は不成立。単独の姓一致とは別）`)
	}
	// 空白区切りは 1 ルーン同士でも従来どおり分割を許可する（明示的な区切りがあり、
	// 単独の 1 文字姓+1 文字名の実在人名を取りこぼさないため）。
	if !SplitsAsFullName("林 学") {
		t.Errorf(`SplitsAsFullName("林 学") = false, want true`)
	}
}

// TestNonPersonHomographDenylist は山田錦（酒米の品種名）のように、姓+名の
// 分割自体は辞書上成立してしまう非人名の固有名詞が denylist で除外されることを
// 確認する（issue #59 段階1）。山田（姓・2 ルーン）+ 錦（名・1 ルーン）は
// 「両方 1 ルーン」制約の対象外のため、分割ループ単体では弾けない。
func TestNonPersonHomographDenylist(t *testing.T) {
	if got := MatchPersonName("山田錦"); got != NoMatch {
		t.Errorf("MatchPersonName(山田錦) = %v, want NoMatch", got)
	}
	if IsPersonName("山田錦") {
		t.Errorf("IsPersonName(山田錦) = true, want false")
	}
}

// TestMatchPersonNameSurnameOnlyHomographs は地名・企業名と同形の姓
// （渋谷・大和・本田）が SurnameOnly（単独の姓一致）と判定され、FullNameSplit
// とは区別されることを確認する（issue #59 段階1: 呼び出し側が判定根拠に応じて
// 信頼度を作り分けるための前提）。
func TestMatchPersonNameSurnameOnlyHomographs(t *testing.T) {
	for _, in := range []string{"渋谷", "大和", "本田"} {
		t.Run(in, func(t *testing.T) {
			if got := MatchPersonName(in); got != SurnameOnly {
				t.Errorf("MatchPersonName(%q) = %v, want SurnameOnly", in, got)
			}
			// 単独の姓一致は IsPersonName としては引き続き true（後方互換）。
			if !IsPersonName(in) {
				t.Errorf("IsPersonName(%q) = false, want true", in)
			}
		})
	}
}

// TestMatchPersonNameFullNameSplit は「姓 + 名」に分割できる完全な氏名が
// FullNameSplit と判定されることを確認する（SurnameOnly/GivenOnly との判定
// 根拠の違いを固定する回帰テスト）。
func TestMatchPersonNameFullNameSplit(t *testing.T) {
	for _, in := range []string{"山田太郎", "山田 太郎", "越智凪沙"} {
		t.Run(in, func(t *testing.T) {
			if got := MatchPersonName(in); got != FullNameSplit {
				t.Errorf("MatchPersonName(%q) = %v, want FullNameSplit", in, got)
			}
		})
	}
}
