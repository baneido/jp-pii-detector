package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/transform"
)

func TestHiraganaToKatakana(t *testing.T) {
	tests := []struct{ in, want string }{
		{"さとう", "サトウ"},
		{"やまだたろう", "ヤマダタロウ"},
		{"ほづみ", "ホヅミ"},       // 濁点つき（だ行）
		{"ちょうそかべ", "チョウソカベ"}, // 拗音（小書き）
		{"ー", "ー"},           // 長音記号は範囲外のためそのまま
		{"", ""},
	}
	for _, tt := range tests {
		if got := hiraganaToKatakana(tt.in); got != tt.want {
			t.Errorf("hiraganaToKatakana(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestReadLastNames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "last_name_org.csv")
	csv := "佐藤,1887000,さとう,satou\n鈴木,1806000,すずき,suzuki\n"
	if err := os.WriteFile(path, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err := readLastNames(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if rows[0].Kanji != "佐藤" || rows[0].Hiragana != "さとう" || rows[0].Romaji != "satou" {
		t.Errorf("rows[0] = %+v, want {佐藤 さとう satou}", rows[0])
	}
}

func TestReadGivenNames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "first_name_man_opti.csv")
	csv := "たろう,tarou,太郎,太朗\nはなこ,hanako,花子\n"
	if err := os.WriteFile(path, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err := readGivenNames(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if rows[0].Hiragana != "たろう" || rows[0].Romaji != "tarou" {
		t.Errorf("rows[0] = %+v, want {たろう tarou}", rows[0])
	}
}

func TestAppendUniqueLinesIsIdempotentAndAdditive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "surnames.txt")
	if err := os.WriteFile(path, []byte("# header\n佐藤\n鈴木\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	header := "# カタカナ読み\n"
	if err := appendUniqueLines(path, header, []string{"サトウ", "スズキ", "サトウ"}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "# header\n佐藤\n鈴木\n" + header + "サトウ\nスズキ\n"
	if string(got) != want {
		t.Fatalf("content after first append = %q, want %q", got, want)
	}

	// 既存エントリのみを渡して再実行しても、ファイルは変化しない
	// （ヘッダーが重複挿入されない・既存行が増えない）。
	if err := appendUniqueLines(path, header, []string{"サトウ", "スズキ"}); err != nil {
		t.Fatal(err)
	}
	got2, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got2) != want {
		t.Fatalf("content after rerun changed: got %q, want unchanged %q", got2, want)
	}
}

func TestAppendUniqueLinesCreatesNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "romaji_surnames.txt")

	header := "# ローマ字姓\n"
	if err := appendUniqueLines(path, header, []string{"suzuki", "satou"}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := header + "satou\nsuzuki\n"
	if string(got) != want {
		t.Fatalf("content = %q, want %q", got, want)
	}
}

func TestAppendUniqueLinesNoOpWhenNothingNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "given_names.txt")
	original := "# header\nサクラ\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := appendUniqueLines(path, "# カタカナ読み\n", []string{"サクラ"}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("file changed when no new entries were given: got %q, want %q", got, original)
	}
}

func TestExcludeSurnames(t *testing.T) {
	surnames := map[string]bool{"サトウ": true, "スズキ": true}
	got := excludeSurnames([]string{"サトウ", "ハナコ", "スズキ", "タロウ"}, surnames)
	want := []string{"ハナコ", "タロウ"}
	if len(got) != len(want) {
		t.Fatalf("got = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got = %v, want %v", got, want)
		}
	}
}

func TestReadIPADICFourRuneSurnames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Noun.name.csv")
	utf8Body := strings.Join([]string{
		"勅使河原,1,1,1,名詞,固有名詞,人名,姓,*,*,勅使河原,テシガワラ,テシガワラ",
		"小比類巻,1,1,1,名詞,固有名詞,人名,姓,*,*,小比類巻,コヒルイマキ,コヒルイマキ",
		"佐々木,1,1,1,名詞,固有名詞,人名,姓,*,*,佐々木,ササキ,ササキ",           // 3文字なので除外
		"武者小路,1,1,1,名詞,固有名詞,人名,名,*,*,武者小路,ムシャノコウジ,ムシャノコージ", // 名なので除外
		"テシガワラ,1,1,1,名詞,固有名詞,人名,姓,*,*,テシガワラ,テシガワラ,テシガワラ",   // 漢字表層でないため除外
	}, "\n") + "\n"
	body, _, err := transform.Bytes(japanese.EUCJP.NewEncoder(), []byte(utf8Body))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readIPADICFourRuneSurnames(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"勅使河原", "テシガワラ", "小比類巻", "コヒルイマキ"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("readIPADICFourRuneSurnames() = %v, want %v", got, want)
	}
}

func TestRunExtendedGivenNamesUsesOrgDelta(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	args := genArgs{
		lastNames:             write("last_name_org.csv", "三木,10000,みき,miki\n"),
		givenMan:              write("first_name_man_opti.csv", "たろう,tarou,太郎\n"),
		givenWoman:            write("first_name_woman_opti.csv", "はなこ,hanako,花子\n"),
		givenOrgMan:           write("first_name_man_org.csv", "たろう,tarou,太郎\nあれっくす,arekkusu,亜歴久寿\n"),
		givenOrgWoman:         write("first_name_woman_org.csv", "はなこ,hanako,花子\nみき,miki,美紀\nまりあ,maria,茉莉愛\n"),
		surnamesOut:           write("surnames.txt", "三木\n"),
		givenNamesOut:         write("given_names.txt", ""),
		extendedGivenNamesOut: filepath.Join(dir, "given_names_katakana_org.txt"),
		sourceRevision:        "test-revision",
		romajiSurnamesOut:     filepath.Join(dir, "romaji_surnames.txt"),
		romajiGivenNamesOut:   filepath.Join(dir, "romaji_given_names.txt"),
	}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(args.extendedGivenNamesOut)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	if !strings.Contains(got, "# upstream revision: test-revision\n") {
		t.Errorf("org差分に生成元revisionが無い: %q", got)
	}
	for _, want := range []string{"アレックス", "マリア"} {
		if !containsLine(got, want) {
			t.Errorf("org差分に %q が無い: %q", want, got)
		}
	}
	for _, unwanted := range []string{"タロウ", "ハナコ", "ミキ"} {
		if containsLine(got, unwanted) {
			t.Errorf("org差分に既定辞書または姓と同形の %q が混入している: %q", unwanted, got)
		}
	}
}

func TestRunRejectsPartialOrgInputs(t *testing.T) {
	err := run(genArgs{givenOrgMan: "only-one.csv"})
	if err == nil || !strings.Contains(err.Error(), "同時指定") {
		t.Fatalf("run(partial org args) error = %v, want 同時指定エラー", err)
	}
}

// TestRunCrossExcludesSurnamesFromGivenNames は、姓と同形のカタカナ読みが
// 名側の辞書に混入しないことを確認する（internal/dict.TestNameDictIntegrity が
// 前提とする姓名相互排他の不変条件）。
func TestRunCrossExcludesSurnamesFromGivenNames(t *testing.T) {
	dir := t.TempDir()
	lastNames := filepath.Join(dir, "last_name_org.csv")
	// 「みき」を姓として収録する（三木 等、実データにも実在する短い読み）。
	if err := os.WriteFile(lastNames, []byte("三木,10000,みき,miki\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	givenMan := filepath.Join(dir, "first_name_man_opti.csv")
	// 同じ読み「みき」を名としても収録する（衝突ケース）。
	if err := os.WriteFile(givenMan, []byte("みき,miki,幹\nたろう,tarou,太郎\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	givenWoman := filepath.Join(dir, "first_name_woman_opti.csv")
	if err := os.WriteFile(givenWoman, []byte("はなこ,hanako,花子\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	surnamesOut := filepath.Join(dir, "surnames.txt")
	givenNamesOut := filepath.Join(dir, "given_names.txt")
	romajiSurnamesOut := filepath.Join(dir, "romaji_surnames.txt")
	romajiGivenNamesOut := filepath.Join(dir, "romaji_given_names.txt")
	if err := os.WriteFile(surnamesOut, []byte("三木\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(givenNamesOut, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := run(genArgs{
		lastNames:           lastNames,
		givenMan:            givenMan,
		givenWoman:          givenWoman,
		surnamesOut:         surnamesOut,
		givenNamesOut:       givenNamesOut,
		romajiSurnamesOut:   romajiSurnamesOut,
		romajiGivenNamesOut: romajiGivenNamesOut,
	}); err != nil {
		t.Fatal(err)
	}

	surnamesBody, err := os.ReadFile(surnamesOut)
	if err != nil {
		t.Fatal(err)
	}
	givenBody, err := os.ReadFile(givenNamesOut)
	if err != nil {
		t.Fatal(err)
	}
	if !containsLine(string(surnamesBody), "ミキ") {
		t.Errorf("surnames.txt に ミキ が無い: %q", surnamesBody)
	}
	if containsLine(string(givenBody), "ミキ") {
		t.Errorf("given_names.txt に姓と同形の ミキ が混入している: %q", givenBody)
	}
	if !containsLine(string(givenBody), "ハナコ") {
		t.Errorf("given_names.txt に衝突しない ハナコ が無い: %q", givenBody)
	}

	romajiSurnamesBody, err := os.ReadFile(romajiSurnamesOut)
	if err != nil {
		t.Fatal(err)
	}
	if !containsLine(string(romajiSurnamesBody), "miki") {
		t.Errorf("romaji_surnames.txt に miki が無い: %q", romajiSurnamesBody)
	}
}

func containsLine(body, line string) bool {
	for _, l := range splitLinesForTest(body) {
		if l == line {
			return true
		}
	}
	return false
}

func splitLinesForTest(body string) []string {
	var out []string
	start := 0
	for i := 0; i < len(body); i++ {
		if body[i] == '\n' {
			out = append(out, body[start:i])
			start = i + 1
		}
	}
	if start < len(body) {
		out = append(out, body[start:])
	}
	return out
}
