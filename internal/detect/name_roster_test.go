package detect

import (
	"strconv"
	"strings"
	"testing"
)

const nameRosterTOML = `
[rules]
name_roster = true
`

// TestNameRosterDisabledByDefault は、ラベルの無い氏名の羅列が既定でも
// --high-recall でも検出されないことを確認する。行単位の手がかりを 1 つも
// 持たない判定のため、専用の opt-in でのみ有効になる。
func TestNameRosterDisabledByDefault(t *testing.T) {
	content := "山田太郎\n佐藤花子\n鈴木一郎\n"
	for _, tt := range []struct{ name, toml string }{
		{"既定", ""},
		{"高再現率のみ", highRecallTOML},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, newDetector(t, tt.toml).ScanContent("roster.txt", content))
		})
	}
}

// TestNameRosterOptIn は opt-in 時に羅列の全行が検出されることを確認する。
func TestNameRosterOptIn(t *testing.T) {
	d := newDetector(t, nameRosterTOML)
	content := "山田太郎\n佐藤花子\n鈴木一郎\n"
	fs := d.ScanContent("roster.txt", content)
	assertRules(t, fs, "person-name-roster", "person-name-roster", "person-name-roster")
	for i, want := range []string{"山田太郎", "佐藤花子", "鈴木一郎"} {
		if fs[i].Match != want {
			t.Errorf("findings[%d].Match = %q, want %q", i, fs[i].Match, want)
		}
		if fs[i].Line != i+1 {
			t.Errorf("findings[%d].Line = %d, want %d", i, fs[i].Line, i+1)
		}
	}
}

// TestNameRosterMinimumNames は、氏名行が rosterMinNames 未満のファイルを
// 名簿とみなさないことを確認する。1〜2 行では「たまたま氏名と同形の語が
// 並んだ」ケースと区別できない。
func TestNameRosterMinimumNames(t *testing.T) {
	d := newDetector(t, nameRosterTOML)
	assertRules(t, d.ScanContent("roster.txt", "山田太郎\n佐藤花子\n"))
}

// TestNameRosterRatioGuard は、氏名行の割合が閾値（非空行の 1/2）を下回る
// ファイルを名簿とみなさないことを確認する。氏名と同形の語が少数混ざる
// 大きなリスト（地名辞書など）を名簿と誤認しないための唯一の防波堤。
func TestNameRosterRatioGuard(t *testing.T) {
	d := newDetector(t, nameRosterTOML)
	var b strings.Builder
	for _, name := range []string{"山田太郎", "佐藤花子", "鈴木一郎"} {
		b.WriteString(name)
		b.WriteString("\n")
	}
	// 氏名でない行を氏名行より多く混ぜて割合を 1/2 未満へ落とす。
	for i := range 4 {
		b.WriteString("項目")
		b.WriteString(strconv.Itoa(i))
		b.WriteString("\n")
	}
	assertRules(t, d.ScanContent("mixed.txt", b.String()))
}

// TestNameRosterBlankLinesIgnored は、空行が割合の分母に入らないことを
// 確認する（見やすさのために空行を挟んだ名簿を落とさないため）。
func TestNameRosterBlankLinesIgnored(t *testing.T) {
	d := newDetector(t, nameRosterTOML)
	content := "山田太郎\n\n佐藤花子\n\n鈴木一郎\n"
	assertRules(t, d.ScanContent("roster.txt", content),
		"person-name-roster", "person-name-roster", "person-name-roster")
}

// TestNameRosterRejectsSurnameOnly は、単独の姓だけが並ぶファイル（地名・
// 企業名と同形になりやすい）を名簿とみなさないことを確認する。
// ValidRosterName は姓+名の分割が成立する値しか許可しない。
func TestNameRosterRejectsSurnameOnly(t *testing.T) {
	d := newDetector(t, nameRosterTOML)
	assertRules(t, d.ScanContent("places.txt", "渋谷\n大和\n本田\n"))
}

// TestNameRosterIgnoreMarker は、行末の ignore マーカーが付いた行が
// 名簿の氏名行として成立しないことを確認する（行全体アンカーのため）。
func TestNameRosterIgnoreMarker(t *testing.T) {
	d := newDetector(t, nameRosterTOML)
	content := "山田太郎 // jp-pii-detector:ignore\n佐藤花子\n鈴木一郎\n高橋美咲\n"
	fs := d.ScanContent("roster.txt", content)
	assertRules(t, fs, "person-name-roster", "person-name-roster", "person-name-roster")
	for _, f := range fs {
		if f.Line == 1 {
			t.Errorf("ignore マーカー付きの行が検出された: %+v", f)
		}
	}
}

// TestNameRosterAllowlist は allowlist の stopwords が名簿の個別の値に
// 効くこと、かつ除外された行が「名簿らしさ」の判定から落ちないことを
// 確認する（allowlist は報告の抑制であって、名簿かどうかの判断材料ではない）。
func TestNameRosterAllowlist(t *testing.T) {
	d := newDetector(t, `
[rules]
name_roster = true
[allowlist]
stopwords = ["山田太郎"]
`)
	content := "山田太郎\n佐藤花子\n鈴木一郎\n"
	fs := d.ScanContent("roster.txt", content)
	assertRules(t, fs, "person-name-roster", "person-name-roster")
	for _, f := range fs {
		if f.Match == "山田太郎" {
			t.Errorf("allowlist の値が検出された: %+v", f)
		}
	}
}
