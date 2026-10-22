package rule

import (
	"strings"
	"testing"
)

// span は line 中の最初の m の位置を返す。
func span(t *testing.T, line, m string) (int, int) {
	t.Helper()
	i := strings.Index(line, m)
	if i < 0 {
		t.Fatalf("%q に %q がない", line, m)
	}
	return i, i + len(m)
}

func TestRejectNumericTokenPart(t *testing.T) {
	cases := []struct {
		line, m string
		want    bool
	}{
		{"番号: 123456789012", "123456789012", true},
		{"番号は123456789012です。", "123456789012", true},
		{"末尾 123456789012.", "123456789012", true}, // 文末のピリオド
		{"(-95.4183170000000018 29.7062300000000015)", "7062300000000015", false},
		{"0.968994140625,629", "968994140625", false},
		{`"start": "148966367200.372"`, "148966367200", false},
		{"blk_3550669278239526374 terminating", "3550669278239526374", false},
		{"id 123456789012_x", "123456789012", false},
	}
	for _, c := range cases {
		s, e := span(t, c.line, c.m)
		if got := rejectNumericTokenPart(c.line, s, e); got != c.want {
			t.Errorf("rejectNumericTokenPart(%q, %q) = %v, want %v", c.line, c.m, got, c.want)
		}
	}
}

func TestRejectHexDumpGroup(t *testing.T) {
	cases := []struct {
		line, m string
		want    bool
	}{
		{"ffffffffffff 838383838383 7b7b7b7b7b7b", "838383838383", false},
		{"ffff 54cd 7484 9797 9999 9a9a", "7484 9797 9999", false},
		{"00000130  64 67 69 74 73 20 50 74  79 20 4c 74 64 30 81 9b  |dgits|", "64 67 69 74 73 20 50 74", false},
		// 16 進でないトークンで打ち切る。
		{"abcd 番号 1234 5678 9012", "1234 5678 9012", true},
		// 幅が違う 16 進トークンは根拠にしない。
		{"card 1234 5678 9012 3456 exp", "1234 5678 9012 3456", true},
		{"cafe 123456789012", "123456789012", true},
		{"マイナンバー 1234 5678 9012", "1234 5678 9012", true},
	}
	for _, c := range cases {
		s, e := span(t, c.line, c.m)
		if got := rejectHexDumpGroup(c.line, s, e); got != c.want {
			t.Errorf("rejectHexDumpGroup(%q, %q) = %v, want %v", c.line, c.m, got, c.want)
		}
	}
}

func TestRejectLogTimestamp66(t *testing.T) {
	f := rejectLogTimestamp66(myNumberContext)
	cases := []struct {
		line, m string
		want    bool
	}{
		{"081109 203807 222 INFO dfs.DataNode", "081109 203807", false},
		{"マイナンバー: 081109 203807", "081109 203807", true}, // ラベルがあれば残す
		{"番号 123456 789012", "123456 789012", true},      // 日付・時刻として不正
		{"081109 253807 x", "081109 253807", true},       // 25 時は時刻でない
	}
	for _, c := range cases {
		s, e := span(t, c.line, c.m)
		if got := f(c.line, s, e); got != c.want {
			t.Errorf("rejectLogTimestamp66(%q, %q) = %v, want %v", c.line, c.m, got, c.want)
		}
	}
}

func TestRejectYouCompound(t *testing.T) {
	cases := []struct {
		line, m string
		want    bool
	}{
		{"新品同様の状態", "新品同", false},
		{"構文仕様を参照", "構文仕", false},
		{"多種多様な", "多種多", false},
		{"本多様へ", "本多", true},
		{"山田様へ", "山田", true},
		{"山田さんへ", "山田", true},
	}
	for _, c := range cases {
		s, e := span(t, c.line, c.m)
		if got := rejectYouCompound(c.line, s, e); got != c.want {
			t.Errorf("rejectYouCompound(%q, %q) = %v, want %v", c.line, c.m, got, c.want)
		}
	}
}

func TestRejectURLUserinfo(t *testing.T) {
	cases := []struct {
		line, m string
		want    bool
	}{
		{`{lastReq: "http://gopher@test.com", newReq: "x"}`, "gopher@test.com", false},
		{`// "ssh://git@github.com/user/repo".`, "git@github.com", false},
		{`see http://user:p@host.example.org/x`, "p@host.example.org", false},
		{`連絡先: taro@mail.co.jp`, "taro@mail.co.jp", true},
		{`<a href="mailto:taro@mail.co.jp">`, "taro@mail.co.jp", true},
		{`https://example.org/ taro@mail.co.jp`, "taro@mail.co.jp", true},
	}
	for _, c := range cases {
		s, e := span(t, c.line, c.m)
		if got := rejectURLUserinfo(c.line, s, e); got != c.want {
			t.Errorf("rejectURLUserinfo(%q, %q) = %v, want %v", c.line, c.m, got, c.want)
		}
	}
}

func TestValidEmailPlaceholderDomain(t *testing.T) {
	for _, m := range []string{"user@domain.com", "joe@somewhere.org", "a@test.com", "me@yourdomain.net"} {
		if validEmail(m) {
			t.Errorf("validEmail(%q) = true, want false", m)
		}
	}
	// ラベル 3 つ以上（サブドメイン）や、第 1 ラベルが一致しないものは残す。
	for _, m := range []string{"taro@mail.domain.co.jp", "taro@testing.co.jp", "taro@gmail.com"} {
		if !validEmail(m) {
			t.Errorf("validEmail(%q) = false, want true", m)
		}
	}
}
