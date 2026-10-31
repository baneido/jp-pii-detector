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
		// 様式・様相・様態の「様」は敬称ではない（行政文書の「申請書様式」等で実測）。
		{"申請書様式を使用", "申請書", false},
		{"共通様式により", "共通", false},
		{"別添様式２", "別添", false},
		{"市場様相が", "市場", false},
		// 既知の取りこぼし: 句読点なしで「式典」が続く敬称は様式と区別できず棄却する
		// （行政文書の様式名の偽陽性抑制を優先）。句読点で区切れば検出する。
		{"山田様式典にご出席", "山田", false},
		{"山田様、式次第", "山田", true},
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

func TestRejectDecimalFraction(t *testing.T) {
	cases := []struct {
		line, m string
		want    bool
	}{
		{"口座 1234567", "1234567", true},
		{"口座 1234567。", "1234567", true},
		{"末尾 1234567.", "1234567", true},
		{"ratio: 0.1234567", "1234567", false},
		{`"mtime": 1712345678.9876543`, "9876543", false},
		{"value 1234567.25", "1234567", false},
		// バージョン風の "v.1234567" は小数ではない。
		{"build v.1234567", "1234567", true},
	}
	for _, c := range cases {
		s, e := span(t, c.line, c.m)
		if got := rejectDecimalFraction(c.line, s, e); got != c.want {
			t.Errorf("rejectDecimalFraction(%q, %q) = %v, want %v", c.line, c.m, got, c.want)
		}
	}
}

func TestRejectHexTokenPart(t *testing.T) {
	cases := []struct {
		line, m string
		want    bool
	}{
		{"digest: 3fa1234567bd", "1234567", false},
		{"hash deadbeef09012345678", "09012345678", false},
		{"HASH DEADBEEF09012345678", "09012345678", false},
		// 16 進以外の英字を含む連結は棄却しない（境界ガードに任せる）。
		{"smartphone09012345678", "09012345678", true},
		{"口座 No1234567", "1234567", true},
		// 短いトークンは型番等と区別できないので棄却しない。
		{"口座 a1234567", "1234567", true},
		// 英字と地続きでなければ対象外。
		{"口座 1234567", "1234567", true},
		{"cafe 09012345678", "09012345678", true},
	}
	for _, c := range cases {
		s, e := span(t, c.line, c.m)
		if got := rejectHexTokenPart(c.line, s, e); got != c.want {
			t.Errorf("rejectHexTokenPart(%q, %q) = %v, want %v", c.line, c.m, got, c.want)
		}
	}
}

func TestRejectURLNumericID(t *testing.T) {
	f := rejectURLNumericID([]string{"tel", "phone", "口座"})
	cases := []struct {
		line, m string
		want    bool
	}{
		{"see https://support.example.com/accounts/answer/1234567 for details", "1234567", false},
		{"https://example.com/help?topic=1234567&lang=ja", "1234567", false},
		{"https://example.com/help?lang=ja&id=09012345678", "09012345678", false},
		{"(https://example.com/item/09012345678)", "09012345678", false},
		// クエリのキー名がコンテキスト語なら番号そのものとみなす。
		{"https://example.com/form?tel=09012345678", "09012345678", true},
		{"https://example.com/form?phone_number=09012345678", "09012345678", true},
		// 区切り付きの番号は URL 中でも対象外。
		{"https://example.com/u/090-1234-5678", "090-1234-5678", true},
		// URL でないパス・代入は対象外。
		{"口座 /1234567", "1234567", true},
		{"口座=1234567", "1234567", true},
		{"tel: 09012345678 https://example.com/", "09012345678", true},
	}
	for _, c := range cases {
		s, e := span(t, c.line, c.m)
		if got := f(c.line, s, e); got != c.want {
			t.Errorf("rejectURLNumericID(%q, %q) = %v, want %v", c.line, c.m, got, c.want)
		}
	}
}

func TestRejectFirebaseAppID(t *testing.T) {
	cases := []struct {
		line, m string
		want    bool
	}{
		{`"mobilesdk_app_id": "1:123456789012:android:0a1b2c3d4e5f6789"`, "123456789012", false},
		{`GOOGLE_APP_ID = 1:123456789012:ios:0a1b2c3d4e5f6789`, "123456789012", false},
		{`appId: "1:123456789012:web:0a1b2c3d4e5f6789"`, "123456789012", false},
		{`番号 1:123456789012 です`, "123456789012", true},
		{`番号 123456789012:android:`, "123456789012", true},
	}
	for _, c := range cases {
		s, e := span(t, c.line, c.m)
		if got := rejectFirebaseAppID(c.line, s, e); got != c.want {
			t.Errorf("rejectFirebaseAppID(%q, %q) = %v, want %v", c.line, c.m, got, c.want)
		}
	}
}

func TestRejectHonorificCommonNoun(t *testing.T) {
	cases := []struct {
		line, m string
		want    bool
	}{
		{"初見さん歓迎", "初見", false},
		{"常連さんに感謝", "常連", false},
		{"社員皆さんへ", "社員皆", false},
		{"来場者皆様へ", "来場者皆", false},
		{"常連客様", "常連客", false},
		{"大家さんへ", "大家", false},
		{"山田太郎さんへ", "山田太郎", true},
		{"初見太郎さん", "初見太郎", true},
		// 「氏」「殿」は対象外。
		{"大家氏", "大家", true},
	}
	for _, c := range cases {
		s, e := span(t, c.line, c.m)
		if got := rejectHonorificCommonNoun(c.line, s, e); got != c.want {
			t.Errorf("rejectHonorificCommonNoun(%q, %q) = %v, want %v", c.line, c.m, got, c.want)
		}
	}
}

func TestNonPersonalEmail(t *testing.T) {
	cases := []struct {
		m    string
		want bool
	}{
		{"chacha20-poly1305@openssh.com", false},
		{"sntrup761x25519-sha512@openssh.com", false},
		{"curve25519-sha256@libssh.org", false},
		{"deploy@my-proj.iam.gserviceaccount.com", false},
		{"123456789012-compute@developer.gserviceaccount.com", false},
		{"service-123456789012@gcp-sa-pubsub.iam.gserviceaccount.com", false},
		{"service-123456789012@compute-system.iam.gserviceaccount.com", false},
		{"kairo-proj@appspot.gserviceaccount.com", false},
		{"123456789012@cloudbuild.gserviceaccount.com", false},
		{"runner@gserviceaccount.com", false},
		{"Deploy@Kairo-Proj.IAM.GServiceAccount.COM", false},
		{"noreply@corp.co.jp", false},
		{"No-Reply@corp.co.jp", false},
		{"taro.yamada@corp.co.jp", true},
		// 似たドメイン・ローカル部は棄却しない。
		{"taro@notopenssh.com", true},
		{"deploy@kairo-proj.gserviceaccount.com.evil.jp", true},
		{"deploy@xgserviceaccount.com", true},
		{"deploy@gserviceaccount.co", true},
		{"taro.yamada+gcp@gmail.com", true},
		{"noreply.taro@corp.co.jp", true},
	}
	for _, c := range cases {
		if got := validEmail(c.m); got != c.want {
			t.Errorf("validEmail(%q) = %v, want %v", c.m, got, c.want)
		}
	}
}
