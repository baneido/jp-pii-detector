package rule

import (
	"strings"
	"testing"
)

// TestRejectIAMGroupMember は、Google Cloud IAM の "group:" メンバー指定の
// アドレスだけを棄却し、"user:" や語の一部の "mygroup:" は残すことを固定する。
func TestRejectIAMGroupMember(t *testing.T) {
	for _, tc := range []struct {
		line, email string
		want        bool
	}{
		{`  kanri_dev_group = "group:kanri-dev@example.co.jp"`, "kanri-dev@example.co.jp", false},
		{`group:ops@example.co.jp`, "ops@example.co.jp", false},
		{`  members = ["deleted:group:old@example.co.jp?uid=123"]`, "old@example.co.jp", false},
		{`  member = "user:taro.yamada@example.co.jp"`, "taro.yamada@example.co.jp", true},
		{`mygroup:taro.yamada@example.co.jp`, "taro.yamada@example.co.jp", true},
		{`To: taro.yamada@example.co.jp`, "taro.yamada@example.co.jp", true},
	} {
		start := strings.Index(tc.line, tc.email)
		if got := rejectIAMGroupMember(tc.line, start, start+len(tc.email)); got != tc.want {
			t.Errorf("rejectIAMGroupMember(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}
