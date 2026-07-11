package detect

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/rule"
	"github.com/baneido/jp-pii-detector/internal/testfixtures"
)

// Finding は出力スキーマではなく、生の PII を持つ Match は json:"-" で
// シリアライズ対象から外している。誤って Finding を直接 marshal しても
// 生値が漏れないことを固定する回帰テスト（正規の出力は internal/report の
// jsonFinding を経由し、値はマスクされる）。
func TestFindingMarshalDoesNotLeakRawMatch(t *testing.T) {
	raw := testfixtures.MustGet(t, "detect.finding_phone")
	f := Finding{RuleID: "jp-phone-number", File: "f.txt", Line: 1, Column: 1, Match: raw}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), raw) {
		t.Fatalf("marshaled Finding leaked raw match %q: %s", raw, b)
	}
}

func TestFindingFormatDoesNotLeakRawMatch(t *testing.T) {
	raw := "private-canary-value"
	f := Finding{RuleID: "canary", File: "f.txt", Line: 1, Column: 2, Match: raw, Confidence: rule.High}
	for _, formatted := range []string{fmt.Sprintf("%v", f), fmt.Sprintf("%+v", f), fmt.Sprintf("%#v", f)} {
		if strings.Contains(formatted, raw) {
			t.Fatalf("formatted Finding leaked raw match")
		}
		if !strings.Contains(formatted, "<redacted>") {
			t.Fatalf("formatted Finding lacks redaction marker: %s", formatted)
		}
	}
}
