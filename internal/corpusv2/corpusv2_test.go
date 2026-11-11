package corpusv2

import (
	"testing"

	"github.com/baneido/jp-pii-detector/internal/checksum"
)

func TestHardNegativePANsAreTheExplicitKnownTestSet(t *testing.T) {
	seen := map[string]bool{}
	for _, pan := range wellKnownTestPANs() {
		if seen[pan] || !checksum.Luhn(pan) || !checksum.KnownTestPAN(pan) || checksum.CreditCard(pan) {
			t.Fatalf("公知テストPAN集合に重複または構造不正な値がある")
		}
		seen[pan] = true
	}
	if len(seen) != 5 {
		t.Fatalf("known test PAN count = %d, want 5", len(seen))
	}
}
