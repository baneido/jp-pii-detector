package dict

import (
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"testing"
)

// 各辞書は sync.OnceValue による遅延ロードなので、初回参照が並列走査の複数
// ワーカーから同時に起きうる。このファイルはその並行アクセスが壊れないこと
// （二重構築が起きず、どの goroutine から見ても同じ結果になること）を保証する。
// `go test -race ./internal/dict/` で実行すること。

// checkAllLazyDictAPIs は遅延ロード対象の全辞書を経由する公開 API を一通り
// 呼び、期待値（各辞書の個別テストと同じスポットチェック値）と一致するかを
// 確認する。goroutine から呼ぶため t.Fatal は使わず t.Error だけを使う。
func checkAllLazyDictAPIs(t *testing.T) {
	t.Helper()
	check := func(got, want bool, name, arg string) {
		if got != want {
			t.Errorf("%s(%q) = %v, want %v", name, arg, got, want)
		}
	}
	// 姓名辞書（surnameSet / givenNameSet / nonPersonHomographSet）。
	check(IsSurname("山田"), true, "IsSurname", "山田")
	check(IsGivenName("太郎"), true, "IsGivenName", "太郎")
	check(SplitsAsFullName("山田太郎"), true, "SplitsAsFullName", "山田太郎")
	check(SplitsAsFullName("山田錦"), false, "SplitsAsFullName", "山田錦") // 同形語 denylist
	check(MatchPersonName("山田太郎") == FullNameSplit, true, "MatchPersonName", "山田太郎")
	// 高再現率用カタカナ名辞書（extendedGivenNameSet）。
	check(IsGivenNameExtended("カレン"), true, "IsGivenNameExtended", "カレン")
	check(IsPersonNameExtended("サトウ カレン"), true, "IsPersonNameExtended", "サトウ カレン")
	// ローマ字姓名辞書（romajiSurnameSet / romajiGivenNameSet）。
	check(IsRomajiSurname("yamada"), true, "IsRomajiSurname", "yamada")
	check(IsRomajiGivenName("taro"), true, "IsRomajiGivenName", "taro")
	// 市区町村・町字辞書（municipalitySet / townSet）。
	check(MunicipalitySuffixMatch("東京都渋谷区渋谷2-1-1"), true, "MunicipalitySuffixMatch", "東京都渋谷区渋谷2-1-1")   // jp-pii-detector:ignore
	check(MunicipalityThenTownMatch("渋谷区神南1丁目2番3号"), true, "MunicipalityThenTownMatch", "渋谷区神南1丁目2番3号") // jp-pii-detector:ignore
	if matchLen, ok := TownPrefixMatch("丸の内2-1-5"); !ok || matchLen != len("丸の内") {
		t.Errorf("TownPrefixMatch(丸の内2-1-5) = (%d, %v), want (%d, true)", matchLen, ok, len("丸の内"))
	}
	// TLD・銀行名・銀行コード・郵便番号辞書。
	check(ValidTLD("com"), true, "ValidTLD", "com")
	check(ValidTLD("invalidtld"), false, "ValidTLD", "invalidtld")
	check(IsBankName("三菱UFJ銀行"), true, "IsBankName", "三菱UFJ銀行")
	check(ValidBankCode("0001"), true, "ValidBankCode", "0001")
	check(ValidPostalCode("150-0043"), true, "ValidPostalCode", "150-0043")
	check(ValidPostalCode("000-0000"), false, "ValidPostalCode", "000-0000")
	// 市外局番辞書（areaCodeSet）。
	if codeLen, ok := ValidAreaCode("0312345678"); !ok || codeLen != 2 {
		t.Errorf("ValidAreaCode(0312345678) = (%d, %v), want (2, true)", codeLen, ok)
	}
	// 決定的な列挙 API（sortedSurnames / sortedGivenNames の遅延ロード経由）。
	if got := SurnameSample(3); len(got) != 3 {
		t.Errorf("len(SurnameSample(3)) = %d, want 3", len(got))
	}
	if got := GivenNameSample(3); len(got) != 3 {
		t.Errorf("len(GivenNameSample(3)) = %d, want 3", len(got))
	}
	if got := SamplePostalCodes(3); len(got) != 3 {
		t.Errorf("len(SamplePostalCodes(3)) = %d, want 3", len(got))
	}
}

// lazyDictIdentities は遅延ロードした各辞書 map のポインタを返す。map は
// ポインタ型なので、二重構築が起きていれば goroutine 間でこの値が食い違う。
func lazyDictIdentities() []uintptr {
	towns, _ := townSet()
	maps := []any{
		surnameSet(), givenNameSet(), extendedGivenNameSet(), nonPersonHomographSet(),
		romajiSurnameSet(), romajiGivenNameSet(),
		municipalitySet(), towns,
		tldSet(), bankNameSet(), areaCodeSet().codes,
	}
	out := make([]uintptr, len(maps))
	for i, m := range maps {
		out[i] = reflect.ValueOf(m).Pointer()
	}
	return out
}

// TestLazyDictConcurrentAccess は遅延ロードした辞書へ複数 goroutine から同時に
// アクセスしても、判定結果が壊れず、辞書が二重に構築されないことを確認する。
func TestLazyDictConcurrentAccess(t *testing.T) {
	const workers = 16
	ids := make([][]uintptr, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			checkAllLazyDictAPIs(t)
			ids[i] = lazyDictIdentities()
		}()
	}
	wg.Wait()

	// 全 goroutine が同一の map インスタンスを見ていること（Once が 1 回だけ
	// 構築し、後続はその結果を共有していること）。
	for i := 1; i < workers; i++ {
		if !reflect.DeepEqual(ids[0], ids[i]) {
			t.Fatalf("goroutine %d が別の辞書インスタンスを参照している: %v != %v", i, ids[i], ids[0])
		}
	}
}

// TestLazyDictConcurrentAccessParallel は上記と同じ検査を、互いに並行に走る
// サブテスト（t.Parallel）から実行する。
func TestLazyDictConcurrentAccessParallel(t *testing.T) {
	for i := range 4 {
		t.Run(fmt.Sprintf("worker%d", i), func(t *testing.T) {
			t.Parallel()
			checkAllLazyDictAPIs(t)
		})
	}
}

// lazyColdStartEnv は子プロセス側を識別する環境変数。
const lazyColdStartEnv = "JP_PII_DICT_LAZY_COLDSTART"

// TestLazyDictColdStartRace は「どの辞書もまだロードされていない状態」から
// 一斉に並行アクセスする経路を検証する。同一プロセス内では他のテストが先に
// 辞書をロードしてしまい Once の初回構築が競合しないため、テストバイナリを
// このテストだけに絞って再実行し、真の cold start で競合させる
// （-race 付きで実行すればその子プロセスも計装済みバイナリのまま）。
func TestLazyDictColdStartRace(t *testing.T) {
	if os.Getenv(lazyColdStartEnv) == "1" {
		// 子プロセス: このテストしか動かないので辞書は未ロードのまま。
		var wg sync.WaitGroup
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				checkAllLazyDictAPIs(t)
			}()
		}
		wg.Wait()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLazyDictColdStartRace$", "-test.v")
	cmd.Env = append(os.Environ(), lazyColdStartEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cold start での並行アクセスが失敗した: %v\n%s", err, out)
	}
}
