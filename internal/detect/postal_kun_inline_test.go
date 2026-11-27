package detect

import (
	"strings"
	"testing"
)

// 2026-11-27 の公開文書 1,439 件の確認（人を指す語・連絡先の語のある無作為 420 行の人手の正解 270 個）で
// 見つけた見逃しの「形」を、合成値だけで再現したケース。氏名は架空の定番名、町名は「架空」を含む架空の名、
// 郵便番号は 000-0000（未割当）か、実在しても個人を指さない番号だけを使い、収集した文書の内容は使わない。

// TestPostalCodeBeforeChibaPrefecture は「〒<郵便番号> 千葉県…」の郵便番号を報告することを確認する。
// 実測では、値の直後の「千」（千葉県の千）を金額の桁の語（1,500 千円の千）とみなして郵便番号を落としていた
// （千葉県の自治体の所在地 6 件。郵便番号の正解 52 個のうち 6 個）。千代田・千歳・万代も同じ。
func TestPostalCodeBeforeChibaPrefecture(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"〒100-0001 千葉県架空郡架空町架空12", // jp-pii-detector:ignore（合成ケース）
		"〒100-0001　千葉県架空市架空1丁目2番",  // jp-pii-detector:ignore（合成ケース）
		"〒100-0001 千代田区架空町1-2-3",   // jp-pii-detector:ignore（合成ケース）
	} {
		found := false
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if f.RuleID == "jp-postal-code" {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: jp-postal-code not reported", line)
		}
	}
}

// TestPostalCodeMultiplierStillSuppressed は、桁の語が金額・数量の単位として続くとき（千円・千人・万円）は
// これまでどおり郵便番号として報告しないことを確認する（修正で金額の抑制を弱めていないこと）。
func TestPostalCodeMultiplierStillSuppressed(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"予算額 100-0001 千円",  // jp-pii-detector:ignore（合成ケース）
		"見込み 100-0001千人",   // jp-pii-detector:ignore（合成ケース）
		"総額 100-0001 万円です", // jp-pii-detector:ignore（合成ケース）
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if f.RuleID == "jp-postal-code" {
				t.Errorf("%q: unexpected jp-postal-code %q", line, f.Match)
			}
		}
	}
}

// TestAddressAfterPostalCode は、郵便番号の直後の都道府県を省いた住所（「〒<番号> <市><町名><番地>」）と、
// 番地が数字だけの住所（「〒<番号> <県><市><町名><数字>」）を jp-address で報告することを確認する。
// 実測では住所の正解 44 個のうち、既定モードで 18 個を落としていた（高再現率モードでしか拾えない形）。
// 所在地は個人の住所とは限らないが、このプロジェクトの jp-address の定義（住所の表記）に当たる。
func TestAddressAfterPostalCode(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct{ line, want string }{
		{"〒000-0000　大分市架空新町1番1号", "大分市架空新町1番1号"},              // jp-pii-detector:ignore（合成ケース。架空の値）
		{"所在地/〒000-0000 秩父市架空町3番4号 (架空庁舎1階)", "秩父市架空町3番4号"}, // jp-pii-detector:ignore（合成ケース。架空の値）
		{"〒000-0000 千葉県佐倉市架空寺町12", "千葉県佐倉市架空寺町12"},            // jp-pii-detector:ignore（合成ケース。架空の値）
		{"〒000-0000　埼玉県比企郡小川町大字架空34", "埼玉県比企郡小川町大字架空34"},      // jp-pii-detector:ignore（合成ケース。架空の値）
		{"〒000-0000　富山市架空1234", "富山市架空1234"},                  // jp-pii-detector:ignore（合成ケース。架空の値）
	}
	for _, tt := range tests {
		var got []string
		for _, f := range d.ScanLine("f.txt", 1, tt.line) {
			if f.RuleID == "jp-address" {
				got = append(got, f.Match)
			}
		}
		if len(got) != 1 || got[0] != tt.want {
			t.Errorf("%q: got %q, want %q", tt.line, got, tt.want)
		}
	}
}

// TestAddressAfterPostalCodeNegatives は、郵便番号の後ろでも住所でない並び（役所名 + 年、市町村の合計、
// 実在しない市区町村名、番号の後ろに単位が続く形）を jp-address で報告しないことを確認する。
func TestAddressAfterPostalCodeNegatives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"〒000-0000 千代田区役所 2024年",
		"〒000-0000 市町村合計12",
		"〒000-0000 架空市架空町12",     // 実在しない市区町村
		"〒000-0000 佐倉市架空町12人",    // 数字の後ろに単位
		"〒000-0000 佐倉市の人口は12千人", // ひらがなを含む
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if f.RuleID == "jp-address" {
				t.Errorf("%q: unexpected jp-address %q", line, f.Match)
			}
		}
	}
}

// TestKunInlineNames は、国会の会議録の本文の「<氏名>君」と、判決書の本文の「裁判官<氏名>」を
// person-name-role-label で拾うことを確認する。実測では発言者ラベルでも指名・当選でもない本文の
// 「民主党・無所属クラブの<氏名>君、」「<氏名>君外八名提出」「理事に<氏名>君及び」「<氏名>君、時間が」と、
// 判決書の「裁判官<氏名>、同<氏名>の少数意見」「裁判官<氏名>同<氏名>の」を落としていた
// （氏名の正解 108 個のうち 10 個）。国会議員・裁判官の氏名も特定の個人を識別できる情報に当たる。
func TestKunInlineNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		line string
		want []string
	}{
		{"本日は、まず民主党・無所属クラブの山田太郎君、次に架空党の佐藤花子君の順序で行います。", []string{"山田太郎", "佐藤花子"}}, // jp-pii-detector:ignore（合成ケース。架空の値）
		{"架空法律案につきまして、鈴木一郎君外八名提出の案の趣旨の説明がございます。", []string{"鈴木一郎"}},               // jp-pii-detector:ignore（合成ケース。架空の値）
		{"それでは、理事に高橋健太君及び田中美咲君を指名いたします。", []string{"高橋健太", "田中美咲"}},               // jp-pii-detector:ignore（合成ケース。架空の値）
		{"○委員長（架空君）　伊藤直樹君、時間が来ております。", []string{"伊藤直樹"}},                          // jp-pii-detector:ignore（合成ケース。架空の値）
		{"この決定は裁判官山田太郎、同佐藤花子の少数意見があるほか、裁判官全員一致の意見である。", []string{"山田太郎", "佐藤花子"}}, // jp-pii-detector:ignore（合成ケース。架空の値）
		{"この判決は、論旨第一点に対する裁判官鈴木一郎同高橋健太の少数意見を除くほか", []string{"鈴木一郎", "高橋健太"}},       // jp-pii-detector:ignore（合成ケース。架空の値）
	}
	for _, tt := range tests {
		got := map[string]bool{}
		for _, f := range d.ScanLine("f.txt", 1, tt.line) {
			if f.RuleID == "person-name-role-label" {
				got[f.Match] = true
			}
		}
		for _, w := range tt.want {
			if !got[w] {
				t.Errorf("%q: %q not reported (got %v)", tt.line, w, got)
			}
		}
	}
}

// TestKunInlineNegatives は、「君」「裁判官」「同」を含むが氏名でない本文（裁判官全員一致・君が代・諸君・
// 姓だけの<姓>君・同社の<姓>君・同意見）を氏名として報告しないことを確認する。姓だけでは個人を特定できない。
func TestKunInlineNegatives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"この判決は裁判官全員一致の意見である。",
		"国歌君が代を斉唱し、諸君の健闘を祈る。",
		"次に、山田君、どうぞ。",
		"同社の佐藤君の報告によれば、",
		"裁判官の意見は、次のとおりである。",
		"裁判官全員の一致で、同意見の、",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}
