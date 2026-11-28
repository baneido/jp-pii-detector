package detect

import (
	"strings"
	"testing"
)

// 2026-11-28 の公開文書 1,401 件の確認（人を指す語・連絡先の語のある無作為 380 行の人手の正解 212 個と、
// 検出の層別サンプル 177 件）で見つけた見逃し・誤検出の「形」を、合成値だけで再現したケース。氏名は架空の
// 定番名、町名は「架空」を含む架空の名、郵便番号は 000-0000（未割当）、メールのドメインは登録できない
// home.arpa だけを使い、収集した文書の内容は使わない。

// TestStarObfuscatedEmail は、迷惑メール対策で「@」を「*」「＊」に置き換え、同じ行に置き換えの指示
// （*を@に置き換えてください）を書いたアドレスを email-address で報告することを確認する。実測では大学の
// 問い合わせ先 2 件（メールの正解 4 個のうち 2 個）を全モードで落としていた。
func TestStarObfuscatedEmail(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct{ line, want string }{
		{"E-mail: kakuu-seminar*mail.kakuu-u.home.arpa（*を@に置き換えてください）", "kakuu-seminar*mail.kakuu-u.home.arpa"}, // jp-pii-detector:ignore（合成ケース）
		{"E-mail:kikin*adb.kakuu-u.home.arpa (*を@に置き換えてください。)", "kikin*adb.kakuu-u.home.arpa"},                  // jp-pii-detector:ignore（合成ケース）
		{"メール：soudan＊kakuu.home.arpa（「＊」を「＠」に置き換えてください）", "soudan＊kakuu.home.arpa"},                             // jp-pii-detector:ignore（合成ケース）
	}
	for _, tt := range tests {
		var got []string
		for _, f := range d.ScanLine("f.txt", 1, tt.line) {
			if f.RuleID == "email-address" {
				got = append(got, f.Match)
			}
		}
		if len(got) != 1 || got[0] != tt.want {
			t.Errorf("%q: got %q, want %q", tt.line, got, tt.want)
		}
	}
}

// TestStarObfuscatedEmailNegatives は、置き換えの指示が無い行の「*」入りの並び（掛け算・注記・伏せ字）や、
// 指示があっても TLD が実在しない・ダミーの値を報告しないことを確認する。
func TestStarObfuscatedEmailNegatives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"計算式は a*b.c と書く",
		"kakuu*kakuu.home.arpa",              // 置き換えの指示が無い（jp-pii-detector:ignore 合成ケース）
		"sample*test.invalid（*を@に置き換えてください）", // TLD が実在しない
		"xxxxx*yyyyy.jp（*を@に置き換えてください）",      // 伏せ字
		"※ *印は@マーク不要",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "email") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestNameNewContexts は、実測した氏名の見逃しの形を person-name-role-label で拾うことを確認する。
//   - 国会会議録の出席者の名簿の行で、名がひらがなの議員「<姓><ひらがなの名>君」
//   - 本文の「<会社名>副社長<氏名>君に願います」（職名に氏名が地続き）
//   - 研究課題の一覧の「研究代表者　<氏名>（<所属>）」
//   - 問い合わせ先の「<団体名> 広報部 <姓> <名> TEL：」
//   - 企業のお知らせの見出し「会長 兼 社長 CEO　<氏名>メッセージ」
//
// 実測では氏名の正解 61 個のうち、これらの形で 5 個を既定モードで落としていた。国会議員・企業の役員・
// 研究者・団体の担当者の氏名は、特定の個人を識別できる情報（個人情報保護法の個人情報）に当たる。
func TestNameNewContexts(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		line string
		want []string
	}{
		{"　　　　山田はなこ君　　　　佐藤　花子君", []string{"山田はなこ", "佐藤　花子"}},      // jp-pii-detector:ignore（合成ケース。架空の値）
		{"○委員長（架空君）　次に架空電力株式会社副社長鈴木一郎君に願います。", []string{"鈴木一郎"}},  // jp-pii-detector:ignore（合成ケース。架空の値）
		{"研究代表者　高橋健太（架空研究部長）", []string{"高橋健太"}},                  // jp-pii-detector:ignore（合成ケース。架空の値）
		{"架空工業協会 広報部 田中 美咲 TEL： 03-0000-0000", []string{"田中 美咲"}}, // jp-pii-detector:ignore（合成ケース。架空の値）
		{"国際女性デー　架空グループ　会長 兼 社長 CEO　伊藤直樹メッセージ", []string{"伊藤直樹"}}, // jp-pii-detector:ignore（合成ケース。架空の値）
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

// TestNameNewContextsNegatives は、同じ手がかり語の近くでも氏名でない並び（名簿の行のひらがなの一般語、
// 職名 + 一般語 + 君、代表者 + 記入方法の説明、部署名 + 一般語の組、CEO + 一般語 + メッセージ）と、
// マイナンバーカードの見本の「番号 花子」を報告しないことを確認する。
func TestNameNewContextsNegatives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"　　　　諸君　　　　みなさん君",
		"次に副社長架空君に願います。",
		"代表者氏名（ふりがな）を記入",
		"総務課 企画 調整 TEL 03-0000-0000", // jp-pii-detector:ignore（合成ケース）
		"社長 CEO　年頭所感メッセージ",
		"氏名 番号 花子",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
	// 券面の見本は氏名ラベルの次の行に値が来る（行をまたぐ経路）。
	for _, f := range d.ScanContent("f.txt", "氏名\n番号 花子\n") {
		if strings.HasPrefix(f.RuleID, "person-name") {
			t.Errorf("cross-line: unexpected %s %q", f.RuleID, f.Match)
		}
	}
}

// TestAddressNoSeparatedBanchi は、「の」で 3 つの数字をつないだ番地（「<町名>1の12の1」）を jp-address で
// 報告し、「の」1 つの並び（第1の2つ目）は番地とみなさないことを確認する。実測では市役所の所在地 1 件を
// 全モードで落としていた。
func TestAddressNoSeparatedBanchi(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct{ line, want string }{
		{"〒000-0000　東京都日野市架空1の12の1", "東京都日野市架空1の12の1"}, // jp-pii-detector:ignore（合成ケース。架空の値）
		{"所在地：東京都日野市架空2の3の4", "東京都日野市架空2の3の4"},         // jp-pii-detector:ignore（合成ケース。架空の値）
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
	for _, line := range []string{"東京都日野市の第1の2つ目の議題", "東京都日野市で1の2を確認"} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "jp-address") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestHighRecallStatTableAndFacilityPrefix は高再現率モードの誤検出 2 つの形を確認する。
//   - 町丁別人口の CSV の行「<地域コード>,<n>,<市><町名><n>丁目,<人口>,…」の町丁の名前（町丁の名前で、
//     特定の人・施設の所在地ではない）は jp-address-high-recall で報告しない。隣が電話番号の施設一覧の
//     「<市><区><町名><n>丁目,<電話>」と、番地のある値はこれまでどおり報告する。
//   - 「<市名>市立さんない保育園」の「<市名>市立」を、敬称「さん」の前の氏名として報告しない。
//
// 実測では高再現率だけで出る検出の無作為 40 件のうち、この 2 つの形で 3 件が誤りだった。
func TestHighRecallStatTableAndFacilityPrefix(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{
		"27210201001,627,枚方市架空町１丁目,344,283,403", // jp-pii-detector:ignore（合成ケース。架空の値）
		"横手市立さんない保育園運営事業",
		"架空町立さんさん館の利用案内",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "jp-address") || strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
	for _, tt := range []struct{ line, want string }{
		{"施設,札幌市中央区架空1条西2丁目,011-000-0000", "札幌市中央区架空1条西2丁目"}, // jp-pii-detector:ignore（合成ケース。架空の値）
		{"1,枚方市架空町１丁目5番,3", "枚方市架空町１丁目5番"},                   // jp-pii-detector:ignore（合成ケース。架空の値）
	} {
		found := false
		for _, f := range d.ScanLine("f.txt", 1, tt.line) {
			if strings.HasPrefix(f.RuleID, "jp-address") && f.Match == tt.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: %q not reported", tt.line, tt.want)
		}
	}
}
