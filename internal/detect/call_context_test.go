package detect

import (
	"strings"
	"testing"
)

// 2026-11-16 の公開文書 6,842 件の確認で見つけた見逃し・誤検出を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）、組織名も架空で、収集した文書の内容は使わない。

// TestCallContextNames は、会議録の指名「次に、<氏名>君。」、括弧の中の氏名 + 職名、活用語尾に続く
// 氏名 + 町長・校長、「<氏名>氏より、」、姓が辞書にない議員の発言者ラベル・名簿を
// person-name-role-label で拾うことを確認する。いずれも特定の個人（議員・役員・首長・校長・
// 生産者）を指す氏名で、個人情報保護法の「特定の個人を識別できる情報」に当たる。実測では、
// 人を指す語のある無作為 400 行のうち設計用の姓+名 79 人で、既定モードが拾えたのは 58 人だった。
func TestCallContextNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"次に、+ 君。", "○架空委員長　次に、佐藤花子君。", []string{"佐藤花子"}},
		{"。+ 君。", "質疑の申出がありますので、順次これを許します。鈴木一郎君。", []string{"鈴木一郎"}},
		{"君が委員長に御当選", "御異議なしと認めます。よって、高橋健太君が委員長に御当選になりました。", []string{"高橋健太"}},
		{"（姓 名社長）", "架空重工業（田中 美咲社長）は、このたび環境報告書を発行した。", []string{"田中 美咲"}},
		{"（氏名会長）", "架空市と架空薬剤師会（伊藤直樹会長）は、協定を締結しました。", []string{"伊藤直樹"}},
		{"（氏名名誉会員）", "第99代会長（佐藤花子名誉会員）を議長とする有識者会議を設立しました。", []string{"佐藤花子"}},
		{"述べる + 町長", "壇上で式辞を述べる鈴木一郎町長", []string{"鈴木一郎"}},
		{"する + 校長", "児童にあいさつする高橋健太校長", []string{"高橋健太"}},
		{"氏より、", "架空生産協議会 田中美咲氏より、学校給食用の米が贈られました。", []string{"田中美咲"}},
		// 姓が辞書にない議員（名は辞書に一致）。会議録の定型に限る。
		{"発言者ラベル・辞書にない姓", "○議長（伊吹太郎君）　起立多数。よって、本案は可決いたしました。", []string{"伊吹太郎"}},
		{"名簿・一般語と同形の姓", "　　　　　　北側　一郎君　　　　山田　花子君", []string{"北側　一郎", "山田　花子"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, f := range d.ScanLine("f.txt", 1, tt.line) {
				if f.RuleID == "person-name-role-label" {
					got = append(got, f.Match)
				}
			}
			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Fatalf("%q: got %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// TestCallContextNegatives は、同じ形に見えるが個人を指さない行（諸君、姓だけ + 君、職名 + 君、
// 組織 + 職名）を氏名として報告しないことを確認する。
func TestCallContextNegatives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"本件は承認すべきものと決するに賛成の諸君。", // 諸君
		"○架空委員長　次に、山田君。",        // 姓だけ（特定できる氏名ではない）
		"　　　委員長　山田君",            // 職名 + 姓だけ
		"　　　理事　　太郎君",            // 職名 + 名だけ
		"○議長（諸君）　静粛に願います。",      // 一般語
		"架空協会（全国市議会議長）からの要望",    // 括弧の中が組織 + 職名
		"会議に出席した各町内会長",          // 連体修飾 + 組織 + 職名
		"研修に参加した小学校長",           // 組織 + 職名
		"（長岡京市長）が出席",            // 自治体の長
		"協定書に署名をする山田本部長（左）",     // 姓 + 本部長（名ではない）
		"憲法担当の当時の山田第一部長らが答弁した",  // 姓 + 第一部長
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 氏名として報告した: %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestHighRecallOrgPlaceHonorifics は、高再現率モードで省庁の略称・役割語・店や機関の名前に付く
// 「さん」「様」、ひらがなの地名「さんりく」、史跡名の「<氏族>氏城館跡」を氏名として報告しない
// ことと、同じ形の氏名は従来どおり報告することを確認する（いずれも特定の個人を指さない）。
func TestHighRecallOrgPlaceHonorifics(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{
		"文科省さんは、ここまでの質問ですので、退席されて結構です。",
		"運送業一般にそうでございますが、荷主さんに対してなかなか言えない。",
		"【医療機関様】　予防接種　実施要領等",
		"地域家電店様などお問合せをお待ちしています。",
		"首都圏さんりく架空人会",
		"史跡架空安東氏城館跡環境整備計画策定委員会設置要綱",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 氏名として報告した: %s %q", line, f.RuleID, f.Match)
			}
		}
	}
	for _, line := range []string{"山田太郎さんが受賞しました。", "寄付者　佐藤花子様"} {
		found := false
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: 氏名を報告しなかった", line)
		}
	}
}

// TestBirthdateHistoricalAndExample は、存命ではありえない生年（明治）と、初期パスワードの
// 作り方の例示「<日付>生まれの場合」を生年月日として報告しないことを確認する（個人情報保護法の
// 個人情報は生存する個人の情報。例示は特定の個人の生年月日ではない）。通常の形は報告する。
func TestBirthdateHistoricalAndExample(t *testing.T) {
	d := newDetector(t, "")
	for _, content := range []string{
		"生年月日\n明治元年1月20日\n",
		"生年月日: 明治40年3月1日\n",
		"生年月日: 1907/03/01\n",
		"初期パスワード（1964年2月1日生まれの場合）\n",
	} {
		for _, f := range d.ScanContent("f.txt", content) {
			if f.RuleID == "jp-birthdate" {
				t.Errorf("%q: 生年月日として報告した: %q", content, f.Match)
			}
		}
	}
	for _, content := range []string{
		"生年月日\n昭和40年9月8日\n",
		"生年月日: 明治45年3月1日\n", // 1912 年。境界より後は従来どおり
		"1964年2月1日生まれ、東京都出身。\n",
	} {
		n := 0
		for _, f := range d.ScanContent("f.txt", content) {
			if f.RuleID == "jp-birthdate" {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%q: 生年月日の検出数 %d, want 1", content, n)
		}
	}
}

// TestMyNumberTimestampFileName は、URL・ファイル名の中の「<西暦年>-<月日>-<時分>」（CMS が付ける
// PDF の名前）を、検査用数字が偶然一致してもマイナンバーとして報告しないことを確認する。
// ラベル付きの同じ値（URL・ファイル名ではない）は従来どおり報告する。値は検査用数字が合う架空の番号。
func TestMyNumberTimestampFileName(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"https://example.jp/kyouiku/2015-0612-1014.pdf",
		"資料: 2015-0612-1014.pdf",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if f.RuleID == "jp-my-number" {
				t.Errorf("%q: マイナンバーとして報告した: %q", line, f.Match)
			}
		}
	}
	if fs := d.ScanLine("f.txt", 1, "個人番号 2015-0612-1014"); len(fs) != 1 || fs[0].RuleID != "jp-my-number" {
		t.Errorf("ラベル付きの番号を報告しなかった: %v", fs)
	}
}
