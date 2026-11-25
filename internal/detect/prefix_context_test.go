package detect

import (
	"strings"
	"testing"
)

// 2026-11-15 の公開文書 2,659 件の確認で見つけた見逃し・誤検出を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）、組織名・催し名も架空で、収集した文書の内容は使わない。

// TestPrefixContextNames は、活用語尾・接続の語・カタカナ語に直結する氏名、氏名と職名の間に空白が
// 入る形、名がひらがなの氏名 + さん、委員長 + 氏名 + 君を person-name-role-label で拾うことを確認する。
// いずれも特定の個人（教員・学生・選手・監督・役員・議員）を指す氏名で、個人情報保護法の
// 「特定の個人を識別できる情報」に当たる。実測では、人を指す語のある無作為 350 行（設計用）の
// 姓+名 54 人のうち、既定モードが拾えたのは 29 人だった。
func TestPrefixContextNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		// 活用語尾・接続の語・「同」に直結する氏名 + 職名・敬称
		{"する + 会長（行末）", "表彰式に出席する佐藤花子会長", []string{"佐藤花子"}},
		{"する / た + 氏", "自然との調和を追求する鈴木一郎氏と、「架空リング」を手掛けた高橋健太氏、 建築家2名", []string{"鈴木一郎", "高橋健太"}},
		{"講師および講師", "医学部の田中美咲講師および伊藤直樹講師が出展しました", []string{"田中美咲", "伊藤直樹"}},
		{"同 + 准教授", "架空大学の佐藤花子教授、同鈴木一郎准教授、架空大学", []string{"佐藤花子", "鈴木一郎"}},
		{"である + さん", "卒業生であり、指導士でもある高橋健太さんが講師を担当しました", []string{"高橋健太"}},
		// カタカナ語に直結する氏名
		{"職業名のカタカナ + さん", "婚活アドバイザー田中美咲さんによるオンライン個別面談", []string{"田中美咲"}},
		{"競技名のカタカナ + 選手", "デフサッカー伊藤直樹選手を新たにスポーツ大使に委嘱！", []string{"伊藤直樹"}},
		{"チーム名 + 監督", "カクウスターズ佐藤花子監督らが本学を訪問", []string{"佐藤花子"}},
		{"チーム名 + 空白区切り + 選手", "カクウソックス鈴木 一郎選手「ボブルヘッド人形」デザイン公開", []string{"鈴木 一郎"}},
		{"事業名 + 選手 + 催し名", "記念事業　高橋健太選手体操教室＆トークショー", []string{"高橋健太"}},
		// 氏名と職名の間に空白が入る形
		{"氏名 + 空白 + 先生 + 英字", "田中美咲 先生Webページ", []string{"田中美咲"}},
		{"空白区切り + 助教（", "\t伊藤 直樹 助教（情報学研究系）とその研究チームによる論文", []string{"伊藤 直樹"}},
		{"の + 氏名 + 空白 + 教授が", "本学工学部機械工学科の佐藤花子 教授が感謝状を授与", []string{"佐藤花子"}},
		// 職名 + 空白 + 氏名 + 助詞
		{"学長 + から", "学長 鈴木一郎からのメッセージ", []string{"鈴木一郎"}},
		{"CEO + 空白区切り + が", "弊社代表取締役社長・CEO 高橋 健太が「架空章」を受章", []string{"高橋 健太"}},
		// 名がひらがなの氏名 + さん
		{"ひらがなの名 + さん", "田中さくらさんと架空市長の対談動画", []string{"田中さくら"}},
		// 会議録の委員長報告の指名
		{"委員長 + 君。", "まず、委員長の報告を求めます。農林水産委員長伊藤直樹君。", []string{"伊藤直樹"}},
		// コロン + 氏名 + 所属 + 職名 + 本文
		{"コロン + 所属 + 職名", "2012年12月21日：佐藤 花子 架空大学特別栄誉教授 フェローに選出", []string{"佐藤 花子"}},
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

// TestPrefixContextNegatives は、同じ形に見えるが個人を指さない行を氏名として報告しないことを確認する
// （姓 + 職名の一部、選手権・選手団・監督官、一般語 + 職名、ひらがなの一般語 + さん）。
func TestPrefixContextNegatives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"ノーベル賞を受賞した山田栄誉教授の研究とは", // 姓 + 栄誉教授（名ではない）
		"当時の山田厚生大臣が私見を述べた",      // 姓 + 厚生大臣
		"海洋研究開発機構の山田主任研究員らの研究",  // 姓 + 主任研究員
		"世界選手権大会に出場する日本代表選手団",   // 選手権・選手団
		"プロ野球選手会が声明を発表した",       // 選手会
		"労働基準監督署の監督官が調査する",      // 監督官・監督署
		"決勝大会監督会議のお知らせ",         // 監督会議
		"学長 選考会議からの報告",          // 職名 + 会議名
		"会長 挨拶より",               // 職名 + 一般語
		"社長 山田 部長が出席",           // 姓 + 職名
		"森のくまさんと遊ぼう",            // ひらがなの一般語 + さん
		"高齢のみなさんと交流しました",        // みなさん
		"出席した各委員会長",             // 連体修飾 + 組織 + 職名
		"委員長報告のとおり決するに賛成の諸君。",   // 諸君
		"山口 大学 教授が講演",           // 地名 + 大学 + 職名
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 氏名として報告した: %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestGluedOrgLabelEmail は、「<村名>役場<アドレス>」のように窓口の名前が空白なしで直前に付く
// メールアドレスを、ASCII の部分だけの範囲で email-address として報告することを確認する
// （村役場の問い合わせ先で実測した全モードの見逃し。高再現率では組織名ごと email-address-eai に
// 取り込んでいた）。入力欄の説明の「入力例：<アドレス>」は例示なので報告しない。
func TestGluedOrgLabelEmail(t *testing.T) {
	for _, cfg := range []string{"", "[rules]\nhigh_recall = true\n"} {
		d := newDetector(t, cfg)
		var got []string
		for _, f := range d.ScanLine("f.txt", 1, "架空村役場madoguchi@home.arpa") {
			got = append(got, f.RuleID+":"+f.Match)
		}
		if strings.Join(got, "|") != "email-address:madoguchi@home.arpa" {
			t.Errorf("cfg %q: got %q", cfg, got)
		}
		for _, line := range []string{"入力例：taro@home.arpa", "記入例: taro@home.arpa"} {
			for _, f := range d.ScanLine("f.txt", 1, line) {
				t.Errorf("cfg %q: %q: 例示を報告した: %s %q", cfg, line, f.RuleID, f.Match)
			}
		}
		// 「例：」だけの形と、本文中のアドレスは従来どおり報告する。
		if fs := d.ScanLine("f.txt", 1, "連絡先（例：taro@home.arpa）"); len(fs) != 1 {
			t.Errorf("cfg %q: 例：のアドレスを報告しなかった: %v", cfg, fs)
		}
	}
}

// TestHighRecallOrgAndPatternHonorifics は、高再現率モードで「日銀さん」（中央銀行の略称）と
// かぎ括弧で囲んだ「菊文様」（模様の名前）を氏名として報告しないことと、同じ形の氏名は
// 従来どおり報告することを確認する。
func TestHighRecallOrgAndPatternHonorifics(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{
		"○架空委員　日銀さんの意見は分かりましたので、次に移ります。",
		"この絵柄に採用したのは、「菊文様」と「波流水」。",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 氏名として報告した: %s %q", line, f.RuleID, f.Match)
			}
		}
	}
	found := false
	for _, f := range d.ScanLine("f.txt", 1, "寄付者　山田　美文様") {
		if strings.HasPrefix(f.RuleID, "person-name") {
			found = true
		}
	}
	if !found {
		t.Error("「<姓>　<名>文様」の氏名を報告しなかった")
	}
}
