package detect

import (
	"strings"
	"testing"
)

// 2026-11-13 の公開文書 2,179 件の確認で見つけた見逃し・誤検出を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）、組織名・催し名も架空で、収集した文書の内容は使わない。

// TestMinutesContextNames は、会議録の指名・当選・発言者ラベル・名乗りと、お知らせの本文の
// 「<氏名>先生に」「<職名>の<氏名>が、」「<職名> <氏名>／」「<氏名> 教授ら」「<姓> <名> 議員」を
// person-name-role-label で拾うことを確認する。いずれも特定の個人（議員・役員・教員・講師）を
// 指す氏名で、個人情報保護法の「特定の個人を識別できる情報」に当たる。実測では、手がかりのある
// 無作為 120 行と無作為 30 文書の姓+名 30 人のうち、既定モードが拾えたのは 15 人だった。
func TestMinutesContextNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		// 会議録の指名・当選・補欠選任（国会・地方議会の定型）
		{"君を指名", "　架空委員長に山田太郎君を指名いたします。", []string{"山田太郎"}},
		{"君が当選", "　佐藤花子君が委員長に当選した。", []string{"佐藤花子"}},
		{"補欠として君が当選", "その補欠として鈴木一郎君が理事に当選した。", []string{"鈴木一郎"}},
		{"及び + 君が辞任", "高橋健太君及び田中美咲君が委員を辞任され、", []string{"田中美咲"}},
		// 地方議会の発言者ラベル（「君」なし・行の途中・ひらがなの名）
		{"発言者ラベル", "○副市長（伊藤直樹） 私からは、大きく２点お答えします。", []string{"伊藤直樹"}},
		{"発言者ラベル（ひらがなの名）", "強化に向けた    ○副議長（佐藤はなこ） 架空副市長。", []string{"佐藤はなこ"}},
		{"発言者ラベル（空白区切り）", "○教育長（鈴木 一郎） お答えします。", []string{"鈴木 一郎"}},
		// 会議録の名乗り
		{"名乗り（でございます）", "　この度、架空委員長に就任いたしました高橋健太でございます。", []string{"高橋健太"}},
		{"名乗り（職名の）", "　架空副大臣の田中美咲でございます。", []string{"田中美咲"}},
		{"名乗り（と申します）", "架空政務官を拝命いたしました伊藤直樹と申します。", []string{"伊藤直樹"}},
		// 「<氏名>先生」+ 助詞
		{"先生に", "講演会「架空の絵本」の山田太郎先生に聞く", []string{"山田太郎"}},
		{"先生、", "架空大学の佐藤花子先生、架空研究所の鈴木一郎先生と続きます", []string{"佐藤花子", "鈴木一郎"}},
		// 「<職名>の<氏名>が、」
		{"CFOの氏名が、", "決算説明会で、取締役 専務執行役員 CFOの高橋健太が、業績を説明しました。", []string{"高橋健太"}},
		// 「<職名> <氏名>／<団体名>」
		{"理事 + スラッシュ", "専務理事 田中美咲／一般社団法人 架空協会", []string{"田中美咲"}},
		// 「<所属> <氏名> 教授らの」
		{"教授ら", "架空化学系 伊藤直樹 教授らの研究グループは、新しい色素を開発しました", []string{"伊藤直樹"}},
		// 助詞の後の「<氏名>准教授・<氏名>教授」
		{"助詞の後の職名", "公開プレゼンテーションに山田太郎准教授・佐藤花子教授が登壇", []string{"山田太郎", "佐藤花子"}},
		// 「<姓> <名> 議員」だけの行
		{"議員の行", "鈴木 一郎 議員", []string{"鈴木 一郎"}},
		// 敬称の後に「など」「表敬」「～」が続く形
		{"さんなど", "起業家の高橋健太さんなど、世界で活躍する方々をお招きします", []string{"高橋健太"}},
		{"さん表敬訪問", "架空大会出場 田中美咲さん、伊藤直樹さん表敬訪問", []string{"田中美咲", "伊藤直樹"}},
		{"である + さん", "この著者である山田太郎さん、第一人者として活躍されています", []string{"山田太郎"}},
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

// TestMinutesContextNegatives は、同じ語彙を含むが個人を指さない行を氏名として報告しないことを
// 確認する（姓だけ・一般語・組織名・職名だけ）。
func TestMinutesContextNegatives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"委員長に山田君を指名いたします。",        // 姓だけ
		"架空課長の山田でございます。",          // 姓だけの名乗り
		"本日は通常国会でございます。",          // 一般語
		"担任の先生に相談してください。",         // 一般語 + 先生
		"保健室の先生が対応します。",           // 部屋 + 先生
		"社長の経営方針が、全社員に示されました。",    // 職名 + の + 一般語
		"○議長（架空市議会） これより会議を開きます。", // 括弧内が組織名
		"専務理事 選任の件／架空協会",          // 職名 + 議題
		"市議会 議員", // 氏名のない行
		"架空大学の教授らの研究グループ", // 氏名のない職名
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 氏名として報告した: %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestLetterSpacedWordNotName は、項目行の次の行にある字間を空けた見出し語（主 催・概 要）と、
// 折り返しで 1 字目だけが離れた文の断片（整 備する・援 を行う）を person-name として報告しない
// ことを確認する。見出し語や文の断片は個人を指さない。実測では既定モードの person-name の
// 無作為 50 件のうち 8 件がこの形の偽陽性だった。
func TestLetterSpacedWordNotName(t *testing.T) {
	d := newDetector(t, "")
	for _, content := range []string{
		"（主催:独立行政法人架空支援機構）\n概 要\n9時00分～17時00分\n",
		"申込先: https://example.com/form\n主 催\n架空商工会議所\n",
		"目標: 学修環境を\n整 備する。\n",
		"方針: 点検・評価の支\n援 を行う。\n",
		"計画: 入学前教育の充\n実 を図る。\n",
	} {
		for _, f := range d.ScanContent("f.txt", content) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 氏名として報告した: %q", content, f.Match)
			}
		}
	}
	// 同じ並びでも、空白区切りの氏名はこれまでどおり拾う。
	found := false
	for _, f := range d.ScanContent("f.txt", "受付番号: A-001\n山田 太郎\n生年月日: 1990年1月1日\n") {
		if f.RuleID == "person-name" && f.Match == "山田 太郎" {
			found = true
		}
	}
	if !found {
		t.Error("項目行の次の行の氏名を検出できない")
	}
}

// TestHandleDigitsNotMyNumber は、「@<12 桁>」（SNS・技術記事サイトのユーザー名）を個人番号として
// 報告しないことを確認する。数字だけのユーザー名は 1/11 の確率で検査用数字が一致するが、
// 個人番号ではない。番号は検査用数字が一致する架空の値。
func TestHandleDigitsNotMyNumber(t *testing.T) {
	d := newDetector(t, "")
	const n = "123456789018"
	for _, f := range d.ScanLine("f.txt", 1, "フォロー @"+n) {
		if f.RuleID == "jp-my-number" {
			t.Errorf("@ に直結する数字列を個人番号として報告した: %q", f.Match)
		}
	}
	found := false
	for _, f := range d.ScanLine("f.txt", 1, "個人番号 "+n) {
		found = found || f.RuleID == "jp-my-number"
	}
	if !found {
		t.Error("ラベル付きの個人番号を検出できない（テストの番号の検査用数字を確認）")
	}
}

// TestHighRecallHonorificWords は、高再現率モードで「喪主様」「施主様」「<劇団名>王様」と、読みに
// 「うじ」を含む歴史上の人物（<姓>氏<1 字>（…うじ…））を敬称付きの氏名として報告しないことを確認する。
func TestHighRecallHonorificWords(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{
		"喪主様名義の振込先口座のわかるもの",
		"施主様とのお打ち合わせ",
		"「架空劇団王様」が同行できる場合があります。",
		"架空氏貞（かくううじさだ）【戦国武将】",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 氏名として報告した: %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}
