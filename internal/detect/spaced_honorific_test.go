package detect

import (
	"strings"
	"testing"
)

// 2026-11-14 の公開文書 7,083 件の確認で見つけた見逃し・誤検出を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）、組織名・催し名も架空で、収集した文書の内容は使わない。

// TestSpacedHonorificNames は、姓と名の間に空白を入れた氏名に敬称・職名・所属が続く表記と、
// 決算短信の欄がつながった表紙、構成員名簿の行、役割のラベル + コロンを person-name-role-label で
// 拾うことを確認する。いずれも特定の個人（学生・受賞者・委員・役員・議員・講師）を指す氏名で、
// 個人情報保護法の「特定の個人を識別できる情報」に当たる。実測では、手がかりのある無作為 150 行の
// 姓+名 36 人のうち、既定モードが拾えたのは 16 人だった（見逃しの大半がこの形）。
func TestSpacedHonorificNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		// 空白区切りの姓名 + 敬称（学生紹介・受賞者・会員名簿）
		{"さん + 出身校（空白あり）", "佐藤 花子 さん架空県立架空高等学校 出身", []string{"佐藤 花子"}},
		{"入選 + さん（学年）", "【毛筆部門・入選】 鈴木 一郎さん（2年生）", []string{"鈴木 一郎"}},
		{"全角空白 + 君", "高橋　健太　君", []string{"高橋　健太"}},
		{"空白 2 個 + 氏", "主任技術者  田中  美咲 氏 ", []string{"田中  美咲"}},
		{"助詞の後のさん（列挙）", "建築大工の伊藤　直樹さん、電気工事士の佐藤　花子さん", []string{"伊藤　直樹", "佐藤　花子"}},
		{"作者 + 様 + 括弧", "作者：鈴木　一郎　様　(架空市)", []string{"鈴木　一郎"}},
		{"先生より", "架空センター所長の高橋 健太 先生よりお祝いの挨拶が述べられました", []string{"高橋 健太"}},
		{"辞書にない名 + さん", "田中 架羽さんが受賞しました", []string{"田中 架羽"}},
		// 名簿の行頭の姓名 + 職名
		{"行頭 + 委員", "伊藤　直樹委員　　架空地区街づくり協議会相談役", []string{"伊藤　直樹"}},
		{"行頭 + 議員", "佐藤 花子議員 質問資料(PDFファイル:1.6MB)", []string{"佐藤 花子"}},
		// 構成員名簿の「<姓>  <名>      <所属><職名>」
		{"構成員名簿", "鈴木  一郎        架空省大臣官房総括審議官", []string{"鈴木  一郎"}},
		// 氏名（<所属>）
		{"括弧の所属（大学）", "高橋 健太（架空大学） 11.超伝導", []string{"高橋 健太"}},
		{"括弧の所属（中学校）", "田中 美咲（架空市立架空中学校3年生）", []string{"田中 美咲"}},
		// 決算短信の欄がつながった表紙
		{"決算短信（欄がつながる）", "代表者（役職名）代表取締役社長（氏名）伊藤　直樹問合せ先責任者（役職名）財務部長（氏名）佐藤　花子TEL  00-0000-0000", []string{"伊藤　直樹", "佐藤　花子"}},
		// 役割のラベル + コロン
		{"撮影：", "架空町place（撮影：鈴木一郎）", []string{"鈴木一郎"}},
		{"総合司会：", "総合司会：高橋 健太（架空学会会長）", []string{"高橋 健太"}},
		{"モデレーター：", "質疑応答（モデレーター：田中 美咲　架空研究所主任研究員）", []string{"田中 美咲"}},
		// 敬称・職名の後ろの語を増やした形
		{"さん来社", "2026年度入社式 伊藤直樹さん来社", []string{"伊藤直樹"}},
		{"さん出演", "佐藤花子さん出演の動画を公開します", []string{"佐藤花子"}},
		{"選手/", "（鈴木一郎選手/教育学部3年、高橋健太選手/教育学部1年）", []string{"鈴木一郎", "高橋健太"}},
		{"衆議院議員", "この場所における田中美咲衆議院議員の、発言がありました", []string{"田中美咲"}},
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

// TestSpacedHonorificNegatives は、同じ形に見えるが個人を指さない行を氏名として報告しないことを
// 確認する（部署 + 職名、欄名、国名、様式・氏名・選手権の一部、姓 + 職名）。
func TestSpacedHonorificNegatives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"事務室 管理課長 廃棄",          // 部署 + 課名 + 職名（文書管理簿）
		"取締役 監査等委員",            // 役職の並び
		"指名委員 監査委員",            // 委員会の役の並び
		"衆議院 議院運営委員会 第29号",     // 会議名
		"写真：山田社長、佐藤学長",         // 姓 + 職名（氏名ではない）
		"著者／発表者",               // 欄名
		"山田 部長 様",              // 姓 + 職名 + 敬称
		"申請者 氏名 様式",            // 欄名 + 様式
		"山口 事務所（架空法人）",         // 地名 + 事務所
		"東 日本 様",               // 方角 + 国名
		"学 年  実施時期  サポート内容",    // 表の見出し
		"架空市  総務部  契約管財課",      // 部署の並び
		"場　　所　　架空会館（架空市中央区）",   // 字間を空けた欄名
		"佐藤 花子氏名",              // 「氏名」の「氏」
		"鈴木 一郎選手権",             // 「選手権」の一部
		"お客 様 各位",              // 一般語
		"（氏名）　　　　　　　問合せ先（役職名）", // 空欄の表紙
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 氏名として報告した: %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestURLLineIsNotFieldLine は、URL だけの行を「https」欄の項目行と読んで、次の行の
// 「<社名のカタカナ> <国名>」を氏名（person-name）にしないことを確認する。海外拠点の一覧の
// 拠点名は法人の名称で、個人を指さない（既定モードの person-name の無作為 60 件中 1 件）。
func TestURLLineIsNotFieldLine(t *testing.T) {
	d := newDetector(t, "")
	content := "https://www.example.com/\n\nカクウ 英国\n\nKakuu UK Ltd.\n"
	for _, f := range d.ScanContent("f.txt", content) {
		if strings.HasPrefix(f.RuleID, "person-name") {
			t.Errorf("氏名として報告した: %q", f.Match)
		}
	}
}

// TestPagerDigitsNotBankAccount は、ニュース一覧のページ送り「1234567...22」を、前の行の
// 「<銀行名>」を文脈に口座番号として報告しないことを確認する（ページ番号は個人情報ではない）。
// 区切りのある通常の口座番号は従来どおり報告する。
func TestPagerDigitsNotBankAccount(t *testing.T) {
	d := newDetector(t, "")
	for _, f := range d.ScanContent("f.txt", "架空大学と架空銀行が協定書を締結\n\n1234567...22\n") {
		if f.RuleID == "jp-bank-account" {
			t.Errorf("ページ送りを口座番号として報告した: %q", f.Match)
		}
	}
	found := false
	for _, f := range d.ScanLine("f.txt", 1, "口座番号：0012345") {
		found = found || f.RuleID == "jp-bank-account"
	}
	if !found {
		t.Error("通常の口座番号を報告しなかった")
	}
}

// TestHighRecallHonorificCommonWords2 は、高再現率モードで職名・政党・拠点・生き物 + 敬称と、
// 「<地名>さんさ踊り」を氏名として報告しないことを確認する（いずれも特定の個人を指さない。
// 高再現率の敬称氏名の無作為 50 件中 7 件がこの種の偽陽性だった）。姓名 + 敬称は従来どおり拾う。
func TestHighRecallHonorificCommonWords2(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{
		"これも、指導主事さんとしては大変大きな仕事でございます。",
		"知事さんや議会の方にもきちっと通知をする",
		"先ほどの質疑の中で、架空党さんがよくおっしゃいます。",
		"架空生活協同組合第2支所様",
		"動画「恐竜さんと行く！駅舎見学会」を公開しました",
		"懇親会では、架空さんさ踊りも見せてもらいました",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 氏名として報告した: %s %q", line, f.RuleID, f.Match)
			}
		}
	}
	found := false
	for _, f := range d.ScanLine("f.txt", 1, "佐藤花子さんに確認した") {
		found = found || strings.HasPrefix(f.RuleID, "person-name")
	}
	if !found {
		t.Error("姓名 + 敬称を報告しなかった")
	}
}

// TestEAIAbsorbedLabelText は、高再現率モードの email-address-eai が、和文のラベルや本文が
// ローカル部に吸着した候補と、例示の語（学籍番号@・アカウント＠）を報告しないことを確認する
// （実測の 8 件はすべてこの形。例示は実在のアドレスではない）。吸着した後ろの ASCII のアドレスは
// email-address が単独で報告し、日本語のローカル部を持つ本物の EAI は従来どおり報告する。
func TestEAIAbsorbedLabelText(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	ids := func(line string) map[string]string {
		out := map[string]string{}
		for _, f := range d.ScanLine("f.txt", 1, line) {
			out[f.RuleID] = f.Match
		}
		return out
	}
	for _, line := range []string{
		"ファクス00-0000-0000　電子メールkakuu-info@baneido.com",
		"（E-mailの場合は各施設ともkakuu-incident@baneido.com）",
	} {
		got := ids(line)
		if m, ok := got["email-address-eai"]; ok {
			t.Errorf("%q: 和文が吸着した候補を報告した: %q", line, m)
		}
		if m := got["email-address"]; !strings.HasPrefix(m, "kakuu-") {
			t.Errorf("%q: ASCII のアドレスを報告しなかった（%v）", line, got)
		}
	}
	for _, line := range []string{
		"※大学のアカウント（学籍番号@baneido.com）でのログインが必要です。",
		"大学が発行するアドレス（Kakuu Mail用アカウント＠baneido.com）が必要です。",
		"本システムにおいてご登録いただいた@baneido.com のメールアドレスに送信できない",
	} {
		if got := ids(line); len(got) != 0 {
			t.Errorf("%q: 例示・文の断片を報告した: %v", line, got)
		}
	}
	if _, ok := ids("連絡は 山田太郎@baneido.com まで")["email-address-eai"]; !ok {
		t.Error("日本語のローカル部を持つ EAI を報告しなかった")
	}
}
