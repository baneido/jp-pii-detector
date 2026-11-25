package detect

import (
	"strings"
	"testing"
)

// 2026-11-21 の公開文書 15,575 件の確認で見つけた見逃し・誤検出を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）、組織名も架空で、収集した文書の内容は使わない。

// TestHonorificContextNames は、行末・空白・括弧に続く「<氏名>さん」「<氏名> 氏」、「<職名> <氏名>が」
// 「<職名> <氏名>様」、「<職名>・<氏名>の」、「<職業><氏名>さん」、「<姓> <名>特別任用教授 最終講義」、
// 「<姓> <名> 教授 (<読み>)」を person-name-role-label で拾うことを確認する。
// いずれも特定の個人（受賞者・登壇者・役員・教員・来賓）を指す氏名で、個人情報保護法の
// 「特定の個人を識別できる情報」に当たる。実測では、人を指す語のある無作為 450 行の正解（姓+名 98 人）の
// うち、既定モードが拾えたのは 79 人だった。
func TestHonorificContextNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"所属 + 空白 + 氏名 + さんで行末", "国際文化学科2年　山田太郎さん", []string{"山田太郎"}},
		{"見出し + 中黒 + 氏名 + 氏で行末", "研究内容説明・佐藤花子氏", []string{"佐藤花子"}},
		{"学年 + 空白 + 氏名 + さんで行末", "3年 鈴木一郎さん", []string{"鈴木一郎"}},
		{"氏名 + 空白 + 氏で行末", "講　師　　高橋健太　氏", []string{"高橋健太"}},
		{"読点で並ぶ氏名 + 氏", "編者：田中美咲氏、伊藤直樹氏", []string{"田中美咲", "伊藤直樹"}},
		{"氏名 + さん + かぎ括弧", "【観劇日誌】山田太郎さん「ことばの重さ」を掲載しました", []string{"山田太郎"}},
		{"氏名 + さん + カタカナの語", "録音技師　佐藤花子さんトークショー", []string{"佐藤花子"}},
		{"氏名 + さん + です", "ゲストは、プロダクトデザイナー・鈴木一郎さんでした。", []string{"鈴木一郎"}},
		{"氏名 + 氏 + からの", "「架空アンバサダー」高橋健太氏からの特別メッセージ", []string{"高橋健太"}},
		{"職名 + 空白 + 氏名 + が", "架空インテリジェンス 代表 田中美咲が特集に掲載されました", []string{"田中美咲"}},
		{"職名 + 空白 + 姓 名 + の", "架空株式会社 ブランディングチーム 部長 伊藤 直樹のコメント", []string{"伊藤 直樹"}},
		{"職名 + 空白 + 姓 名 + より", "【新規事業開発本部 本部長 山田 太郎より】", []string{"山田 太郎"}},
		{"首長の職名 + 空白 + 氏名 + 様", "架空市長　佐藤花子様", []string{"佐藤花子"}},
		{"職名 + 空白 + 氏名 + 空白 + 様 + から", "架空クラブ　会長　鈴木一郎 様から寄付金をいただきました", []string{"鈴木一郎"}},
		{"職名・氏名 + の", "このたび、架空法人理事長・高橋健太の新刊が出版されます。", []string{"高橋健太"}},
		{"職名・氏名 + が", "番組に弊社代表取締役社長・田中美咲が出演します。", []string{"田中美咲"}},
		{"職業 + 氏名 + さん", "【受付終了】絵本作家伊藤直樹さんとみんなでつくる大きな絵", []string{"伊藤直樹"}},
		{"卒業生 + 氏名 + さん", "11/30卒業生山田太郎さんが出演した番組", []string{"山田太郎"}},
		{"姓 名 + 特別任用教授 + 空白", "【1月13日（水）】佐藤 花子特別任用教授 最終講義", []string{"佐藤 花子"}},
		{"姓 名 + 空白 + 教授 + 括弧の読み", "鈴木 一郎 教授 (スズキ イチロウ)", []string{"鈴木 一郎"}},
		{"氏名 + 専任講師", "海洋生物学科の高橋健太専任講師が受賞しました", []string{"高橋健太"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, f := range d.ScanLine("f.txt", 1, tt.line) {
				if f.RuleID == "person-name-role-label" {
					got = append(got, strings.Join(strings.Fields(strings.ReplaceAll(f.Match, "　", " ")), " "))
				}
			}
			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Fatalf("%q: got %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// TestHonorificContextNegatives は、同じ形に見えるが個人を指さない行・亡くなった人・高再現率モードの
// 範囲として残す形を、既定モードで氏名として報告しないことを確認する。
func TestHonorificContextNegatives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"山田太郎様", // 「様」だけの行は高再現率モードの範囲（宛名・記入欄）
		"ゆかりのある山田太郎氏より寄贈", // ひらがなに直結する形は高再現率モードの範囲
		"記入欄：山田太郎氏名",      // 「氏名」の「氏」
		"新商品開発さん",         // 一般語 + さん
		"先輩各位さん",          // 一般語 + さん
		"○山田国務大臣　根本的には、国際競争力が非常に落ちている。", // 会議録の発言者の印の後は発言の本文
		"○山田国務大臣　瀬戸内海の水質保全を図る観点から",      // 同上（地名）
		"部長 会議室の予約について",                 // 職名 + 一般語 + の
		"代表 取締役が出席しました",                 // 職名 + 職名
		"会長・副会長の選任について",                 // 職名・職名 + の
		"名誉会長・山田太郎が、92歳にて永眠しました。",       // 亡くなった人（生存する個人の情報ではない）
		"昨年12月に逝去された 山田太郎さん",            // 同上
		"特別任用教授 募集要項",                   // 職名 + 一般語
		"研究 開発教授 募集",                    // 一般語の並び + 職名
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
	// 行全体が氏名 + 敬称だけの行は、前後の行に文があっても既定モードでは報告しない
	// （検出器は隣り合う 2 行をつないで走査するので、行頭・行末は物理行で判定する）。
	for _, f := range d.ScanContent("f.txt", "受賞者の一覧です\n山田太郎さん\n佐藤花子氏\n以上です\n") {
		if strings.HasPrefix(f.RuleID, "person-name") {
			t.Errorf("unexpected %s %q", f.RuleID, f.Match)
		}
	}
	// 「<職名> <姓> <名>先生は」は敬称まで値に含めず、氏名だけを報告する。
	for _, f := range d.ScanLine("f.txt", 1, "9回目の記事では、専任講師　山田 花子先生が解説します。") {
		if strings.HasPrefix(f.RuleID, "person-name") && strings.Contains(f.Match, "先生") {
			t.Errorf("unexpected span %q", f.Match)
		}
	}
}

// TestHonorificOrgAndProseNotReported は、高再現率モードで、事業者・官署・役割の語に付く「様」「さん」と、
// 説明の文の一部の「…が@<ドメイン>」を報告しないこと、職業の語を氏名の範囲に含めないことを確認する。
// いずれも特定の個人を指さない（企業・官公署・取引先の種類・手続き上の立場・アドレスの説明）。
func TestHonorificOrgAndProseNotReported(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{
		"架空ソフト、架空自動織機様のAI自動補正システムの構築を支援",
		"wk_10727558_01_osx架空開発様_決議_P.doc",
		"特約店様向け情報",
		"製造業様向けDXサービス　カタログ",
		"【地域共創】架空市消防局様の事例を公開しました",
		"架空県警察様より感謝状をいただきました",
		"法定代理人様のご署名が必要です",
		"世帯主様あてに通知をお送りします",
		"連絡方法は、学園指定アドレス（ドメインが@example.ac.jp）のみを使用します。",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") || strings.HasPrefix(f.RuleID, "email") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
	// 職業の語は氏名の範囲に含めない。
	for _, f := range d.ScanLine("f.txt", 1, "【受付終了】絵本作家山田太郎さんとみんなでつくる大きな絵") {
		if strings.HasPrefix(f.RuleID, "person-name") && f.Match != "山田太郎" {
			t.Errorf("unexpected span %s %q", f.RuleID, f.Match)
		}
	}
	// 敬称の後に漢字が続く形でも、高再現率モードでは職業・立場の語を除いた氏名を報告する。
	found := false
	for _, f := range d.ScanLine("f.txt", 1, "博士前期課程修了生山田太郎さん研究発表") {
		if strings.HasPrefix(f.RuleID, "person-name") && f.Match == "山田太郎" {
			found = true
		}
	}
	if !found {
		t.Errorf("修了生 + 氏名 + さん: want 山田太郎")
	}
	// 敬称付きの氏名と、通常のメールアドレスは従来どおり報告する。
	for line, prefix := range map[string]string{
		"寄付ありがとうございます（山田太郎様）":         "person-name",
		"連絡先: info@home.arpa": "email",
	} {
		found := false
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, prefix) {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: want a %s finding", line, prefix)
		}
	}
}
