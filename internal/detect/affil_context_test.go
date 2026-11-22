package detect

import (
	"strings"
	"testing"
)

// 2026-11-22 の公開文書 7,736 件の確認で見つけた見逃し・誤検出を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）、組織名も架空で、収集した文書の内容は使わない。

// TestAffilContextNames は、括弧の中の「<氏名><学科名>教授」、会議録の委員の異動「委員<氏名>君辞任につき」
// 「補欠として<氏名>君及び<氏名>君が」、「<姓> <名>( <所属> 教授 )」、「<職名> <氏名>）」、「当社 <姓> <名>が」、
// 「社長の<氏名>の」、「<氏名>常務理事」、「理事（理事長） <姓> <名>（重任）」を person-name-role-label で
// 拾うことを確認する。いずれも特定の個人（教員・議員・役員・登壇者）を指す氏名で、個人情報保護法の
// 「特定の個人を識別できる情報」に当たる。実測では、人を指す語のある無作為 461 行の正解（姓+名 61 人）の
// うち、既定モードが拾えたのは 42 人だった。
func TestAffilContextNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"括弧 + 氏名 + 学科名 + 教授", "行動情報科学研究室（山田太郎情報科学科教授）に所属した学生が提案しました。", []string{"山田太郎"}},
		{"括弧 + 氏名 + 研究科 + 准教授", "研究チーム（佐藤花子理工学研究科准教授）が発表", []string{"佐藤花子"}},
		{"委員 + 氏名 + 君辞任", "委員鈴木一郎君辞任につき、その補欠として", []string{"鈴木一郎"}},
		{"委員 + 「長」で始まる氏名 + 君辞任（委員長と読まない）", "委員長谷川健太君辞任につき、その補欠として", []string{"長谷川健太"}},
		{"補欠として + 氏名 + 君及び + 氏名 + 君が", "の補欠として高橋健太君及び田中美咲君が議長の指名で委員に選任された。", []string{"田中美咲", "高橋健太"}},
		{"姓 名 + 括弧の長い所属 + 教授", "[就任]伊藤　直樹( 架空医科大学　医学部・大学院医学研究科　病理学講座機能病態学分野 教授 )", []string{"伊藤 直樹"}},
		{"職名・職名 + 空白 + 氏名 + 括弧の閉じ", "架空医療センター（架空市中央区　理事長・院長　山田太郎）と覚書を締結いたしました。", []string{"山田太郎"}},
		{"括弧 + 職名 + 空白 + 氏名 + 括弧の閉じ", "架空センター（院長　佐藤花子）と協定を結びました。", []string{"佐藤花子"}},
		{"当社 + 空白 + 姓 名 + が", "カンファレンスにおいて、当社 鈴木 一郎が登壇することをお知らせいたします。", []string{"鈴木 一郎"}},
		{"職名 + の + 氏名 + の", "Webメディアに、当社社長の高橋健太のインタビュー記事が掲載されました。", []string{"高橋健太"}},
		{"職名 + の + 氏名 + 氏（氏を範囲に含めない）", "セミナーでは、架空地域事務所長の佐藤隆氏を迎え、分析を紹介しました。", []string{"佐藤隆"}},
		{"首長の職名 + 空白 + 氏名 + 氏 + 括弧の閉じ（氏を範囲に含めない）", "連携協定を締結しました。（調印者：架空町長　鈴木豊氏）", []string{"鈴木豊"}},
		{"氏名 + 常務理事", "事業の支援をしていただいている架空クラブの田中美咲常務理事にも同行いただいた", []string{"田中美咲"}},
		{"理事（理事長） + 姓 名 + （重任）", "    （就任） 理事（理事長）            伊藤 直樹（重任）", []string{"伊藤 直樹"}},
		{"対談 + 氏名 + 様（氏名だけの範囲）", "対談山田太郎様", []string{"山田太郎"}},
		{"行頭の印 + 姓 名 + 括弧の所属 + 職名", "◎佐藤　花子　（元　架空県農林総合研究センター所長）", []string{"佐藤 花子"}},
		{"部門名 + 姓 名 + 括弧の所属 + 職名", "農業環境部門  　鈴木　一郎　（架空工学会専務理事）", []string{"鈴木 一郎"}},
		{"姓 名 + 括弧の所属 + 技術主管", "　高橋　健太　（架空園芸農業協同組合連合会技術主管）", []string{"高橋 健太"}},
		{"姓 名 + 入れ子の括弧の所属 + 顧問", "　田中　美咲　（元　（株）架空土木顧問）", []string{"田中 美咲"}},
		{"姓 名 + 括弧の大学名 + 名誉教授（大学名は氏名にしない）", "　伊藤　直樹　（山形大学名誉教授）", []string{"伊藤 直樹"}},
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

// TestAffilContextNegatives は、同じ形に見えるが個人を指さない行と、亡くなった人の氏名を、既定モードで
// 氏名として報告しないことを確認する。
func TestAffilContextNegatives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"（山形大学名誉教授）",                   // 「<県名>大学」は所属の名前で、姓 + 名ではない
		"◎該当なし　（理事）",                   // 行頭の印 + 一般語
		"研究所所長（元山形大学農学部教授）　講演",         // 「元<県名>」+ 大学は経歴で、姓 + 名ではない
		"第二代所長の山田太郎が編集にあたった業績集",        // 沿革の記述（存命かどうか分からない）
		"初代社長の山田太郎が掲げた創業の精神に則り",        // 会社の沿革の創業者（存命かどうか分からない）
		"共同研究（山口大学工学部教授）の成果",           // 「<県名>大」+ 学部は大学名で、姓 + 1 字の名ではない
		"（情報科学科教授）",                    // 氏名のない所属 + 職名
		"委員長の選任について",                   // 職名 + 一般語
		"委員各位辞任の件",                     // 氏名のない「委員」+ 辞任
		"当社 代表 取締役が出席しました",             // 当社 + 職名
		"当社 営業 企画の担当者よりご連絡します",         // 当社 + 部署名
		"社長の交代理由は次のとおりです。",             // 職名 + の + 一般語
		"会長の選任方法を定める。",                 // 同上
		"理事（非常勤） 募集（新任）",               // 職名 + 一般語 + 就任の区分
		"事務局の常務理事会資料",                  // 氏名のない職名
		"名誉会長（理事長　山田太郎）が、92歳にて永眠しました。", // 亡くなった人（生存する個人の情報ではない）
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestDeceasedNoticeNameNotReported は、訃報・逝去のお知らせの氏名（ラベルに続く値・見出しの氏名）を
// 報告しないことを確認する。個人情報保護法の個人情報は「生存する個人に関する情報」で、亡くなった人の
// 氏名は当たらない（自治体の訃報のお知らせで実測）。同じラベルでも、亡くなったことを示す語のない行と、
// 遺族年金の届出のように存命の人の氏名の行は従来どおり報告する。
func TestDeceasedNoticeNameNotReported(t *testing.T) {
	d := newDetector(t, "")
	for _, content := range []string{
		"１ 概要\n (１) 氏  名：山田 太郎（享年７３歳）\n (２) 逝去日時：令和８年１１月１３日\n",
		"【訃報】架空市長   山田 太郎の逝去について\n\n１ 概要\n (１) 氏  名：山田 太郎（享年７３歳）\n",
	} {
		for _, f := range d.ScanContent("f.txt", content) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", content, f.RuleID, f.Match)
			}
		}
	}
	for _, content := range []string{
		"氏名：山田 太郎\n住所：東京都千代田区千代田1-1\n",
		"遺族年金の請求者 氏名：佐藤 花子\n",
	} {
		found := false
		for _, f := range d.ScanContent("f.txt", content) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: want a person-name finding", content)
		}
	}
}

// TestPaperIDNotMyNumber は、大学の機関リポジトリのページの「内容記述 / <12 桁>」を jp-my-number として
// 報告しないことを確認する。この 12 桁は国立情報学研究所の論文 ID（NAID）で、検査用数字が偶然合うものが
// ある。論文の識別子で、個人の番号ではない。ラベルのない 12 桁と、マイナンバーのラベルが付いた同じ値は
// 従来どおり報告する。値は検査用数字だけを合わせた架空の番号。
func TestPaperIDNotMyNumber(t *testing.T) {
	d := newDetector(t, "")
	for _, content := range []string{
		"内容記述\n110007123450\n言語\n",
		"内容記述: 110007123450\n",
		"NAID 110007123450\n",
	} {
		for _, f := range d.ScanContent("f.txt", content) {
			if f.RuleID == "jp-my-number" {
				t.Errorf("%q: unexpected %s %q", content, f.RuleID, f.Match)
			}
		}
	}
	for _, content := range []string{
		"備考\n110007123450\n",
		"マイナンバー\n110007123450\n",
	} {
		found := false
		for _, f := range d.ScanContent("f.txt", content) {
			if f.RuleID == "jp-my-number" {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: want a jp-my-number finding", content)
		}
	}
}

// TestHonorificRoleAndClanNotReported は、高再現率モードで、立場・施設・職種を指す一般語に付く敬称と、
// 歴史上の一族を指す「<氏族名>氏」を報告しないことを確認する。いずれも特定の生存する個人を指さない
// （不動産会社の案内・システム会社の案内・国会の会議録・自治体の文化財の案内で実測）。
func TestHonorificRoleAndClanNotReported(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{
		"貸主様・借主様 | 賃貸ご検討中のお客様",
		"・施設様のニーズに合わせたシステム環境の構築が可能です",
		"院長がおっしゃったとおり、看護婦さんたちの評判がとてもいいんです。",
		"この地は毛利氏の支配下にあった。",
		"1．今川氏・織田氏の系譜",
		"種子島氏の居城であったと伝わる。",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
	// 「対談<氏名>様」は「対談」を氏名の範囲に含めない。
	for _, f := range d.ScanLine("f.txt", 1, "対談山田太郎様") {
		if strings.HasPrefix(f.RuleID, "person-name") && f.Match != "山田太郎" {
			t.Errorf("unexpected span %s %q", f.RuleID, f.Match)
		}
	}
	// 姓 + 氏・姓 + 様は従来どおり報告する。
	for _, line := range []string{
		"毛利氏からお話を伺いました。",
		"問合せ先：架空県　山田様",
	} {
		found := false
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: want a person-name finding", line)
		}
	}
}
