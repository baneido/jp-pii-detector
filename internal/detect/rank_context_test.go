package detect

import (
	"strings"
	"testing"
)

// 2026-11-19 の公開文書 4,541 件の確認で見つけた見逃し・誤検出を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）、組織名・URL・番号も架空で、収集した文書の内容は使わない。

// TestRankContextNames は、氏名に直結する職名（栄誉教授・診療講師・技師・課長）、空白区切りの氏名に
// 直結する職名、職名 + 氏名 + 括弧、「社長・<氏名>）」、「CEO <氏名>」の行末、「<所属>の<氏名>教授が」を
// person-name-role-label で拾うことを確認する。
// いずれも特定の個人（教員・技術職員・役員・職員）を指す氏名で、個人情報保護法の
// 「特定の個人を識別できる情報」に当たる。実測では、人を指す語のある無作為 440 行の正解（姓+名 81 人）の
// うち、既定モードが拾えたのは 61 人だった。
func TestRankContextNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"氏名 + 栄誉教授", "架空賞レポート 2016 山田太郎栄誉教授 | 架空大学", []string{"山田太郎"}},
		{"括弧の中の氏名 + 技師", "優秀表彰を受賞(佐藤一郎教授、鈴木健太技師)", []string{"佐藤一郎", "鈴木健太"}},
		{"氏名 + 課長インタビュー", "【新館ができるまで】高橋健太課長インタビュー記事を公開しました", []string{"高橋健太"}},
		{"氏名 + 診療講師ら", "循環器内科学の鈴木一郎診療講師らの研究グループは、", []string{"鈴木一郎"}},
		{"空白区切りの氏名 + 職名", "副センター長の田中 美咲特任准教授が、伊藤 直樹学長の代理として訪問しました。", []string{"田中 美咲", "伊藤 直樹"}},
		{"職名 + 氏名 + 括弧", "架空大地域総合学部准教授 鈴木一郎（架空市）", []string{"鈴木一郎"}},
		{"社長・氏名）", "架空製菓株式会社（架空県架空市、代表取締役社長・山田 太郎）は、新商品を発売します。", []string{"山田 太郎"}},
		{"CEO + 氏名で行末", "左：架空社 広報、右：架空製薬 社長兼CEO 佐藤花子", []string{"佐藤花子"}},
		// 名が辞書にない氏名も、所属 + の + 氏名 + 職名があれば「辞書の姓 + 名」で採る。
		{"所属の氏名 + 教授が・名が辞書にない", "経営学部の高橋架空斗教授が「架空賞」に入賞", []string{"高橋架空斗"}},
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

// TestRankContextNegatives は、同じ形に見えるが個人を指さない行を氏名として報告しないことを確認する。
func TestRankContextNegatives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"総務部長、企画課長及び財政課長が出席した。",    // 部署名 + 職名
		"市民生活部長（兼）危機管理室長",          // 部署名 + 職名
		"山田栄誉教授の講演会を開催します。",        // 姓だけ + 栄誉教授
		"医学部の特任教授が講演します。",          // 所属 + の + 職名だけ
		"大学の客員准教授らが参加しました。",        // 所属 + の + 職名だけ
		"代表取締役社長・最高経営責任者）を選任しました。", // 職名・職名
		"社長兼CEO 就任のお知らせ",           // 英字の役職名 + 一般語
		"准教授 募集要項（任期付き）",           // 職名 + 一般語 + 括弧
		"主任研究員、上席研究員及び技師を募集します。",   // 職名の並び
		"鈴木本部長を中心に確認させていただいた。",     // 姓 + 本部長
		"当時の鈴木第二課長らが答弁した。",         // 姓 + 第二課長
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestKunSpanExcluded は、会議録の「○議長（<姓>　<名>君）」「<職名>　<姓>　<名>君」で、敬称の「君」を
// 氏名の範囲に含めないことを確認する（範囲の誤り。氏名そのものは報告する）。
func TestKunSpanExcluded(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"○議長（鈴木　彰君）　　これにて本日の会議を閉じます。",
		"　　　　　　　架空省架空局長　　佐藤　周夫君",
	} {
		var got []string
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				got = append(got, f.Match)
			}
		}
		if len(got) != 1 || strings.HasSuffix(got[0], "君") {
			t.Errorf("%q: got %q, want one name without 君", line, got)
		}
	}
}

// TestDigitsInURLAndPhonePairNotReported は、URL の中の 10 桁と、並んだ 2 つの電話番号にまたがる
// 「4 桁 + 空白 + 4 桁」を、年金・介護保険・健康保険の番号として報告しないことを確認する。
// いずれも個人に割り当てられた番号ではない（データセットの ID と、窓口の電話番号の一部）。
func TestDigitsInURLAndPhonePairNotReported(t *testing.T) {
	d := newDetector(t, "")
	for _, content := range []string{
		"第3章 国民年金,https://data.example.jp/dataset/231002_1300050000_01/resource/x\n",
		"a,221007,架空市,介護保険サービス提供事業者一覧,,ja,https://data.example.jp/dataset/221007-1748247124,,介護保険課\n",
		"国民健康保険の加入・喪失に関すること。保険証の発行。\n\n給付係 0476-33-4464 0476-42-8901\n",
	} {
		for _, f := range d.ScanContent("f.txt", content) {
			switch f.RuleID {
			case "jp-pension-number", "jp-kaigo-insurance", "jp-health-insurance":
				t.Errorf("%q: unexpected %s %q", content, f.RuleID, f.Match)
			}
		}
	}
	// URL の外の番号は従来どおり報告する。
	for content, rule := range map[string]string{
		"基礎年金番号 1234-567890 https://example.jp/nenkin\n": "jp-pension-number",
		"介護保険 被保険者番号 0012345678\n":                       "jp-kaigo-insurance",
		"保険証 記号番号 1234 5678\n":                           "jp-health-insurance",
	} {
		found := false
		for _, f := range d.ScanContent("f.txt", content) {
			found = found || f.RuleID == rule
		}
		if !found {
			t.Errorf("%q: want %s", content, rule)
		}
	}
}

// TestOccurrenceDateNotBirthdate は、「発生年月日」（事故・事案の発生日）の日付を生年月日として
// 報告しないことと、「生年月日」の日付は従来どおり報告することを確認する。
func TestOccurrenceDateNotBirthdate(t *testing.T) {
	d := newDetector(t, "")
	for _, content := range []string{
		"発生年月日\n\n令和07年11月22日\n\n事案\n",
		"発生年月日：2025年11月22日\n",
	} {
		for _, f := range d.ScanContent("f.txt", content) {
			if f.RuleID == "jp-birthdate" {
				t.Errorf("%q: unexpected %q", content, f.Match)
			}
		}
	}
	for _, content := range []string{
		"生年月日\n\n昭和60年1月2日\n",
		"生年月日：1985年1月2日\n",
	} {
		found := false
		for _, f := range d.ScanContent("f.txt", content) {
			found = found || f.RuleID == "jp-birthdate"
		}
		if !found {
			t.Errorf("%q: want jp-birthdate", content)
		}
	}
}
