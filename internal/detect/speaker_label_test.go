package detect

import "testing"

// 会議録の発言者ラベル「【<姓>会長】」「<姓>構成員：」は姓だけでも会議内の特定の個人を指す
// （2026-11-10 の実測。官公庁の会議録で全モードが取りこぼしていた最大の見逃し群）。
// 日常語との衝突を避けるため high-recall に限り、山括弧／コロンと姓辞書一致を要求する。
// 値は姓辞書にある合成の姓のみ（実在人物ではない）。
func TestSpeakerLabelSurnameHighRecall(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	pos := []string{
		"【鈴木会長】 ありがとうございます。",
		"【佐藤部会長】 それでは次に進みます。",
		"田中構成員： 資料について質問があります。",
		"　高橋委員： 御意見を申し上げます。",
	}
	for _, line := range pos {
		assertRules(t, d.ScanLine("f.txt", 1, line), "person-name-high-recall")
	}
	neg := []string{
		"【専門委員】 ありがとうございます。",
		"【事務局長】 説明いたします。",
		"選挙管理委員会の開催について",
		"教育委員： 担当課の配置について",
	}
	for _, line := range neg {
		assertRules(t, d.ScanLine("f.txt", 1, line))
	}
}
