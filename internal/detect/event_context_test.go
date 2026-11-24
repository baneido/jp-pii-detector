package detect

import (
	"sort"
	"strings"
	"testing"
)

// 2026-11-24 の公開文書 7,564 件の確認で見つけた見逃し・誤検出の「形」を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）、組織名・催しの名前もすべて架空で、収集した文書の内容は使わない。

// TestEventContextNames は、「<氏名>先生サイン会」、「<委員会名>委員長 <姓> <名>」、「<姓> <名> 医師」の行末、
// 「・<氏名> 先生 ・<氏名> 先生」の並び、「<氏名> 委員（<所属><職名>）」、「<研究所名><氏名>社長（当時）」、
// 「院長：<姓> <名>」、「<氏名>講師です」、「<氏名>（<大学名>）」、「<姓> <名>医師の」、「理事長 <氏名> （<補足>）」、
// 「<姓> <名> 総監督」を person-name-role-label で拾うことを確認する。いずれも職名・所属・催しと一緒に
// 書かれた特定の個人の氏名で、個人情報保護法の「特定の個人を識別できる情報」に当たる。実測では、人を
// 指す語のある無作為 730 行の正解（姓+名 106 人）のうち、既定モードが拾えたのは 73 人だった。
func TestEventContextNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"氏名 + 先生 + サイン会", "10/25 (日) 山田花子先生サイン会のお知らせ【駅前店】", []string{"山田花子"}},
		{"行頭の氏名 + 先生 + 卒寿", "山田太郎先生卒寿を祝う会（2022.12.10)", []string{"山田太郎"}},
		{"氏名 + 先生 + 講演会", "2026年2月20日  2025年度 佐藤花子先生講演会", []string{"佐藤花子"}},
		{"委員会名 + 委員長 + 姓 名", "広報委員長　山田　太郎", []string{"山田 太郎"}},
		{"姓 名 + 空白 + 医師（行末）", "架空専門医（小児科）　山田 太郎 医師", []string{"山田 太郎"}},
		{"姓 名 + 空白 + 医長（行末）", "消化器内科　鈴木　一郎　医長", []string{"鈴木 一郎"}},
		{"氏名 + 先生の並び", "・山田太郎 先生　・鈴木一郎 先生　・佐藤花子 先生", []string{"山田太郎", "鈴木一郎", "佐藤花子"}},
		{"氏名 + 委員（所属 + 職名）", "山田花子　委員（架空大学短期大学部教授）", []string{"山田花子"}},
		{"姓 名 + 委員（括弧が閉じない）", "鈴木　一郎　委員（政策シンクタンク架空総研研究顧問", []string{"鈴木 一郎"}},
		{"研究所名 + 氏名 + 社長（当時）", "と架空総合研究所山田太郎社長（当時）の会見の場でも、大きな期待が寄せられた", []string{"山田太郎"}},
		{"院長：姓 名", "院長：山田 太郎", []string{"山田 太郎"}},
		{"副院長：氏名", "副院長：鈴木一郎", []string{"鈴木一郎"}},
		{"氏名 + 講師です", "執筆に携わったのが、文学部日本学科の山田太郎講師です。現場を経験した後", []string{"山田太郎"}},
		{"氏名（大学名）の並び", "企画担当委員 山田太郎（架空大学），鈴木一郎（架空工業大学）", []string{"山田太郎", "鈴木一郎"}},
		{"氏名 + 氏（研究所名）は氏を含めない", "佐藤次郎氏（架空文化財研究所）", []string{"佐藤次郎"}},
		{"姓 名 + 医師の", "「健康サイト」に総合センター 関 太郎医師の記事が掲載されました", []string{"関 太郎"}},
		{"理事長 + 氏名 + 空白 + 括弧", "架空協会　理事長　山田太郎　（架空流四世家元）", []string{"山田太郎"}},
		{"姓 名 + 総監督（行全体）", "山田 太郎 総監督", []string{"山田 太郎"}},
		{"姓 名 + 先生（括弧の所属）は先生を含めない", "今回は、山田 花子先生（教育学部 ・教授）の講演です", []string{"山田 花子"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, f := range d.ScanLine("f.txt", 1, tt.line) {
				if f.RuleID == "person-name-role-label" {
					got = append(got, strings.Join(strings.Fields(strings.ReplaceAll(f.Match, "　", " ")), " "))
				}
			}
			want := append([]string(nil), tt.want...)
			sort.Strings(got)
			sort.Strings(want)
			if strings.Join(got, "|") != strings.Join(want, "|") {
				t.Fatalf("%q: got %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// TestEventContextNegatives は、同じ形に見えるが個人を指さない行を、高再現率モードでも氏名として
// 報告しないことを確認する。
func TestEventContextNegatives(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{
		"担任の先生サイン会",               // 氏名がない
		"総務委員長　報告 事項",             // 役の名前 + 一般語
		"外来 担当 医師",                // 一般語の組 + 医師
		"検討会　委員（架空大学教授）",          // 会議体の名前 + 委員
		"架空銀行取締役会長の挨拶",            // 組織名 + 役員の職名（氏名がない）
		"院長：外来 担当",                // 職名：一般語
		"所長：挨拶要旨",                 // 職名：一般語
		"担当の特任講師です。",              // 職名だけ
		"石川県立（架空大学）",              // 地名 + 県立
		"外来 担当医師の変更",              // 一般語 + 医師
		"理事長　挨拶要旨　（令和8年）",         // 職名 + 一般語
		"男子 女子 監督",                // 一般語の組 + 監督
		"キャリア支援課、山田花子さん（仮名）①",     // 仮名は本人を特定させないための名前
		"相談に来た山田太郎氏（仮名）は",         // 同上
		"山田太郎さんを偲んで（３・完結編）",       // 亡くなった人（生存する個人の情報ではない）
		"名誉教授　山田　太郎先生　追悼",         // 同上
		"名前：山北町",                  // 自治体の名前（SNS アカウントの一覧）
		"代理店様が同システムから直接アクセスできます",  // 取引先の種類 + 様
		"新婚さんはおトクなサービスが受けられます",    // 一般語 + さん
		"㈱山田さんが施工されました",           // 法人の印の直後（社名）
		"（優良さんぱいナビ）",              // さんぱい = 産廃
		"CSR活動 | 出雲殿グループ 【公式サイト】", // 「殿」で終わる社名
		"●拾九間長屋・松浦氏屋敷の燻蒸業務のお知らせ",  // 氏族の屋敷
		"【講演会】鎌倉北条氏と南宋禅林",         // 地名を冠した一族
		"1044回：小田原北条氏の武蔵侵攻",       // 同上
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestEventContextShopNameNotPerson は、項目行の隣の「<屋号> <地名>店」を氏名として報告しないことを
// 確認する（企業の店舗案内で実測。屋号のカタカナが姓の読みの辞書と同形だった）。
func TestEventContextShopNameNotPerson(t *testing.T) {
	d := newDetector(t, "")
	content := "定休日：火曜日（祝日の場合 営業）\nミシマ 高岡店\n富山県高岡市架空町1368-5\n"
	for _, f := range d.ScanContent("f.txt", content) {
		if strings.HasPrefix(f.RuleID, "person-name") {
			t.Errorf("unexpected %s %q", f.RuleID, f.Match)
		}
	}
}

// TestEventContextHonorificRange は、高再現率モードで「専門医<氏名>氏」の範囲が氏名だけになること、
// 姓だけ・氏族名でない「<姓>氏」は従来どおり拾うことを確認する。
func TestEventContextHonorificRange(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	tests := []struct{ line, want string }{
		{"今年は『図書館で学ぶ、専門医山田太郎氏による「肝臓」講座』を開催", "山田太郎"},
		{"山田氏が登壇しました", "山田"},
		{"北条氏は語る", "北条"},
		{"山田太郎さんを招いて講演会", "山田太郎"},
	}
	for _, tt := range tests {
		var got []string
		for _, f := range d.ScanLine("f.txt", 1, tt.line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				got = append(got, f.Match)
			}
		}
		if len(got) != 1 || got[0] != tt.want {
			t.Errorf("%q: got %q, want %q", tt.line, got, tt.want)
		}
	}
}
