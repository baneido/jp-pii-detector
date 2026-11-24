package detect

import (
	"strings"
	"testing"
)

// 2026-11-23 の公開文書 8,396 件の確認で見つけた見逃し・誤検出の「形」を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）と辞書に無い架空の名、組織名・番組名・番号もすべて架空で、
// 収集した文書の内容は使わない。

// TestSelfOrgContextNames は、「本学 <氏名>教授」（名が辞書に無い 1 字）、決算短信の「（役職名）…（氏名）<姓> <名>」
// （姓も名も辞書に無い）、「<氏名>氏×<氏名> 対談」、「<氏名>医師」、パンくずリストの末尾の氏名、
// 「<姓> <名>(<携帯番号>)」、「委員長 <姓> <名>」、「看護師長 <氏名>」、「監修<姓> <名>」、「<氏名> <部署>部長」を
// person-name-role-label で拾うことを確認する。いずれも特定の個人（教員・役員・医師・職員・対談者）を指す
// 氏名で、個人情報保護法の「特定の個人を識別できる情報」に当たる。実測では、人を指す語のある無作為 460 行の
// 正解（姓+名 58 人）のうち、既定モードが拾えたのは 41 人だった。
func TestSelfOrgContextNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"本学 + 氏名（名が辞書に無い 1 字）+ 教授", "『架空新報』の特集に本学 高橋陞教授のコメントが掲載されました", []string{"高橋陞"}},
		{"決算短信の問合せ先（役職名）…（氏名）+ 辞書に無い姓 名", "問合せ先責任者（役職名）経理部長                    （氏名）椛 力斗", []string{"椛 力斗"}},
		{"決算短信の代表者（役職名）…（氏名）", "代表者          （役職名） 代表取締役社長                     （氏名）椛 力斗", []string{"椛 力斗"}},
		{"氏名 + 氏×氏名 + 対談", "「これからの地域」（研究者・山田太郎氏×佐藤次郎 対談①）", []string{"山田太郎", "佐藤次郎"}},
		{"氏名 + 先生×氏名 + 対談（2 人目）", "架空流家元 山田太郎先生×佐藤次郎対談より", []string{"佐藤次郎"}},
		{"氏名 + 医師 + の", "内容：佐藤花子さんと山田太郎医師のトークセッション　他", []string{"佐藤花子", "山田太郎"}},
		{"当院の + 氏名 + 医師が", "第一部では、当院の鈴木一郎医師が『肩こりのお話』の講演を行いました", []string{"鈴木一郎"}},
		{"パンくずリストの末尾の氏名", "トップ > 医師紹介 > 山田　太郎", []string{"山田 太郎"}},
		{"姓 名 + 括弧の携帯番号", "採用担当連絡先 山田　太郎(090-1234-5678)", []string{"山田 太郎"}},
		{"委員長 + 空白 + 姓 名", "委員長　山田　太郎", []string{"山田 太郎"}},
		{"看護師長 + 空白 + 氏名", "担当者：地域連携室看護師長　山田花子", []string{"山田花子"}},
		{"部長 + 空白 + 氏名", "看護部長 佐藤花子", []string{"佐藤花子"}},
		{"監修 + 姓 名", "監修田中 美咲", []string{"田中 美咲"}},
		{"担当 + 姓 名", "内科外来担当山田 太郎", []string{"山田 太郎"}},
		{"氏名 + 空白 + 部署 + 部長", "山田太郎 情報調査部長", []string{"山田太郎"}},
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

// TestSelfOrgContextNegatives は、同じ形に見えるが個人を指さない行を、既定モードで氏名として報告しない
// ことを確認する。
func TestSelfOrgContextNegatives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"本学 情報工学教授の公募について",    // 分野名 + 教授（氏名がない）
		"（役職名）経理部長 （氏名）別紙 参照", // 一般語の組は氏名ではない
		"担当医師のご紹介",            // 「担当」+ 医師
		"産業医師会のお知らせ",          // 団体名
		"トップ > 医師紹介 > 外来 担当",  // パンくずリストの末尾が一般語
		"委員長　挨拶",              // 役の名前 + 一般語
		"総務部長 挨拶要旨",           // 役職 + 一般語
		"監修 架空 大学",            // 組織名
		"新製品 開発部長",            // 一般語 + 部署 + 役職
		"山田太郎×佐藤次郎",           // 「×」だけで対談の語がない（試合の組み合わせと区別できない）
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestSpacedPlaceAndFacilityNotName は、項目行（「TEL：…」「開催日：…」）に隣り合う行のうち、字間を空けた地名
// （岡　山）と、地名 + 施設の名前（<地名> 二番館）を person-name として報告しないことを確認する。会場一覧の
// 地名の見出しと施設名で、個人を識別する情報ではない。同じ位置の空白区切りの氏名は従来どおり報告する。
func TestSpacedPlaceAndFacilityNotName(t *testing.T) {
	d := newDetector(t, "")
	for _, content := range []string{
		"架空ホテル\n\nTEL：000-000-0000\n\n岡　山\n\n9月19日(土)\n\n本学キャンパス\n",
		"開催日：2026年12月4日（金） 〜\n\n松原 二番館\n\n見学会＆サービス説明会\n\n開催日：2026年10月13日（火）\n",
	} {
		for _, f := range d.ScanContent("f.txt", content) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", content, f.RuleID, f.Match)
			}
		}
	}
	found := false
	for _, f := range d.ScanContent("f.txt", "山田 太郎\n生年月日: 1980年1月1日\n") {
		if f.RuleID == "person-name" && f.Match == "山田 太郎" {
			found = true
		}
	}
	if !found {
		t.Errorf("want person-name for a spaced name before a person field line")
	}
}

// TestAnimalBirthdayNotReported は、動物の紹介（「<名前> （メス）／誕生日／<日付>／出生地」）の誕生日を
// jp-birthdate として報告しないことを確認する。動物の誕生日は個人情報ではない。性別の印が近くにない
// 誕生日は従来どおり報告する。
func TestAnimalBirthdayNotReported(t *testing.T) {
	d := newDetector(t, "")
	for _, content := range []string{
		"ハナコ （メス）\n\nDATA\n\n誕生日\n\n2015年6月16日\n\n出生地\n\n架空動物園\n",
		"名前：タロウ\n性別：オス\n誕生日：2011年3月10日\n",
	} {
		for _, f := range d.ScanContent("f.txt", content) {
			if f.RuleID == "jp-birthdate" {
				t.Errorf("%q: unexpected %s %q", content, f.RuleID, f.Match)
			}
		}
	}
	found := false
	for _, f := range d.ScanContent("f.txt", "選手名：山田 太郎\n誕生日：2001年3月10日\n出身地：東京都\n") {
		if f.RuleID == "jp-birthdate" {
			found = true
		}
	}
	if !found {
		t.Errorf("want jp-birthdate for a person's birthday")
	}
}

// TestStatCSVCodeColumnsNotID は、統計表の CSV の「時間軸コード」「数値」の列の数字を、同じ行の項目名
// （要介護認定者数・被保険者保険給付総額・公的年金）を文脈にして介護保険・健康保険・基礎年金の番号として
// 報告しないことを確認する。年度を表すコードと統計の値で、個人の番号ではない。被保険者番号の列は
// 従来どおり報告する。値はすべて架空。
func TestStatCSVCodeColumnsNotID(t *testing.T) {
	d := newDetector(t, "")
	content := "時間軸コード,西暦（暦年）,和暦（暦年）,地域コード,地域,項目,数値,単位\n" +
		"2000100000,平成12年度,2000年度,99000,架空府,要介護認定者数,12345 ,人\n" +
		"1987100000,1987年度,昭和62年度,99000,架空府,被保険者保険給付総額,53545266 ,千円\n" +
		"2017100000,2017年度,平成29年度,99000,架空府,公的年金,45 ,件\n"
	for _, f := range d.ScanContent("stat.csv", content) {
		t.Errorf("unexpected %s %q", f.RuleID, f.Match)
	}
	found := false
	for _, f := range d.ScanContent("members.csv", "氏名,介護保険被保険者番号\n山田太郎,0000123456\n") {
		if f.RuleID == "jp-kaigo-insurance" {
			found = true
		}
	}
	if !found {
		t.Errorf("want jp-kaigo-insurance for a labeled insured-number column")
	}
}

// TestHonorificLeadInAndGenericWords は、高再現率モードの敬称パターンで、氏名でない語（今・金額・役職）から
// 始まる値は氏名だけの範囲にし、特定の個人を指さない語（新郎様・右四氏・喘息様の症状・渡来氏族・
// <氏族名>氏の歴史）は報告しないことを確認する。
func TestHonorificLeadInAndGenericWords(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{
		"・新郎様・新婦様入場体験",
		"○委員長　右四氏の御報告に対しましては、申合せによりまして質疑を行います",
		"多くは軽い症状で済みますが、喘息様の症状を呈することもあります",
		"この社は渡来氏族が信仰したと伝わります。",
		"毛利氏の歴史",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
	for line, want := range map[string]string{
		"ことであります。今鈴木さんの御質問は根本的なことについてのお話でありました": "鈴木",
		"○架空委員　今山田さんは一般的な原則論を説明なさつたのですが":        "山田",
		"この報告書では、二千万円佐藤さんが受け取ったことについて触れていません":   "佐藤",
		"本日の進学説明会は、入試広報課　課長代理山田様をお迎えしました。":      "山田",
		"今井さんからお話を伺いました。":                       "今井",
	} {
		var got []string
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				got = append(got, f.Match)
			}
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("%q: got %q, want [%q]", line, got, want)
		}
	}
}

// TestKatakanaFaxLabelPhone は、「ファクス番号：(03)…」「ファックス番号 (03)…」のように、カタカナのラベルの後の
// 括弧つき市外局番の番号を jp-phone-number として拾うことを確認する（「FAX番号」は従来から拾えていた）。
// 未知の採番ラベル（受付番号・整理番号）の後の同じ形は従来どおり報告しない。番号は架空。
func TestKatakanaFaxLabelPhone(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{"ファクス番号：(03)1234-5678", "ファックス番号 (03)1234-5678"} { // jp-pii-detector:ignore
		found := false
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if f.RuleID == "jp-phone-number" {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: want jp-phone-number", line)
		}
	}
	for _, line := range []string{"受付番号：(03)1234-5678", "整理番号：(03)1234-5678"} { // jp-pii-detector:ignore
		for _, f := range d.ScanLine("f.txt", 1, line) {
			t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
		}
	}
}
