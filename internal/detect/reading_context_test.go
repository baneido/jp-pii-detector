package detect

import (
	"strings"
	"testing"
)

// 2026-11-18 の公開文書 4,198 件の確認で見つけた見逃し・誤検出を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）、組織名も架空で、収集した文書の内容は使わない。
// 番号の形の値は検査用数字が合うように作った架空の値。

// TestReadingContextNames は、読みがなの括弧、職名に続く字間を空けた氏名、所属 + 職名の行、
// 「<役割>の<氏名>氏」、「<氏名>代表が」、かぎ括弧の氏名 + 敬称、「<氏名>さん主演」、
// 「<職名> <姓><ひらがなの名>氏」、決算短信の「問合せ先責任者 <部署> <姓> <名>」を
// person-name-role-label で拾うことを確認する。
// いずれも特定の個人（選手・役員・弁護士・教員・講師・政党の代表）を指す氏名で、個人情報保護法の
// 「特定の個人を識別できる情報」に当たる。実測では、人を指す語のある無作為 520 行の正解のうち
// 設計用の姓+名 38 人で、既定モードが拾えたのは 28 人だった（修正後 37 人）。
func TestReadingContextNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"氏名（姓の読み 名の読み）選手", "女子レスリングの山田花子（やまだ はなこ）選手採用のお知らせ", []string{"山田花子"}},
		{"空白区切りの氏名（読み・読み）", "鈴木 一郎（すずき・いちろう） 作", []string{"鈴木 一郎"}},
		// 名が辞書にない氏名も、読みがなの括弧 + 敬称があれば「辞書の姓 + 名」で採る。
		{"氏名（読み）さん・名が辞書にない", "代表理事を務める、佐藤架空斗（さとうかくと）さんです。", []string{"佐藤架空斗"}},
		{"氏名（名の読み）さん", "同校3年の高橋健太（けんた）さんが出場します。", []string{"高橋健太"}},
		{"職名 + 字間を空けた氏名", "           問合せ先 代表取締役副社長執行役員 山 田 太 郎", []string{"山 田 太 郎"}},
		{"弁護士 + 字間を空けた氏名", "同訴訟代理人弁護士             佐    藤    一    郎", []string{"佐    藤    一    郎"}},
		{"字間を空けた氏名 + 次の欄", " 取締役         田   中   直   樹   架空株式会社代表取締役社長", []string{"田   中   直   樹"}},
		{"教員一覧の行", "山田　太郎　　　医学研究科　教授（1987-2014）", []string{"山田 太郎"}},
		{"氏名 + 空白 + 学部 + 職名", "鈴木花子 医学部教授（架空学講座）が受賞しました。", []string{"鈴木花子"}},
		{"役割の + 氏名 + 氏・名が辞書にない", "架空大学名誉教授の佐藤佰太郎氏をお迎えし、講演会を開きます。", []string{"佐藤佰太郎"}},
		{"役割・氏名 + 氏", "著者・田中架空子氏の講演会開催", []string{"田中架空子"}},
		{"氏名 + 代表が", "我が党の山田太郎代表が、質問をしました。", []string{"山田太郎"}},
		{"かぎ括弧の氏名 + さん", "本校2年生『山田　花子』さんが出場しました。", []string{"山田 花子"}},
		{"氏名 + さん主演", "スペシャルムービー（鈴木花子さん主演）公開", []string{"鈴木花子"}},
		{"職名 + 姓 + ひらがなの名 + 氏", "NPO法人架空　所長　山田ゆみ子氏", []string{"山田ゆみ子"}},
		{"問合せ先責任者 + 部署 + 氏名", "　　問合せ先責任者　　社長室 山田 匡", []string{"山田 匡"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, f := range d.ScanLine("f.txt", 1, tt.line) {
				if f.RuleID == "person-name-role-label" {
					got = append(got, strings.Join(strings.Fields(strings.ReplaceAll(f.Match, "　", " ")), " "))
				}
			}
			want := make([]string, len(tt.want))
			for i, w := range tt.want {
				want[i] = strings.Join(strings.Fields(w), " ")
			}
			if strings.Join(got, "|") != strings.Join(want, "|") {
				t.Fatalf("%q: got %q, want %q", tt.line, got, want)
			}
		})
	}
}

// TestReadingContextNegatives は、同じ形に見えるが個人を指さない行を氏名として報告しないことを確認する。
func TestReadingContextNegatives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"第２回地域通貨「杉小判（すぎこばん）」配布について",                    // 用語 + 1 語の読みがな
		"架空資料館（かくうしりょうかん）",                             // 施設名 + 読みがな
		"多文化共生（たぶんかきょうせい）さんぽ",                          // 用語 + 読みがな
		"（１）    取 締 役 会 決 議 日       2026 年 11 月 12 日",  // 均等割付の見出し
		"     21,741        長 期 借 入 金          19,984", // 均等割付の勘定科目
		"  役   職      氏   名     就任年月日",                 // 欄の名前
		"文学部　日本文学科　教授　一覧",                              // 所属 + 職名だけ
		"架空大学名誉教授の研究室氏名一覧",                             // 役割の + 一般語
		"愛知県代表として出場します。",                               // 県 + 代表
		"伝説の元日本代表が直接指導します。",                            // 日本代表
		"山口公明代表が、会見で述べた。",                              // 姓 + 政党の略称 + 代表（名ではない）
		"「入門 講座」さんぽ",                                   // かぎ括弧の一般語
		"会長 山田より様",                                     // 助詞を名に取り込まない
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 氏名として報告した: %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestRegionPlacePairIsNotName は、標語の「<地域名> <村名>。」だけの行を氏名（person-name）として
// 報告しないことを確認する（2 語目が実在の市区町村名。特定の個人を指さない）。
// 「<姓> <名>。」だけの署名行は従来どおり報告する。
func TestRegionPlacePairIsNotName(t *testing.T) {
	d := newDetector(t, "")
	for _, f := range d.ScanContent("f.txt", "楽しい・美味しい・懐かしい\n南信州 平谷村。\n") {
		if strings.HasPrefix(f.RuleID, "person-name") {
			t.Errorf("地域名 + 村名を報告した: %s %q", f.RuleID, f.Match)
		}
	}
	found := false
	for _, f := range d.ScanContent("f.txt", "以上のとおり報告します。\n山田 太郎。\n") {
		found = found || f.RuleID == "person-name"
	}
	if !found {
		t.Errorf("署名行の氏名を報告しなかった")
	}
}

// TestSpacedNumberRowIsNotMyNumber は、寸法・数量の表の行に並んだ数値のうち、4 桁が 3 つ続く部分を
// 個人番号として報告しないことを確認する（検査用数字が偶然合っているだけで、個人を識別する番号ではない）。
// 「個人番号」「マイナンバー」の語がある行と、数値の並びでない 4-4-4 は従来どおり報告する。
func TestSpacedNumberRowIsNotMyNumber(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"300 450 600 1234 5678 9018",
		"1234 5678 9018 300 450",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if f.RuleID == "jp-my-number" {
				t.Errorf("%q: 数値の並びを個人番号として報告した: %q", line, f.Match)
			}
		}
	}
	for _, line := range []string{
		"マイナンバー 1234 5678 9018",
		"個人番号 12 1234 5678 9018",
	} {
		found := false
		for _, f := range d.ScanLine("f.txt", 1, line) {
			found = found || f.RuleID == "jp-my-number"
		}
		if !found {
			t.Errorf("%q: 個人番号を報告しなかった", line)
		}
	}
}

// TestHonorificOrgOrSampleHighRecall は、高再現率モードで、団体の種類を表す語に付く敬称と、記入例の
// 定番の名だけの「花子さん」を敬称付きの氏名として報告しないことを確認する（特定の個人を指さない）。
// 氏名 + さんは従来どおり報告する。
func TestHonorificOrgOrSampleHighRecall(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{
		"今回の改革において、農協さんの名誉のためにも申し上げます。",
		"架空証券取引所様の上場インタビューに掲載されました。",
		"寸劇で学ぶ入門講座～花子さんのみちしるべ～を開催します",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 氏名として報告した: %s %q", line, f.RuleID, f.Match)
			}
		}
	}
	found := false
	for _, f := range d.ScanLine("f.txt", 1, "本日の講師は山田花子さんです。") {
		found = found || strings.HasPrefix(f.RuleID, "person-name")
	}
	if !found {
		t.Errorf("氏名 + さんを報告しなかった")
	}
}
