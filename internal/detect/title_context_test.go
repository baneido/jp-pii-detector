package detect

import (
	"strings"
	"testing"
)

// 2026-11-12 の公開文書 2,489 件の確認で見つけた見逃し・誤検出を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）、組織名・催し名も架空で、収集した文書の内容は使わない。

// TestTitleContextNames は、大学・官公庁・企業の広報の本文で職名・敬称・就任が氏名に直結する
// 表記を person-name-role-label で拾うことを確認する。いずれも特定の個人（受賞者・登壇者・役員・
// 閣僚）を指す氏名で、個人情報保護法の個人情報に当たる。実測では、手がかりのある無作為 80 行の
// 姓+名 19 人のうち既定モードが拾えたのは 4 人だった。
func TestTitleContextNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		// 「<姓><名>・<学部>教授が」（大学のニュースの見出し）
		{"中黒 + 所属 + 職名", "山田太郎・架空学部教授が架空賞を受賞", []string{"山田太郎"}},
		{"中黒 + 名誉教授", "佐藤花子・名誉教授が講演しました", []string{"佐藤花子"}},
		// 「<姓> <名> <所属> <職名>」と、スラッシュで並ぶ発表者欄・括弧で閉じる発表者表記
		{"空白区切りの氏名 + 職名", "山田　太郎 架空府大臣政務官", []string{"山田　太郎"}},
		{"発表者欄のスラッシュ区切り", "鈴木一郎 架空研究院 准教授 / 高橋健太 架空学院 大学院生", []string{"鈴木一郎", "高橋健太"}},
		{"括弧で閉じる発表者", "架空の研究成果を発表（架空学部・田中美咲 特任助教）", []string{"田中美咲"}},
		// 「<姓> <名>（<担当>大臣）」だけの行（閣僚名簿）
		{"括弧の職名だけの行", "伊藤 直樹（架空戦略担当大臣）", []string{"伊藤 直樹"}},
		// 「<姓><名>が代表取締役社長に就任」（沿革）
		{"就任", "架空株式会社を設立。山田太郎が代表取締役社長に就任", []string{"山田太郎"}},
		// 敬称の後に文が続く「<姓><名>氏、」「<姓><名>さんが」
		{"氏 + 読点", "芸人の佐藤花子氏、鈴木一郎氏に架空大使を委嘱しました", []string{"佐藤花子", "鈴木一郎"}},
		{"から + 氏", "架空学部長から高橋健太氏に感謝状を伝達", []string{"高橋健太"}},
		{"の + さんが", "架空研究科修士2年の田中美咲さんがグランプリを受賞", []string{"田中美咲"}},
		// 「<姓><名>総長からの」「<姓><名>医学部長から」
		{"総長", "山田太郎総長からのメッセージ", []string{"山田太郎"}},
		{"医学部長", "佐藤花子医学部長から報告がありました", []string{"佐藤花子"}},
		// 「<職名>　<姓><名>）」で閉じる研究成果の見出し
		{"職名 + 氏名 + 括弧閉じ", "架空の発見（架空研究所　教授　鈴木一郎）", []string{"鈴木一郎"}},
		// 「で<姓><名>選手が」
		{"助詞の後の選手", "架空大会で高橋健太選手が優勝", []string{"高橋健太"}},
		// 「<姓> <名>（Taro Yamada）」先頭だけ大文字のローマ字
		{"ローマ字の読み（先頭大文字）", "山田 太郎（Taro Yamada）", []string{"山田 太郎"}},
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

// TestTitleContextRejects は同じ形の一般語・組織名・姓だけ・故人を氏名として拾わないことを確認する。
func TestTitleContextRejects(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		// 「<姓>大臣・<姓>大臣」の「<姓>大臣」は姓 + 職名（実測した偽陽性の形）
		"山田大臣・佐藤大臣の定例記者会見",
		// 組織の英語表記（「<地名>大学（<英語名>）」。実測した偽陽性の形）
		"架空大学（KAKUU UNIVERSITY）",
		// 施設の英語名はローマ字の姓名辞書に一致しない
		"東京駅（Tokyo Station）",
		// 一般語 + 敬称・「さんさん」・氏名の欄
		"高知さんさんテレビにて放送",
		"実在氏名を使わないこと",
		"お子さんがいる家庭",
		// 姓だけ + 敬称
		"山田さんが来ました",
		// 故人
		"故・山田太郎氏をしのぶ会",
		// 職名 + 部署・一般語
		"架空学部長からの報告",
		"教授会 / 研究科長",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 氏名として検出した（%s %q）", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestOrgUnitSpacedValueNotName は、項目行らしい行（「（PDF：143KB）」）の次の行の「<局> <課>」
// 「<室> <課>」を、辞書に無い空白区切りの姓名として拾わないことを確認する（市のソーシャル
// メディア一覧で実測した偽陽性。部署名は個人を識別しない）。辞書にある姓名は従来どおり拾う。
func TestOrgUnitSpacedValueNotName(t *testing.T) {
	d := newDetector(t, "")
	for _, content := range []string{
		"運用ポリシー（PDF：143KB）\n\n架空室 広報課\n",
		"運用ポリシー（PDF：157KB）\n\n水道局 総務課\n",
	} {
		for _, f := range d.ScanContent("f.txt", content) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 部署名を氏名として検出した（%s %q）", content, f.RuleID, f.Match)
			}
		}
	}
}

// TestExecTitleUncommonSpacedName は、代表取締役の後の姓も名も辞書にない空白区切りの氏名を拾い、
// 一般語の組は拾わないことを確認する（会社概要で実測した見逃し）。
func TestExecTitleUncommonSpacedName(t *testing.T) {
	d := newDetector(t, "")
	found := func(line string) []string {
		var got []string
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if f.RuleID == "person-name-role-label" {
				got = append(got, f.Match)
			}
		}
		return got
	}
	if got := found("代表取締役社長　蘂沢　鑢之介"); strings.Join(got, "|") != "蘂沢　鑢之介" {
		t.Errorf("辞書にない役員名: got %q", got)
	}
	if got := found("代表取締役社長　挨拶　動画"); len(got) != 0 {
		t.Errorf("一般語の組を氏名として検出した: %q", got)
	}
}

// TestHighRecallYouSymptom は高再現率モードで「感冒様症状」の「様」を敬称とみなさないことを確認する。
func TestHighRecallYouSymptom(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{"感冒様症状者にかかる届出制度", "インフルエンザ様疾患の報告"} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 氏名として検出した（%s %q）", line, f.RuleID, f.Match)
			}
		}
	}
}
