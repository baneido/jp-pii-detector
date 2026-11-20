package detect

import (
	"strings"
	"testing"
)

// 2026-11-20 の公開文書 6,129 件の確認で見つけた見逃し・誤検出を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）、組織名・番号も架空で、収集した文書の内容は使わない。

// TestListContextNames は、括弧の役職の見出し + 読点区切りの氏名、「理事 <氏名>（<本務>）」、
// 「<氏名><県名>知事」「<氏名><市名>市長」、「理事長に<氏名>が就任」、「<職名> <姓> <名>...」、
// 「<催し> <氏名>氏」の行末を person-name-role-label で拾うことを確認する。
// いずれも特定の個人（法人の役員・首長・教員・講師）を指す氏名で、個人情報保護法の
// 「特定の個人を識別できる情報」に当たる。実測では、人を指す語のある無作為 421 行の正解（姓+名 50 人）の
// うち、既定モードが拾えたのは 34 人だった。
func TestListContextNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"括弧の役職 + 読点区切りの氏名", "         ｛評議員｝ 山田太郎、佐藤花子、鈴木一郎、高橋健太、", []string{"山田太郎", "佐藤花子", "鈴木一郎", "高橋健太"}},
		{"括弧の役職 + 読点区切りの氏名（末尾に読点なし）", "【理事】田中美咲、伊藤直樹、山田太郎", []string{"田中美咲", "伊藤直樹", "山田太郎"}},
		{"理事 + 氏名 + 括弧の本務", "理事　佐藤花子（架空ライン株式会社代表取締役社長）", []string{"佐藤花子"}},
		{"氏名 + 県名 + 知事", "架空県庁では山田太郎鳥取県知事、", []string{"山田太郎"}},
		{"氏名 + 市名 + 市長", "市役所では佐藤花子鳥取市長を表敬訪問し、", []string{"佐藤花子"}},
		{"職名 + に + 氏名 + が就任", "学校法人架空学園理事長に高橋 健太（健應）が就任", []string{"高橋 健太"}},
		{"職名 + 氏名 + 省略記号", "架空文化センターで、架空大学 特任准教授 田中 美咲...", []string{"田中 美咲"}},
		{"催し + 氏名 + 氏で行末", "建築学部 建築学科 特別レクチャー 伊藤直樹氏", []string{"伊藤直樹"}},
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

// TestListContextNegatives は、同じ形に見えるが個人を指さない行を氏名として報告しないことを確認する。
func TestListContextNegatives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"｛会員｝ 東京都、大阪府、北海道、福岡県、", // 括弧の見出し + 地名の並び
		"【委員】総務部会、企画部会、広報部会",    // 括弧の見出し + 会議体の並び
		"評議員、理事、監事の選任について、",     // 役職の並び（括弧の見出しなし）
		"理事 就任挨拶（令和8年度）",        // 職名 + 一般語 + 括弧
		"歴代鳥取県知事、歴代鳥取市長の一覧",     // 氏名のない知事・市長
		"前鳥取市長を表敬訪問しました。",       // 氏名のない市長
		"理事長に就任しました。",           // 氏名のない就任
		"理事長に新体制が就任する予定です。",     // 職名 + に + 一般語 + が就任
		"特任准教授 募集 要項...",        // 職名 + 一般語 + 省略記号
		"特別レクチャー 開催案内",          // 催し + 一般語
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestDatasetIDAndPermitNumberNotReported は、下線で自治体コードにつながったデータセットの ID の 10 桁と、
// 「古物営業許可 … 第<12 桁>号」の 12 桁を、介護保険・年金・運転免許証の番号として報告しないことを確認する。
// いずれも個人に割り当てられた番号ではない（データセットの ID と、事業者の許可番号）。
func TestDatasetIDAndPermitNumberNotReported(t *testing.T) {
	d := newDetector(t, "")
	for _, content := range []string{
		"795,5,架空市,介護保険サービス提供事業者一覧,介護保険サービス提供事業者一覧（平成26年度）,221007_1748247124,x\n",
		"12,国民年金の加入者数,231002_1300050000,y\n",
		"宅建免許番号 東京都知事(3)第00000号\n古物営業許可 東京都公安委員会 第304360809505号\n",
	} {
		for _, f := range d.ScanContent("f.csv", content) {
			switch f.RuleID {
			case "jp-pension-number", "jp-kaigo-insurance", "jp-drivers-license":
				t.Errorf("%q: unexpected %s %q", content, f.RuleID, f.Match)
			}
		}
	}
	// 下線・「第…号」を伴わない番号は従来どおり報告する。
	for content, rule := range map[string]string{
		"介護保険 被保険者番号 1748247124\n": "jp-kaigo-insurance",
		"運転免許証番号 304360809505\n":   "jp-drivers-license",
	} {
		found := false
		for _, f := range d.ScanContent("f.txt", content) {
			if f.RuleID == rule {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: want %s", content, rule)
		}
	}
}

// TestHonorificFishShoshiShopNotReported は、高再現率モードで、敬称と同じ字を含む一般語と伏せ字の
// メールアドレスを報告しないことを確認する。いずれも特定の個人を指さない（魚の名前・複数の人への敬称・
// 店・日付の字を取り込んだ範囲・書式の例）。
func TestHonorificFishShoshiShopNotReported(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{
		"R08/04,42005,丸干さんま,0,*合計*,29.5,27410",
		"先輩諸氏が長年にわたって築き上げてこられた歴史と伝統を受け継ぎ、",
		"会員諸氏のより充実した学術活動により、",
		"今朝は、八百屋さんが大きく育ったすいかを届けてくれました。",
		"Before: 〇〇〇@example.ac.jp After: 〇〇〇@ms.example.ac.jp",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") || strings.HasPrefix(f.RuleID, "email") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
	// 日付の「月」を氏名の範囲に取り込まない。
	for _, f := range d.ScanLine("f.txt", 1, "1912年4月山田太郎氏によってこの場所に開所し、") {
		if strings.HasPrefix(f.Match, "月") {
			t.Errorf("unexpected span %q", f.Match)
		}
	}
	// 敬称付きの氏名は従来どおり報告する（「<姓>さんまで」は助詞の続き、「土屋」は姓）。
	for _, line := range []string{"お問い合わせは山田太郎さんまでお願いします。", "土屋さんが受賞しました。"} {
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
