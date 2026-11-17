package detect

import (
	"strings"
	"testing"
)

// 2026-11-17 の公開文書 8,699 件の確認で見つけた見逃し・誤検出を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）、組織名も架空で、収集した文書の内容は使わない。
// 番号の形の値は検査用数字が合うように作った架空の値。

// TestPostContextNames は、職名に直結した「<氏名>君。」、名乗り「<職名>の<氏名>です。」、
// 「<氏名>・党代表」「<氏名>前首相」、行の途中の「<氏名>（<所属><職名>）」、「<職名><氏名>さん」、
// 名がひらがな・1 字の議員の発言者ラベルを person-name-role-label で拾うことを確認する。
// いずれも特定の個人（大臣・議員・首長・教員）を指す氏名で、個人情報保護法の「特定の個人を識別できる
// 情報」に当たる。実測では、人を指す語のある無作為 600 行の正解のうち設計用の姓+名 35 人で、
// 既定モードが拾えたのは 21 人だった（修正後 31 人）。
func TestPostContextNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"職名 + 氏名 + 君。", "この際、発言を求められております。これを許します。内閣総理大臣佐藤花子君。", []string{"佐藤花子"}},
		{"職名の + 氏名 + です。", "架空市長の鈴木一郎です。", []string{"鈴木一郎"}},
		{"氏名・党代表", "架空選挙区から出馬した高橋健太・党代表は、２位当選を果たした。", []string{"高橋健太"}},
		{"氏名 + 前首相", "この町は田中美咲前首相の出身地としても知られています。", []string{"田中美咲"}},
		{"氏名 + 元知事", "記念講演は伊藤直樹元知事が務めました。", []string{"伊藤直樹"}},
		{"行の途中の氏名（所属 + 職名）", "訳・解説　田中美咲（人文学部文化学科准教授）", []string{"田中美咲"}},
		{"職名 + 氏名 + さん", "令和3年度架空大学国際学部教授佐藤花子さん実施報告", []string{"佐藤花子"}},
		// 会議録の定型に限り、名がひらがな・1 字の議員を採る。
		{"発言者ラベル・ひらがなの名", "○山田まさみ君　架空党の山田です。", []string{"山田まさみ"}},
		{"指名・ひらがなの名", "　質疑を続けます。鈴木ただし君。", []string{"鈴木ただし"}},
		{"発言者ラベル・辞書にない姓 + 1 字の名", "○国務大臣（伊吹淳君）　お答えいたします。", []string{"伊吹淳"}},
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

// TestPostContextNegatives は、同じ形に見えるが個人を指さない行を氏名として報告しないことを確認する。
func TestPostContextNegatives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"これを許します。内閣総理大臣山田君。", // 姓だけ
		"会長の出身地です。",          // 職名の + 一般語
		"市長の定例会見です。",         // 職名の + 一般語
		"自民・党代表は、会見で述べた。",    // 政党の略称
		"歴代市長・議員の一覧",         // 職名の並び
		"当時の現職前知事が出席した。",     // 一般語 + 前知事
		"資料　参考文献（架空大学教授）",    // 氏名ではない語 + 括弧
		"架空大学教授全員さんにお願いします。", // 職名 + 一般語
		"○議長（諸君）　静粛に願います。",   // 一般語
		"○委員長（山田君）　次に移ります。",  // 姓だけ
		"氏名: 札幌 花子",          // 自治体名を姓にした記入例（実在の個人ではない）
		"氏名　千代田太郎",           // 同上
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 氏名として報告した: %s %q", line, f.RuleID, f.Match)
			}
		}
	}
	// 見出し「氏名」の次の行の記入例。
	for _, f := range d.ScanContent("f.txt", "氏名\n\n千代田 太郎\n") {
		t.Errorf("記入例を報告した: %s %q", f.RuleID, f.Match)
	}
	// 自治体名と同形でない姓の記入例でない氏名は従来どおり報告する。
	if fs := d.ScanLine("f.txt", 1, "氏名: 山田 花子"); len(fs) != 1 {
		t.Errorf("氏名を報告しなかった: %v", fs)
	}
}

// TestFacilityNumbersAreNotPersonalNumbers は、事業所・施設の番号や整理番号を、個人の番号として
// 報告しないことを確認する（いずれも個人を識別する番号ではない）。
//   - 介護保険の事業所番号（CSV の列見出し「介護保険事業所番号」、本文の「介護保険事業者 <県>指定№」）
//   - 「<団体コード>,<団体コード + 連番>」の施設 ID、抽選の当選番号の一覧（検査用数字が偶然合う 12 桁）
//   - 「年金」と同じ行にあるナビダイヤルの番号
//
// ラベル付きの個人の番号は従来どおり報告する。
func TestFacilityNumbersAreNotPersonalNumbers(t *testing.T) {
	d := newDetector(t, "")
	for _, c := range []struct{ file, content string }{
		{"jigyosho.csv", "サービス種類,介護保険事業所番号,事業所名称,電話番号\n通所介護,0970201042,架空デイサービス,\n訪問介護,0970201059,架空ヘルパーステーション,\n"},
		{"f.txt", "介護保険事業者　架空県指定№2471200192\n"},
		{"shisetsu.csv", "全国地方公共団体コード,ID,地方公共団体名,名称\n999001,999001000010,架空県架空市,架空介護センター\n999001,999001000028,架空県架空市,架空グループホーム\n"},
		{"f.txt", "当選番号　123456789018　555012345670　777000111220　888000999110　100000000000\n"},
		{"f.txt", "恩給や共済年金を担保とする融資のお問合せは、架空支店（Tel 0570-000000（ナビダイヤル））で承ります。\n"},
	} {
		for _, f := range d.ScanContent(c.file, c.content) {
			switch f.RuleID {
			case "jp-kaigo-insurance", "jp-my-number", "jp-pension-number":
				t.Errorf("%q: %s として報告した: %q", c.content, f.RuleID, f.Match)
			}
		}
	}
	for _, c := range []struct{ rule, content string }{
		{"jp-kaigo-insurance", "介護保険被保険者番号 0000123456\n"},
		{"jp-my-number", "個人番号 123456789018\n"},
		{"jp-my-number", "個人番号　123456789018　555012345676　777000111222　888000999114\n"},
		{"jp-pension-number", "基礎年金番号 1234-567890\n"},
	} {
		found := false
		for _, f := range d.ScanContent("f.txt", c.content) {
			if f.RuleID == c.rule {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: %s を報告しなかった", c.content, c.rule)
		}
	}
}

// TestHighRecallFacilityHonorifics は、高再現率モードで施設・事業者の名前に付く「様」「さん」
// （<地名>保育園様、事業所様、<姓>農園さん）を氏名として報告しないことを確認する。
func TestHighRecallFacilityHonorifics(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{
		"モデル園として、架空東保育園様にご参画いただいております。",
		"工事関係・事業所様へ",
		"本日の食材は、山田農園さんの「キャベツ」です。",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: 氏名として報告した: %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}
