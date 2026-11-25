package detect

import (
	"sort"
	"strings"
	"testing"
)

// 2026-11-25 の公開文書 8,083 件の確認で見つけた見逃し・誤検出の「形」を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）、組織名・番号もすべて架空で、収集した文書の内容は使わない。

// TestAppointContextNames は、「<氏名>が社長就任」、「<氏名>社長就任」、「に就任した<氏名>です」、
// 「<氏名>招へい教授」、「新院長：<氏名> 先生」、「報告：<氏名>氏」、写真の説明の「左：<氏名> 代表取締役」、
// 「当社 <氏名>代表取締役社長」、行全体が「学校長 <姓> <名>」の形を person-name-role-label で拾うことを
// 確認する。いずれも職名と一緒に書かれた特定の個人の氏名で、個人情報保護法の「特定の個人を識別できる
// 情報」に当たる。実測では、人を指す語のある無作為 1,060 行の正解（姓+名 113 人）のうち、既定モードが
// 拾えたのは 84 人だった。
func TestAppointContextNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"氏名 + が + 社長就任", "山田太郎が社長就任。社内改革を推進。", []string{"山田太郎"}},
		{"氏名 + 氏が + 代表取締役社長に就任", "2020年4月 佐藤花子氏が代表取締役社長に就任", []string{"佐藤花子"}},
		{"創設者の + 氏名 + が + 理事長に就任", "架空連盟創設者の高橋健太が理事長に就任、2019年に高橋直樹が理事長に就任。", []string{"高橋健太", "高橋直樹"}},
		{"氏名 + 社長就任", "2016(平成28)年 5月　取締役交代　鈴木一郎社長就任", []string{"鈴木一郎"}},
		{"に就任した + 氏名 + です", "2018年度より、架空町内会長に就任した山田太郎です。", []string{"山田太郎"}},
		{"氏名 + 招へい教授", "架空研究所の山田太郎准教授・佐藤花子招へい教授、同研究所の鈴木一郎特任准教授（常勤）", []string{"山田太郎", "佐藤花子", "鈴木一郎"}},
		{"新院長：氏名 + 先生", "2024.12.01お知らせ12月1日 新院長：山田太郎 先生・就任", []string{"山田太郎"}},
		{"新院長：氏名（行末）", "新院長：鈴木一郎", []string{"鈴木一郎"}},
		{"報告：氏名 + 氏", "報告：山田太郎氏", []string{"山田太郎"}},
		{"講演：姓 名 + 氏", "講演：佐藤 花子氏", []string{"佐藤 花子"}},
		{"写真の説明の左・中央・右", "（左：山田太郎 代表取締役 、中央：佐藤花子市長、右： 当社 鈴木一郎代表取締役社長兼 CEO）", []string{"山田太郎", "佐藤花子", "鈴木一郎"}},
		{"学校長 + 姓 名（行全体。後ろに中黒）", "                             学校長 山田 太郎                          ・   ", []string{"山田 太郎"}},
		{"学校長 + 辞書に無い姓 + 名", "学校長 釈迦堂 弘修", []string{"釈迦堂 弘修"}},
		{"学部の + 氏名 + 特命教授ら（特命を含めない）", "本学架空学部の山田茂特命教授らの共同研究グループが", []string{"山田茂"}},
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

// TestAppointContextNegatives は、同じ形に見えるが個人を指さない行を、高再現率モードでも氏名として
// 報告しないことを確認する。
func TestAppointContextNegatives(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{
		"前副社長が社長就任",              // 氏名がない（職名だけ）
		"新会社社長就任のお知らせ",           // 一般語 + 職名
		"会長に就任した当時の方針です",         // 氏名がない
		"院長 外来 担当",               // 職名 + 一般語の組
		"会長 挨拶 要旨",               // 同上
		"左：東京本社 取締役会",            // 写真の説明の位置の語 + 組織名
		"報告：令和八年度事業計画",           // 次第の役 + 議題
		"当社 代表取締役社長",             // 氏名がない
		"未就園児さん向けのイベントも開催しています。", // 一般語 + さん
		"【ミニ企画展】大工さんの記録",         // 同上
		"寮長寮母さんが住み込みでしっかりサポート",   // 同上
		"ピアトレーニングの依頼と実施（幹事様向け）",  // 一般語 + 様
		"詩のワークショップ　詩人さんめがね",      // 一般語 + さん
		"外題は「近江源氏先陣館盛綱陣屋の段」",     // 旧国名を冠した源氏（作品の名前）
		"甲斐源氏の祖として知られている",        // 同上
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestAppointContextHonorificRange は、高再現率モードで「<氏名>各氏」「<姓>両氏」の「各」「両」まで含む
// 範囲を報告しないこと、既定モードで見出しの次の行の「<姓> <名>氏」は敬称を外して報告することを確認する。
func TestAppointContextHonorificRange(t *testing.T) {
	hr := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{"室内楽を金昌国各氏に師事。", "馬・木村両氏の発見は"} {
		for _, f := range hr.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") && (strings.HasSuffix(f.Match, "各") || strings.HasSuffix(f.Match, "両")) {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
	d := newDetector(t, "")
	// 「26日前 <姓>さん」の「日前」は投稿からの経過日数で、姓ではない（既定モードは姓だけの「<姓>さん」を報告しない）。
	for _, f := range d.ScanLine("f.txt", 1, "2020年7月6日　26日前　山田さん") {
		if strings.HasPrefix(f.RuleID, "person-name") {
			t.Errorf("日前: unexpected %s %q", f.RuleID, f.Match)
		}
	}
	var got []string
	for _, f := range d.ScanContent("f.txt", "講師：架空の会　読み聞かせ講師\n\n山田　花子氏\n") {
		if strings.HasPrefix(f.RuleID, "person-name") {
			got = append(got, strings.ReplaceAll(f.Match, "　", " "))
		}
	}
	if len(got) != 1 || got[0] != "山田 花子" {
		t.Errorf("got %q, want [山田 花子]", got)
	}
}

// TestAppointContextNumberFalsePositives は、番号のルールの誤検出を確認する。いずれも個人の番号ではない。
//   - 「介護保険指定番号 <県名> <10 桁> 号」は事業所の番号（jp-kaigo-insurance）
//   - 統計 CSV の「18.<8 桁>」は小数部（jp-health-insurance）
//   - 予算書 CSV の「予算額」「支出額(円)」の列は金額（jp-health-insurance・jp-my-number）
//   - 施設一覧 CSV の郵便番号の欄（次の欄が住所）は、同じ行に銀行名があっても口座番号ではない（jp-bank-account）
func TestAppointContextNumberFalsePositives(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	has := func(fs []Finding, id string) bool {
		for _, f := range fs {
			if f.RuleID == id {
				return true
			}
		}
		return false
	}
	if fs := d.ScanLine("f.txt", 1, "  ⑤ 介護保険指定番号 架空 3810528145 号"); has(fs, "jp-kaigo-insurance") {
		t.Errorf("指定番号: unexpected jp-kaigo-insurance")
	}
	if fs := d.ScanLine("f.txt", 1, "介護保険被保険者番号 3810528145"); !has(fs, "jp-kaigo-insurance") { // jp-pii-detector:ignore（合成ケース。架空の番号）
		t.Errorf("被保険者番号: jp-kaigo-insurance が消えた")
	}
	if fs := d.ScanLine("f.txt", 1, "被保険者 26,7,9.027777778,26.92307692,18.08066759,4.867872045"); has(fs, "jp-health-insurance") {
		t.Errorf("小数部: unexpected jp-health-insurance")
	}
	budget := "01会計,02款,07細々節,08予算額\n02国民健康保険事業特別会計,01一般被保険者療養給付費,01療養給付費,10042846\n"
	if fs := d.ScanContent("yosan.csv", budget); has(fs, "jp-health-insurance") {
		t.Errorf("予算額の列: unexpected jp-health-insurance")
	}
	kessan := "\"支出／科目\",\"支出／支出額(円)\"\n\"保険給付費／一般被保険者分／高額介護合算療養費\",\"22278253\"\n\"支出合計\",\"503124377201\"\n"
	if fs := d.ScanContent("kessan.csv", kessan); has(fs, "jp-health-insurance") || has(fs, "jp-my-number") {
		t.Errorf("支出額の列: unexpected %v", fs)
	}
	shisetsu := "施設名,アクセス,郵便番号,住所,電話\n架空食堂 駅前店,架空駅南口すぐ　ゆうちょ銀行架空店向かい,1000001,東京都千代田区千代田1-1,\n"
	if fs := d.ScanContent("shisetsu.csv", shisetsu); has(fs, "jp-bank-account") {
		t.Errorf("郵便番号の欄: unexpected jp-bank-account")
	}
	// 口座番号の欄は従来どおり拾う。
	koza := "氏名,銀行名,口座番号\n架空 太郎,みずほ銀行,1234567\n" // jp-pii-detector:ignore（合成ケース。架空の番号）
	if fs := d.ScanContent("koza.csv", koza); !has(fs, "jp-bank-account") {
		t.Errorf("口座番号の欄: jp-bank-account が消えた")
	}
}

// TestAppointContextCSVReadingColumn は、高再現率モードで「観光地名,ふりがな」の読みの列を氏名として
// 報告しないこと、「氏名,フリガナ」の読みの列は従来どおり拾うことを確認する。施設・場所の名前の読みは
// 個人を識別する情報ではない。
func TestAppointContextCSVReadingColumn(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, f := range d.ScanContent("kanko.csv", "ID,観光地名,ふりがな,市町村\n863,鎌倉街道,カマクラカイドウ,架空町\n864,高倉寺,コウソウジ,架空市\n") {
		if strings.HasPrefix(f.RuleID, "person-name") {
			t.Errorf("観光地名の読み: unexpected %s %q", f.RuleID, f.Match)
		}
	}
	n := 0
	for _, f := range d.ScanContent("meibo.csv", "ID,氏名,フリガナ\n1,山田太郎,ヤマダタロウ\n") {
		if f.RuleID == "person-name-structured" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("氏名・フリガナの列: got %d, want 2", n)
	}
}

// TestAppointContextEAIGluedLabel は、高再現率モードで「ライブラリー<ASCII のアドレス>」のように窓口の名前が
// 付いたままの範囲を email-address-eai として報告せず、ASCII の部分を email-address が拾うことを確認する。
func TestAppointContextEAIGluedLabel(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	var ids []string
	for _, f := range d.ScanLine("f.txt", 1, "ライブラリーlibrary9@tosho.kakuu-u.ac.jp") {
		ids = append(ids, f.RuleID+":"+f.Match)
	}
	if len(ids) != 1 || ids[0] != "email-address:library9@tosho.kakuu-u.ac.jp" {
		t.Errorf("got %q", ids)
	}
}
