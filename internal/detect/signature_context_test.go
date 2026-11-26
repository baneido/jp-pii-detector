package detect

import (
	"sort"
	"strings"
	"testing"
)

// 2026-11-26 の公開文書 1,538 件の確認で見つけた見逃しと範囲の誤りの「形」を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）と、辞書に無い架空の名で、収集した文書の内容は使わない。

// TestJudgeSignatureSpacedNames は、判決書の末尾の署名「裁判官　<1 字ずつ離した氏名>」を
// person-name-role-label で拾うことを確認する。最高裁判所の判決書の PDF をレイアウトを保って文字にすると、
// 均等割付の署名が 1 字ずつ離れ、実測では人を指す語のある無作為 460 行の正解（姓+名 119 人）のうち、
// この形の 28 人を全モードで 1 人も拾えていなかった。裁判官の氏名も特定の個人を識別できる情報
// （個人情報保護法）に当たる。
func TestJudgeSignatureSpacedNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line, want string
	}{
		{"裁判官 + 1 字ずつの姓名", "              裁判官           山   田   太   郎", "山   田   太   郎"},
		{"裁判長裁判官 + 姓名（名が 1 字、姓名の間が広い）", "         裁判長裁判官            佐   藤       茂", "佐   藤       茂"},
		{"3 字の名", "             裁判官           鈴   木   一   太   郎", "鈴   木   一   太   郎"},
		{"名が辞書に無い（姓は辞書にある）", "                裁判官           高   橋   朔       東", "高   橋   朔       東"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, f := range d.ScanLine("f.txt", 1, tt.line) {
				if strings.HasPrefix(f.RuleID, "person-name") {
					got = append(got, f.Match)
				}
			}
			if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("%q: got %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// TestJudgeSignatureNegatives は、判決書の同じ形に見えるが氏名でない行（本文の「裁判官全員一致」、
// 1 字ずつ離した一般語）を、高再現率モードでも氏名として報告しないことを確認する。
func TestJudgeSignatureNegatives(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, line := range []string{
		" この判決は裁判官全員一致の意見によるものである。",                 // 本文
		"              裁判官           全   員   一   致", // 1 字ずつ離した一般語
		"              裁判官           退       官",     // 同上
		"              裁判官           氏   名   省   略", // 伏せた署名
		"         裁判長裁判官            公   判   中",      // 一般語
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestOldFormKanjiNames は、旧字体で書かれた名（「豐一」「德次」は辞書に新字体の「豊一」「徳次」だけがある）を、
// 新字体と同じく拾うことを確認する。1950 年代の国会の会議録の「○議長（<姓><旧字体の名>君）」を、
// 新字体の氏名は拾えるのに全モードで見逃していた。
func TestOldFormKanjiNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"発言者ラベルの括弧内の旧字体の名", "○議長（山田豐一君）　御異議ないと認めます。", []string{"山田豐一"}},
		{"会議録の名簿の旧字体の名", "○政府委員（佐藤德次君）　お答えいたします。", []string{"佐藤德次"}},
		{"新字体の名（従来どおり）", "○議長（山田豊一君）　御異議ないと認めます。", []string{"山田豊一"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, f := range d.ScanLine("f.txt", 1, tt.line) {
				if strings.HasPrefix(f.RuleID, "person-name") {
					got = append(got, f.Match)
				}
			}
			sort.Strings(got)
			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Fatalf("%q: got %q, want %q", tt.line, got, tt.want)
			}
		})
	}
	// 旧字体の一般語の組は、新字体に畳んでも一般語なので氏名にしない。
	for _, line := range []string{"院長 學校 醫療", "会長 學校 圖書"} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// TestKunTodanLooseNames は、会議録の登壇の注記「〔<職名><氏名>君登壇〕」で、名が辞書に無い氏名・姓が
// 辞書に無い氏名を、発言者ラベルと同じ検証で拾うことを確認する（2026-11-26 に 1950 年代の会議録で実測した
// 見逃し）。注記の中の職名だけ・議事の注記は拾わない。
func TestKunTodanLooseNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"名が辞書に無い", "　　　　〔山田朔東君登壇〕", []string{"山田朔東"}},              // jp-pii-detector:ignore（合成ケース。架空の氏名）
		{"職名 + 姓が辞書に無い氏名", "　　　〔国務大臣架空太郎君登壇、拍手〕", []string{"架空太郎"}}, // jp-pii-detector:ignore（合成ケース。架空の氏名）
		{"辞書どおりの氏名（従来どおり）", "　　　〔佐藤花子君登壇〕", []string{"佐藤花子"}},       // jp-pii-detector:ignore（合成ケース。架空の氏名）
		{"議事の注記", "　　　　〔議長退席、副議長着席〕", nil},
		{"賛成者起立", "　　　　〔賛成者起立〕", nil},
		{"職名だけ", "　　　〔国務大臣登壇、拍手〕", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, f := range d.ScanLine("f.txt", 1, tt.line) {
				if strings.HasPrefix(f.RuleID, "person-name") {
					got = append(got, f.Match)
				}
			}
			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Fatalf("%q: got %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// TestHonorificLeadInAdverbRange は、高再現率モードの敬称パターンが、会議録の「多分<姓>さんは」
// 「大体<姓>さんの」「現在<姓><名>さんは」「往年<姓><名>氏が」「政治家<姓>さんを」で、前の副詞・
// 一般語を値に含めず、氏名だけを報告することを確認する（2026-11-26 に実測した範囲の誤り）。
func TestHonorificLeadInAdverbRange(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	tests := []struct{ line, want string }{
		{"○架空国務大臣　多分山田さんは御承知で言っておられる", "山田"},
		{"大体佐藤さんのおつしやるところでは", "佐藤"},
		{"○架空委員長　現在鈴木一郎さんは出席しておりません。", "鈴木一郎"},
		{"往年高橋健太氏が", "高橋健太"},
		{"政治家田中さんを信頼する", "田中"},
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
	for _, line := range []string{"現在さんぽ中です", "多分様々な意見がある", "本日様々なイベントを開催"} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}
