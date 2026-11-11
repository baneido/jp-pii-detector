package detect

import (
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/checksum"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// 2026-11-11 の公開文書 2,307 件の確認で見つけた見逃し・誤検出を、合成値だけで再現したケース。
// 氏名は架空の定番名（山田 太郎 等）、番号・住所・電話はすべて架空の値で、収集した文書の内容は使わない。

// TestKunMinutesNames は国会・地方議会の会議録の「<氏名>君」の定型（発言者ラベル・登壇の注記・
// 議長の指名・議案の提出者・出席者名簿）を person-name-role-label（Medium）で拾うことを確認する。
// 会議録では議員・国務大臣を「君」で呼ぶ書式が定型で、氏名は特定の個人を識別できる個人情報に当たる。
// 実測では「君」付きの氏名を含む 5,897 行のうち、全モードで 24 行しか検出できていなかった。
func TestKunMinutesNames(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		want       []string
	}{
		{"発言者ラベル（役職と括弧）", "○議長（山田太郎君）　ただいまから会議を開きます。", []string{"山田太郎"}},
		{"発言者ラベルと議長の指名", "○副議長（佐藤花子君）　鈴木一郎君。", []string{"佐藤花子", "鈴木一郎"}},
		{"発言者ラベル（氏名だけ）", "○高橋健太君　ただいま議題となりました法律案について御説明します。", []string{"高橋健太"}},
		{"登壇の注記（大臣）", "　　　〔国務大臣田中美咲君登壇、拍手〕", []string{"田中美咲"}},
		{"登壇の注記（議員）", "　　　〔伊藤直樹君登壇〕", []string{"伊藤直樹"}},
		{"起立の注記", "　　　〔高橋健太君起立〕", []string{"高橋健太"}},
		{"議案の提出者", "日程第一　架空法案（山田太郎君外二名提出）", []string{"山田太郎"}},
		{"出席者名簿（字間あき）", "山田　太郎君　　　佐藤　　花子君　　　鈴木　一郎君", []string{"山田　太郎", "佐藤　　花子", "鈴木　一郎"}},
		{"大臣の出席者欄", "総務大臣　　　高橋　　健太君", []string{"高橋　　健太"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, f := range d.ScanLine("f.txt", 1, tt.line) {
				if f.RuleID == "person-name-role-label" && f.Confidence == rule.Medium {
					got = append(got, f.Match)
				}
			}
			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Fatalf("%q: got %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

// TestKunMinutesRejects は「君」を含む一般語・姓だけの呼びかけを氏名として拾わないことを確認する。
// 姓だけでは個人を特定できない書き方であり、「諸君」「光る君へ」「暴君」は人名ではない。
func TestKunMinutesRejects(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"次の諸君を任命することについて同意を求めます。",
		"大河ドラマ「光る君へ」の放送にあわせた催し",
		"山田君、それは違う。",
		"暴君 として知られる王",
		"○議長（山田君）　ただいまから会議を開きます。",
		"諸君 よく聞いてほしい",
	} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if strings.HasPrefix(f.RuleID, "person-name") {
				t.Errorf("%q: unexpected %s %q", line, f.RuleID, f.Match)
			}
		}
	}
}

// luhnComplete は数字列 body の末尾に Luhn の検査数字を付けた値を返す（テスト用の架空の番号を作る）。
func luhnComplete(body string) string {
	for c := '0'; c <= '9'; c++ {
		if checksum.Luhn(body + string(c)) {
			return body + string(c)
		}
	}
	return ""
}

// TestCreditCardRejectsAddressPhoneRun は、協賛店一覧の「<町名><番地> <電話番号>」のように番地と電話番号が
// 並んで偶然 Luhn を通る数字列を credit-card（High）として拾わないことを確認する（2026-11-11 に県の公開 PDF で
// 3 件実測した誤検出。カード番号の券面・入力欄の区切りは先頭 4 桁で、1〜2 桁の組は現れない）。
func TestCreditCardRejectsAddressPhoneRun(t *testing.T) {
	d := newDetector(t, "")
	// 「3-6-1X 012-345-678X」の形（番地 + 市外局番つき電話番号）で、全体が Luhn を通る架空の値を作る。
	digits := luhnComplete("361201234567")
	if len(digits) != 13 {
		t.Fatalf("test setup: luhn digits %q", digits)
	}
	line := "協賛店 架空町" + digits[0:1] + "-" + digits[1:2] + "-" + digits[2:4] + " " + digits[4:7] + "-" + digits[7:10] + "-" + digits[10:] + " 割引あり"
	for _, f := range d.ScanLine("f.txt", 1, line) {
		if f.RuleID == "credit-card" {
			t.Fatalf("%q: unexpected credit-card %q", line, f.Match)
		}
	}
	// 正しい区切り（4-4-4-4）のカード番号は従来どおり拾う。
	card := luhnComplete("453201234567890")
	cardLine := "カード番号 " + card[0:4] + "-" + card[4:8] + "-" + card[8:12] + "-" + card[12:]
	found := false
	for _, f := range d.ScanLine("f.txt", 1, cardLine) {
		if f.RuleID == "credit-card" {
			found = true
		}
	}
	if !found {
		t.Fatalf("%q: want credit-card", cardLine)
	}
}

// TestBankAccountRejectsPhoneContinuation は、協賛店一覧の「<銀行名> <支店名> <町名><番地> <市外局番>-<局番>-<番号>」
// で、番地と市外局番を口座番号の 3+4 表記として拾わないことを確認する（2026-11-11 に実測した誤検出）。
func TestBankAccountRejectsPhoneContinuation(t *testing.T) {
	d := newDetector(t, "")
	line := "架空銀行 架空支店    架空町大字架空456 0270-00-0000  金利優遇"
	for _, f := range d.ScanLine("f.txt", 1, line) {
		if f.RuleID == "jp-bank-account" {
			t.Fatalf("%q: unexpected jp-bank-account %q", line, f.Match)
		}
	}
	// 口座番号ラベルの 3+4 表記は従来どおり拾う。
	ok := "架空銀行 架空支店 口座番号 123 4567"
	found := false
	for _, f := range d.ScanLine("f.txt", 1, ok) {
		if f.RuleID == "jp-bank-account" {
			found = true
		}
	}
	if !found {
		t.Fatalf("%q: want jp-bank-account", ok)
	}
}

// TestEmailRejectsRepeatedLetterPlaceholder は、様式の記入例「xxxxx@yyyyy.jp」のような伏せ字の
// アドレスを拾わないことを確認する（2026-11-11 に市の申請様式で実測した誤検出。実在の宛先ではない）。
func TestEmailRejectsRepeatedLetterPlaceholder(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{"メール：xxxxx@yyyyy.jp", "E-mail AAAA@BBBB.co.jp"} {
		for _, f := range d.ScanLine("f.txt", 1, line) {
			if f.RuleID == "email-address" {
				t.Errorf("%q: unexpected email %q", line, f.Match)
			}
		}
	}
	// ローカル部だけが繰り返しのアドレスは実在しうるので拾う。
	line := "連絡先 zzz@kaisha-mail.jp"
	found := false
	for _, f := range d.ScanLine("f.txt", 1, line) {
		if f.RuleID == "email-address" {
			found = true
		}
	}
	if !found {
		t.Fatalf("%q: want email-address", line)
	}
}

// TestHighRecallRejectsChoTayou は高再現率モードで、催し名の「～超多様～」の「超多」を敬称付き氏名と
// みなさないことを確認する（2026-11-11 に大学の催し案内で実測した誤検出）。姓 + 様（本多様）は残す。
func TestHighRecallRejectsChoTayou(t *testing.T) {
	d := newDetector(t, "[rules]\nhigh_recall = true\n")
	for _, f := range d.ScanLine("f.txt", 1, "「架空の催し～超多様～」内の展示") {
		if strings.HasPrefix(f.RuleID, "person-name") {
			t.Fatalf("unexpected %s %q", f.RuleID, f.Match)
		}
	}
}
