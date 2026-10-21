package model

import "testing"

func TestRecognizeBankAccountFromModelSpan(t *testing.T) {
	// Sumi は銀行名・支店・種別まで含めて BANK_ACCOUNT とする。スパン内の口座番号だけを報告する。
	text := "振込先は見本銀行 架空支店 普通 4728163、名義は本人です。"
	r := fakeRecognizer(t, text, []fakeSpan{{"見本銀行 架空支店 普通 4728163", "BANK_ACCOUNT", 10}})
	got, err := r.Recognize(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].RuleID != "jp-bank-account" || got[0].Column != 18 || got[0].Length != 7 {
		t.Fatalf("got %+v", got)
	}
}

func TestRecognizeBankAccountSpanNeedsBankWordsAndHighProb(t *testing.T) {
	for _, tc := range []struct {
		name, text, span string
		logit            float32
	}{
		{"銀行の語がない", "ビルド番号 架空 4728163 を参照", "架空 4728163", 10},
		{"確率が低い", "見本銀行 普通 4728163", "見本銀行 普通 4728163", 4.5},
		{"口座番号の書式でない", "見本銀行 普通 47", "見本銀行 普通 47", 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := fakeRecognizer(t, tc.text, []fakeSpan{{tc.span, "BANK_ACCOUNT", tc.logit}})
			got, err := r.Recognize(tc.text)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 0 {
				t.Errorf("got %+v", got)
			}
		})
	}
}

func TestRecognizeSingleKanjiSurnameNeedsHonorific(t *testing.T) {
	text := "森さんに連絡する。森の中を歩いた。"
	r := fakeRecognizer(t, text, []fakeSpan{{"森さん", "NAME", 10}})
	// fakeRecognizer は最初の出現にだけラベルを付けるので、地の文の「森」は別に確かめる。
	got, err := r.Recognize(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].RuleID != "person-name" {
		t.Fatalf("got %+v", got)
	}

	text = "昨日は森の中を歩いた。"
	r = fakeRecognizer(t, text, []fakeSpan{{"森", "NAME", 10}})
	if got, _ := r.Recognize(text); len(got) != 0 {
		t.Errorf("敬称のない 1 文字を氏名にした: %+v", got)
	}
}

func TestRecognizeSingleKanjiSpanWithHonorific(t *testing.T) {
	text := "森さんに連絡する。"
	r := fakeRecognizer(t, text, []fakeSpan{{"森", "NAME", 10}})
	got, err := r.Recognize(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Column != 1 || got[0].Length != 1 {
		t.Fatalf("got %+v", got)
	}
	r = fakeRecognizer(t, text, []fakeSpan{{"森", "NAME", 4.5}}) // medium 相当
	if got, _ := r.Recognize(text); len(got) != 0 {
		t.Errorf("確率が低い 1 文字を氏名にした: %+v", got)
	}
}

func TestRecognizeRomajiNames(t *testing.T) {
	text := "author: Taro Yamada / import os / def main / user_id / Hello World / John Smith"
	r := fakeRecognizer(t, text, []fakeSpan{
		{"Taro Yamada", "EMAIL", 10}, // Sumi はローマ字の氏名を EMAIL とすることがある
		{"os", "NAME", 10},
		{"def main", "NAME", 10},
		{"user_id", "NAME", 10},
		{"Hello World", "NAME", 4.5}, // 大文字始まりでも確率が highProb 未満なら報告しない
		{"John Smith", "NAME", 10},
	})
	got, err := r.Recognize(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].RuleID != "person-name" || got[0].Column != 9 || got[0].Length != 11 ||
		got[1].Length != 10 {
		t.Fatalf("got %+v", got)
	}
}

func TestRecognizeDropsOrganizationNames(t *testing.T) {
	text := "例: `フリーギンコウ` と 見本商事株式会社 と ミホンシンキン"
	r := fakeRecognizer(t, text, []fakeSpan{
		{"フリーギンコウ", "NAME", 10},
		{"見本商事株式会社", "NAME", 10},
		{"ミホンシンキン", "NAME", 10},
	})
	if got, _ := r.Recognize(text); len(got) != 0 {
		t.Errorf("組織名を氏名にした: %+v", got)
	}
}

func TestRecognizeDropsNamePartsOfLongerWords(t *testing.T) {
	text := "例: `フリーギンコウ` / getTanakaValue / 担当はタナカ ジロウです"
	r := fakeRecognizer(t, text, []fakeSpan{
		{"ギン", "NAME", 10},
		{"Tanaka", "NAME", 10},
		{"タナカ ジロウ", "NAME", 10},
	})
	got, err := r.Recognize(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Length != 7 {
		t.Errorf("語の一部を氏名にした、または正しい氏名を落とした: %+v", got)
	}
}
