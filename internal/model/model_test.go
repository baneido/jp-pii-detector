package model

import (
	"strconv"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/checksum"
	"github.com/baneido/jp-pii-detector/internal/external"
)

var testLabels = []string{"O", "B-NAME", "I-NAME", "B-ADDRESS", "I-ADDRESS", "B-PHONE", "I-PHONE",
	"B-EMAIL", "I-EMAIL", "B-DOB", "I-DOB", "B-BANK_ACCOUNT", "I-BANK_ACCOUNT",
	"B-CREDIT_CARD", "I-CREDIT_CARD", "B-MYNUMBER", "I-MYNUMBER", "B-MEMBER_ID", "I-MEMBER_ID",
	"B-POSTAL_CODE", "I-POSTAL_CODE"}

// runeTokenizer は 1 ルーン = 1 トークンの最小トークナイザ（ID はルーンの値 + 1000）。
func runeTokenizer() *tokenizer {
	t := &tokenizer{pieces: map[string]piece{}, maxRunes: 1}
	for i := range t.bytes {
		t.bytes[i] = int64(i + 100)
	}
	return t
}

func (t *tokenizer) addRunes(s string) {
	for _, r := range s {
		t.pieces[string(r)] = piece{id: int64(r) + 1000, score: -1}
	}
}

// fakeRecognizer は text のうち spans で指定した部分文字列に、指定の種別と確率の
// BIO ラベルを付ける偽のモデルで Recognizer を作る。推論は窓の順に呼ばれるので、
// これまでに受け取ったトークン数から元テキスト上の位置を求める。
func fakeRecognizer(t *testing.T, text string, spans []fakeSpan) *Recognizer {
	t.Helper()
	tok := runeTokenizer()
	tok.addRunes(text)
	runes := []rune(text)
	labels := make([]string, len(runes))
	logit := make([]float32, len(runes))
	for i := range labels {
		labels[i] = "O"
		logit[i] = 10
	}
	for _, s := range spans {
		start := strings.Index(text, s.value)
		if start < 0 {
			t.Fatalf("%q が本文にありません", s.value)
		}
		rs := len([]rune(text[:start]))
		for i := range []rune(s.value) {
			labels[rs+i] = "I-" + s.typ
			logit[rs+i] = s.logit
		}
		labels[rs] = "B-" + s.typ
	}
	cursor := 0
	infer := func(ids []int64) ([][]float32, error) {
		out := make([][]float32, len(ids))
		for i := range out {
			out[i] = make([]float32, len(testLabels))
			if i == 0 || i == len(ids)-1 {
				out[i][0] = 10
				continue
			}
			pos := cursor + i - 1
			for k, l := range testLabels {
				if l == labels[pos] {
					out[i][k] = logit[pos]
				}
			}
		}
		cursor += len(ids) - 2
		return out, nil
	}
	return &Recognizer{tok: tok, infer: infer, labels: testLabels, temperature: 1}
}

type fakeSpan struct {
	value, typ string
	logit      float32 // 10 で確率約 0.9991、3.4 で約 0.60（ラベル数 21）
}

// withCheckDigit は 11 桁にマイナンバーの検査用数字を付ける。
func withCheckDigit(t *testing.T, body string) string {
	for d := range 10 {
		if v := body + strconv.Itoa(d); checksum.MyNumber(v) {
			return v
		}
	}
	t.Fatalf("検査用数字が見つかりません: %s", body)
	return ""
}

// withLuhn は Luhn を満たすよう末尾の 1 桁を付ける。
func withLuhn(t *testing.T, body string) string {
	for d := range 10 {
		if v := body + strconv.Itoa(d); checksum.CreditCard(v) {
			return v
		}
	}
	t.Fatalf("Luhn を満たす数字が見つかりません: %s", body)
	return ""
}

func candidatesByRule(cs []external.Candidate) map[string]external.Candidate {
	m := map[string]external.Candidate{}
	for _, c := range cs {
		m[c.RuleID] = c
	}
	return m
}

func TestRecognizeMapsSpansToRuleIDsAndRuneColumns(t *testing.T) {
	phone := "090-" + "3812-4471" // jp-pii-detector:ignore
	text := "1行目\n昨日、佐藤花子から連絡。折り返しは" + phone + "まで\n"
	r := fakeRecognizer(t, text, []fakeSpan{{"佐藤花子", "NAME", 10}, {phone, "PHONE", 10}})
	got, err := r.Recognize(text)
	if err != nil {
		t.Fatal(err)
	}
	m := candidatesByRule(got)
	if c := m["person-name"]; c.Line != 2 || c.Column != 4 || c.Length != 4 || c.Confidence != "high" {
		t.Errorf("person-name = %+v", c)
	}
	if c := m["jp-phone-number"]; c.Line != 2 || c.Column != 18 || c.Length != 13 {
		t.Errorf("jp-phone-number = %+v", c)
	}
}

func TestRecognizeRetypesDigitSpansByFormat(t *testing.T) {
	myNumber := withCheckDigit(t, "38291047562")
	card := withLuhn(t, "453901234567890")
	// モデルがマイナンバーを CREDIT_CARD、カード番号を MYNUMBER と取り違えても、
	// 書式（検査用数字・Luhn）で正しいルール ID に付け直す。
	text := "値 " + myNumber + " と " + card
	r := fakeRecognizer(t, text, []fakeSpan{{myNumber, "CREDIT_CARD", 10}, {card, "MYNUMBER", 10}})
	got, err := r.Recognize(text)
	if err != nil {
		t.Fatal(err)
	}
	m := candidatesByRule(got)
	if _, ok := m["jp-my-number"]; !ok {
		t.Errorf("マイナンバーに付け直されていない: %+v", got)
	}
	if _, ok := m["credit-card"]; !ok {
		t.Errorf("カード番号に付け直されていない: %+v", got)
	}
}

func TestRecognizeDropsSpansThatFailConfirmation(t *testing.T) {
	bad := withCheckDigit(t, "38291047562")
	bad = bad[:11] + strconv.Itoa((int(bad[11]-'0')+1)%10) // 検査用数字を壊す
	text := "user_name と 一乗寺払殿町 と 会員 A12345 と " + bad + " と 1"
	r := fakeRecognizer(t, text, []fakeSpan{
		{"user_name", "EMAIL", 10},  // @ がない
		{"一乗寺払殿町", "ADDRESS", 10},   // 番地がない
		{"A12345", "MEMBER_ID", 10}, // 対象外の種別
		{bad, "MYNUMBER", 10},       // 検査用数字が合わない
		{"1", "DOB", 10},            // 年月日が揃わない
	})
	got, err := r.Recognize(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("確認器で落ちるべき候補が残った: %+v", got)
	}
}

func TestRecognizeConfidenceFromProbability(t *testing.T) {
	text := "担当の高橋健太と、田村さん"
	r := fakeRecognizer(t, text, []fakeSpan{{"高橋健太", "NAME", 4.5}, {"田村", "NAME", 2.5}})
	got, err := r.Recognize(text)
	if err != nil {
		t.Fatal(err)
	}
	// 4.5 → 約 0.82（medium）。2.5 → 約 0.38 で閾値 0.5 未満のため候補にしない。
	if len(got) != 1 || got[0].Confidence != "medium" || got[0].Length != 4 {
		t.Errorf("got %+v", got)
	}
}

func TestRecognizeSplitsSpanAcrossLines(t *testing.T) {
	text := "宛先\n東京都渋谷区\n道玄坂2-10-7\n"
	r := fakeRecognizer(t, text, []fakeSpan{{"東京都渋谷区\n道玄坂2-10-7", "ADDRESS", 10}})
	got, err := r.Recognize(text)
	if err != nil {
		t.Fatal(err)
	}
	// 1 行目の断片は番地がないので落ち、2 行目の断片だけが残る。
	if len(got) != 1 || got[0].Line != 3 || got[0].Column != 1 || got[0].Length != 9 {
		t.Errorf("got %+v", got)
	}
}

func TestWindowsPreferNewlineAndSplitLongLines(t *testing.T) {
	var b strings.Builder
	for range 100 {
		b.WriteString("あいう\n") // 4 トークン/行
	}
	text := b.String()
	tok := runeTokenizer()
	tok.addRunes(text)
	runes := []rune(text)
	ws := windows(runes, tok.encode(text))
	total := 0
	for _, w := range ws {
		if len(w) > maxWindowTokens {
			t.Fatalf("窓が上限を超えた: %d", len(w))
		}
		if last := w[len(w)-1]; runes[last.Start] != '\n' {
			t.Errorf("窓が行の途中で切れた: %q", string(runes[last.Start]))
		}
		total += len(w)
	}
	if total != 400 {
		t.Errorf("トークンの合計 %d, want 400", total)
	}

	long := strings.Repeat("あ", 600)
	tok.addRunes(long)
	ws = windows([]rune(long), tok.encode(long))
	if len(ws) != 3 || len(ws[0]) != maxWindowTokens {
		t.Errorf("改行のない長い行の窓: %d 個, 先頭 %d トークン", len(ws), len(ws[0]))
	}
}

func TestRecognizeSecondWindowCoordinates(t *testing.T) {
	text := strings.Repeat("あいう\n", 100) + "連絡は佐藤花子まで\n"
	r := fakeRecognizer(t, text, []fakeSpan{{"佐藤花子", "NAME", 10}})
	got, err := r.Recognize(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Line != 101 || got[0].Column != 4 {
		t.Errorf("got %+v", got)
	}
}
