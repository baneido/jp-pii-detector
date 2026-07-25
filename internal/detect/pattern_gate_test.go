package detect

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/normalize"
)

// gateSoundnessAlphabet はゲート健全性検証で組み立てるランダム行の素材。
// 数字・区切り記号・英字に加えて、ラベル語や住所語に使われる日本語の文字を
// 混ぜることで、電話番号・郵便番号・住所・氏名など各ルールが実際に反応
// しうる形の行が現れるようにする。要素は 1 文字ずつなので、このソース自身は
// PII 形状にならない（ドッグフーディング走査で検出されない）。
var gateSoundnessAlphabet = []string{
	"a", "A", "0", "1", "5", "9", "@", ".", "-", "_", " ", ":", "/", "+", ",", "#",
	"あ", "漢", "電", "話", "番", "号", "住", "所", "氏", "名", "前", "様", "円", "件",
	"県", "市", "区", "町", "村", "丁", "目", "郵", "便", "座", "金", "銀", "行",
	"ー", "ｰ", "１", "９", "　", "〒", "－",
}

// TestPatternGateSoundness は patternGate の唯一の正しさ条件、すなわち
// 「ゲートがスキップした行は、その正規表現を実行しても絶対にマッチしない」
// ことを、全ルール（高再現率ルール込み）× 全パターン × 多様なランダム行の
// 総当たりで検証する。patternGate は構文木から保証下限を導出する保守側の
// 近似なので、この不変条件さえ守られていれば検出結果は一切変わらない。
// 逆向き（マッチしない行を必ずスキップする）は最適化の効き具合の話であり、
// 正しさではないので検証しない。
//
// 行は固定シードの擬似乱数で生成するため、失敗は常に再現できる。
func TestPatternGateSoundness(t *testing.T) {
	cfg := config.Default()
	// 高再現率ルールのパターンもゲート対象なので有効にして全数を見る。
	cfg.SetHighRecall(true)
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	rnd := rand.New(rand.NewSource(20260725))
	const lines = 20000
	skips := 0
	for i := 0; i < lines; i++ {
		var sb strings.Builder
		for j := rnd.Intn(48); j > 0; j-- {
			sb.WriteString(gateSoundnessAlphabet[rnd.Intn(len(gateSoundnessAlphabet))])
		}
		// 走査本体と同じく、ゲート判定も正規表現も正規化済みの行に対して行う。
		norm := normalize.Line(sb.String())
		feats := classifyLine(norm)
		for ri := range d.rules {
			for pi := range d.rules[ri].Patterns {
				if !d.patternGates[ri][pi].skips(feats) {
					continue
				}
				skips++
				re := d.rules[ri].Patterns[pi].Re
				if loc := re.FindStringIndex(norm); loc != nil {
					t.Fatalf("ゲートがマッチする行をスキップした: rule=%s pattern=%q\n  line=%q\n  match=%q\n  gate=%+v feats=%+v",
						d.rules[ri].ID, re.String(), norm, norm[loc[0]:loc[1]],
						d.patternGates[ri][pi], feats)
				}
			}
		}
	}
	if skips == 0 {
		// スキップが 1 件も起きていないなら、この検証は何も見ていない。
		t.Fatal("ゲートによるスキップが一度も発生しなかった（検証が空回りしている）")
	}
	t.Logf("検証したスキップ: %d 件 / ランダム行 %d 本", skips, lines)
}

// normalizeConcatAlphabet は正規化の連結不変条件を試す素材。正規化が実際に
// 変換する文字（全角英数・全角ハイフン類・長音記号・全角空白）と、変換
// 対象の判定が隣接文字に依存する組み合わせ（数字に隣接する長音記号など）が
// 行境界をまたいで誤って成立しないかを突くために、半角カナや結合記号も混ぜる。
var normalizeConcatAlphabet = []string{
	"a", "A", "0", "9", "@", " ", "-", ".",
	"あ", "漢", "ー", "ｰ", "゠", "－", "‐", "‑", "–", "—", "―",
	"１", "９", "Ａ", "ｚ", "　", "ｱ", "ﾝ", "ﾞ", "ﾟ", "･",
}

// TestNormalizeLineConcatInvariant は combineLineStates が依拠する不変条件
// normalize.Line(a+"\n"+b) == normalize.Line(a)+"\n"+normalize.Line(b)
// を検証する。隣接行ペア走査は、2 行を個別に正規化した結果を '\n' で
// つないだものを結合行の正規化結果として再利用しており、この等式が崩れると
// 走査対象の文字列そのものがずれて検出結果が変わる。
//
// 正規化はルーン単位の 1:1 変換であり、隣接文字を見る規則（数字に隣接する
// 長音記号のハイフン化など）も '\n' を挟めば成立しないため等式は常に成り立つ。
// 将来この前提を崩す規則が入ったらここで落ちる。
func TestNormalizeLineConcatInvariant(t *testing.T) {
	rnd := rand.New(rand.NewSource(20260726))
	mk := func() string {
		var sb strings.Builder
		for j := rnd.Intn(10); j > 0; j-- {
			sb.WriteString(normalizeConcatAlphabet[rnd.Intn(len(normalizeConcatAlphabet))])
		}
		return sb.String()
	}
	for i := 0; i < 200000; i++ {
		a, b := mk(), mk()
		got := normalize.Line(a + "\n" + b)
		want := normalize.Line(a) + "\n" + normalize.Line(b)
		if got != want {
			t.Fatalf("正規化の連結不変条件が崩れた: a=%q b=%q\n  got =%q\n  want=%q", a, b, got, want)
		}
	}
}

// TestCombineLineStatesMatchesDirect は combineLineStates が合成した状態が、
// 結合行を素直に計算した状態と一致することを検証する（正規化結果の再利用
// 最適化と、特徴量の和・最大による合成の両方を突く）。
func TestCombineLineStatesMatchesDirect(t *testing.T) {
	rnd := rand.New(rand.NewSource(20260727))
	mk := func() string {
		var sb strings.Builder
		for j := rnd.Intn(16); j > 0; j-- {
			sb.WriteString(gateSoundnessAlphabet[rnd.Intn(len(gateSoundnessAlphabet))])
		}
		return sb.String()
	}
	for i := 0; i < 50000; i++ {
		a, b := mk(), mk()
		first, second := newLineScanState(a), newLineScanState(b)
		got := combineLineStates(a+"\n"+b, &first, &second)
		want := newLineScanState(a + "\n" + b)
		if got.norm != want.norm {
			t.Fatalf("合成した正規化結果が不一致: a=%q b=%q\n  got =%q\n  want=%q", a, b, got.norm, want.norm)
		}
		if got.feats != want.feats {
			t.Fatalf("合成した特徴量が不一致: a=%q b=%q got=%+v want=%+v", a, b, got.feats, want.feats)
		}
	}
}

// TestGateForPattern は代表的なパターン形状に対する導出結果を固定する。
// 期待値は「そのパターンにマッチするどの文字列にも必ず含まれる量」の
// 下限であり、実際の下限より小さい（保守側の）値になることは許される。
// ここで検査しているのは、実用上効いてほしい形状で下限が 0 に潰れて
// いないこと。
func TestGateForPattern(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want patternGate
	}{
		{
			// マイナンバー等の固定長数字列。総数・連続桁とも桁数そのもの。
			name: "固定長の数字列",
			src:  `\d{12}`,
			want: patternGate{minDigits: 12, minDigitRun: 12},
		},
		{
			// 郵便番号形。ハイフンで連続桁は途切れるが総数は合算できる。
			name: "ハイフン区切りの数字列",
			src:  `\d{3}-\d{4}`,
			want: patternGate{minDigits: 7, minDigitRun: 4},
		},
		{
			// クレジットカード形。区切りが任意なので連続桁は 1 ブロック分だけ、
			// 総数は全ブロックの合計を保証できる。
			name: "任意区切りの繰り返し",
			src:  `(?:\d{4}[- ]?){2}\d{4}`,
			want: patternGate{minDigits: 12, minDigitRun: 4},
		},
		{
			// 選択はどの分岐でも成り立つ量＝各分岐の最小値。
			name: "選択は最小値を取る",
			src:  `(?:\d{3}|\d{5})`,
			want: patternGate{minDigits: 3, minDigitRun: 3},
		},
		{
			// 全要素が U+3000 以上の文字クラスは CJK を保証する。
			name: "CJK文字クラス",
			src:  `[一-龯]{2}`,
			want: patternGate{needsCJK: true},
		},
		{
			// CJK リテラルと数字の連接。両方の保証が立つ。
			name: "CJKリテラルと数字の連接",
			src:  `〒\d{3}-\d{4}`,
			want: patternGate{minDigits: 7, minDigitRun: 4, needsCJK: true},
		},
		{
			// 0 回でも成立しうる繰り返しは何も保証しない。
			name: "Starは保証なし",
			src:  `\d*`,
			want: patternGate{},
		},
		{
			name: "Questは保証なし",
			src:  `(?:\d{4})?`,
			want: patternGate{},
		},
		{
			// Plus は最低 1 回の出現を保証する。
			name: "Plusは1回分を保証",
			src:  `\d+`,
			want: patternGate{minDigits: 1, minDigitRun: 1},
		},
		{
			// キャプチャは中身の保証をそのまま引き継ぐ。境界ガード（dg()）で
			// 本体がグループに入る組み込みルールの形。
			name: "キャプチャと幅ゼロの表明",
			src:  `(?:^|\D)(\d{7})(?:\D|$)`,
			want: patternGate{minDigits: 7, minDigitRun: 7},
		},
		{
			// 任意文字は数字とも CJK とも限らないため保証なし。
			name: "任意文字は保証なし",
			src:  `.{5}`,
			want: patternGate{},
		},
		{
			// 解析不能な正規表現はゼロ値（ゲートなし＝常に評価）へフォールバック。
			name: "解析不能はゼロ値",
			src:  `[`,
			want: patternGate{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gateForPattern(tt.src); got != tt.want {
				t.Errorf("gateForPattern(%q) = %+v, want %+v", tt.src, got, tt.want)
			}
		})
	}
}

// TestGateSkipsRequiresAllConditions は skips の判定条件そのものを固定する
// （下限に 1 つでも届かなければスキップ、すべて満たせば評価する）。
func TestGateSkipsRequiresAllConditions(t *testing.T) {
	g := patternGate{minDigits: 7, minDigitRun: 4, needsCJK: true}
	tests := []struct {
		name  string
		gate  patternGate
		feats lineFeatures
		want  bool
	}{
		{"すべて満たす", g, lineFeatures{hasCJK: true, digits: 7, maxDigitRun: 4}, false},
		{"数字の総数が足りない", g, lineFeatures{hasCJK: true, digits: 6, maxDigitRun: 4}, true},
		{"連続桁が足りない", g, lineFeatures{hasCJK: true, digits: 9, maxDigitRun: 3}, true},
		{"CJKがない", g, lineFeatures{digits: 7, maxDigitRun: 4}, true},
		{"ゲートなし（ゼロ値）は常に評価", patternGate{}, lineFeatures{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.gate.skips(tt.feats); got != tt.want {
				t.Errorf("skips(%+v) = %v, want %v", tt.feats, got, tt.want)
			}
		})
	}
}

// TestClassifyLineInvalidUTF8IsCJK は classifyLine が不正な UTF-8 バイトを
// U+FFFD として CJK 扱いする（＝ゲートで走査を落とさない保守側に倒れる）
// ことを固定する。ルーン走査していた旧実装との挙動一致でもある。
func TestClassifyLineInvalidUTF8IsCJK(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want lineFeatures
	}{
		{"純ASCII", "abc def", lineFeatures{}},
		{"ASCIIの数字", "a12b345", lineFeatures{hasDigit: true, digits: 5, maxDigitRun: 3}},
		{"アットマーク", "a@b", lineFeatures{hasAt: true}},
		{"日本語", "電話番号", lineFeatures{hasCJK: true}},
		{"U+3000未満の非ASCII", "café", lineFeatures{}},
		{"不正UTF-8はCJK扱い", "a\xffb", lineFeatures{hasCJK: true}},
		{"孤立継続バイトもCJK扱い", "\x80", lineFeatures{hasCJK: true}},
		{"多バイト文字は数字の連なりを断つ", "1あ2", lineFeatures{hasDigit: true, hasCJK: true, digits: 2, maxDigitRun: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyLine(tt.in); got != tt.want {
				t.Errorf("classifyLine(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}
