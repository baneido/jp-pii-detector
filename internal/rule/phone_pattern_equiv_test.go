package rule

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// このファイルは jp-phone-number を「必須リテラルごとの複数 Rule エントリ」へ
// 分割した最適化（phoneRules）が、検出挙動を一切変えていないことを固定する。
//
// 検証は次の 4 本で、いずれも「分割前の参照実装 legacyPhonePatterns」と比較する。
//
//  1. TestPhoneRulesPreserveLegacyPatterns:
//     正規表現ソース・Base・RequireContext・RequireContextWindow・
//     NegativeContextMode・ValidateLine の挙動と、その並び順が分割前と同一。
//  2. TestPhoneRulesShareRuleMetadata:
//     分割した全エントリがパターン以外のメタデータ（文脈語・検証・種別分類）を共有。
//  3. TestPhoneScanEquivalence:
//     生成ケース・乱数ケースのコーパスで、internal/detect の走査プロトコル
//     （キャプチャ終端から次を探す反復）と FindAllStringSubmatchIndex の双方について
//     「リテラル事前判定を挟んだ分割後の走査」と「分割前の走査」の結果が完全一致し、
//     かつ PrefilterLiterals が必要条件になっている（スキップで取りこぼさない）。
//  4. TestBirthdatePrefilterLiteralsAreMandatory:
//     同じ考え方で jp-birthdate に入れたルール単位のリテラル事前判定を検証する。
//
// テストデータは実在しうる番号をソースへ書かないよう、すべて実行時に生成する。

// legacyPhonePatterns は分割前（単一 Rule エントリ時代）の jp-phone-number の
// パターン列を、定義順そのままに保持した参照実装。phoneRules 側を編集したときに
// 検出挙動の差分が出ていないかを比較するためだけに存在する（本番経路では未使用）。
func legacyPhonePatterns() []Pattern {
	return []Pattern{
		{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0[5-9]0-\d{4}-\d{4}`), Base: High, NegativeContextMode: NegativeContextAdjacentLabelOnly},
		{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0[5-9]0[ .]\d{4}[ .]\d{4}`), Base: Medium,
			ValidateLine: rejectSeparatedDigitGroup(".", 1)},
		{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0[5-9]0/\d{4}/\d{4}`), Base: Medium, RequireContext: true,
			ValidateLine: rejectSeparatedDigitGroup("/", 1)},
		{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0[5-9]0\d{8}`), Base: Medium, NegativeContextMode: NegativeContextAdjacentLabelOnly},
		{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{1,4}-\d{1,4}-\d{3,4}`), Base: Medium, NegativeContextMode: NegativeContextAdjacentLabelOnly},
		{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{1,4}\.\d{1,4}\.\d{3,4}`), Base: Medium,
			ValidateLine: rejectSeparatedDigitGroup(".", 1)},
		{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{1,4}\.\d{1,4}-\d{3,4}`), Base: Medium,
			ValidateLine: rejectSeparatedDigitGroup(".-", 1)},
		{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{1,4}-\d{1,4}\.\d{3,4}`), Base: Medium,
			ValidateLine: rejectSeparatedDigitGroup(".-", 1)},
		{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{1,4}\(\d{1,4}\)\d{4}`), Base: Medium},
		{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`\(0\d{1,4}\)\s?\d{1,4}-?\d{4}`), Base: Medium},
		{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{9}`), Base: Medium, RequireContext: true},
		{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`\+81[- ]?\d{1,4}[- ]?\d{1,4}[- ]?\d{3,4}`), Base: High, NegativeContextMode: NegativeContextAdjacentLabelOnly},
	}
}

// phoneEntries は Builtin() 中の jp-phone-number エントリ（分割後）を返す。
func phoneEntries(t testing.TB) []Rule {
	t.Helper()
	var out []Rule
	for _, r := range Builtin() {
		if r.ID == "jp-phone-number" {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		t.Fatal("jp-phone-number エントリが Builtin() に見つかりません")
	}
	return out
}

// flatPhonePatterns は分割後の全エントリのパターンを、エントリ順・パターン順に
// 平坦化して返す（検出時の評価順序と同じ並び）。
func flatPhonePatterns(t testing.TB) []Pattern {
	t.Helper()
	var out []Pattern
	for _, r := range phoneEntries(t) {
		out = append(out, r.Patterns...)
	}
	return out
}

func TestPhoneRulesPreserveLegacyPatterns(t *testing.T) {
	legacy := legacyPhonePatterns()
	got := flatPhonePatterns(t)
	if len(got) != len(legacy) {
		t.Fatalf("パターン数 = %d, want %d（分割でパターンを増減させてはいけない）", len(got), len(legacy))
	}
	// ValidateLine は関数値のため同一性を比較できない。区切り＋桁数の組合せを
	// 網羅したプローブ行で挙動を比較し、実質的な同一性を確認する。
	probes := validateLineProbes()
	for i := range legacy {
		l, g := legacy[i], got[i]
		if l.Re.String() != g.Re.String() {
			t.Errorf("パターン %d の正規表現 = %q, want %q（並び順も分割前と同一である必要がある）", i, g.Re.String(), l.Re.String())
			continue
		}
		if l.Base != g.Base {
			t.Errorf("パターン %d (%s) の Base = %v, want %v", i, g.Re.String(), g.Base, l.Base)
		}
		if l.RequireContext != g.RequireContext {
			t.Errorf("パターン %d (%s) の RequireContext = %v, want %v", i, g.Re.String(), g.RequireContext, l.RequireContext)
		}
		if l.RequireContextWindow != g.RequireContextWindow {
			t.Errorf("パターン %d (%s) の RequireContextWindow = %v, want %v", i, g.Re.String(), g.RequireContextWindow, l.RequireContextWindow)
		}
		if l.NegativeContextMode != g.NegativeContextMode {
			t.Errorf("パターン %d (%s) の NegativeContextMode = %v, want %v", i, g.Re.String(), g.NegativeContextMode, l.NegativeContextMode)
		}
		if (l.Validate == nil) != (g.Validate == nil) {
			t.Errorf("パターン %d (%s) の Validate の有無が分割前と異なる", i, g.Re.String())
		}
		if (l.ValidateLine == nil) != (g.ValidateLine == nil) {
			t.Errorf("パターン %d (%s) の ValidateLine の有無が分割前と異なる", i, g.Re.String())
			continue
		}
		if l.ValidateLine == nil {
			continue
		}
		for _, p := range probes {
			want := l.ValidateLine(p.line, p.start, p.end)
			gotOK := g.ValidateLine(p.line, p.start, p.end)
			if want != gotOK {
				t.Errorf("パターン %d (%s) の ValidateLine(%q,%d,%d) = %v, want %v",
					i, g.Re.String(), p.line, p.start, p.end, gotOK, want)
			}
		}
	}
}

// TestPhoneRulesShareRuleMetadata は分割した全エントリがパターン以外のメタデータを
// 共有していること（＝分割で文脈語・検証・種別分類の挙動が変わらないこと）を固定する。
func TestPhoneRulesShareRuleMetadata(t *testing.T) {
	entries := phoneEntries(t)
	first := entries[0]
	for i, r := range entries[1:] {
		switch {
		case r.Description != first.Description:
			t.Errorf("エントリ %d の Description がエントリ 0 と異なる", i+1)
		case r.Prefilter != first.Prefilter:
			t.Errorf("エントリ %d の Prefilter がエントリ 0 と異なる", i+1)
		case strings.Join(r.Context, "\x00") != strings.Join(first.Context, "\x00"):
			t.Errorf("エントリ %d の Context がエントリ 0 と異なる", i+1)
		case strings.Join(r.NegativeContext, "\x00") != strings.Join(first.NegativeContext, "\x00"):
			t.Errorf("エントリ %d の NegativeContext がエントリ 0 と異なる", i+1)
		case r.RequireContextWindow != first.RequireContextWindow:
			t.Errorf("エントリ %d の RequireContextWindow がエントリ 0 と異なる", i+1)
		case (r.Validate == nil) != (first.Validate == nil):
			t.Errorf("エントリ %d の Validate の有無がエントリ 0 と異なる", i+1)
		case (r.Kind == nil) != (first.Kind == nil):
			t.Errorf("エントリ %d の Kind の有無がエントリ 0 と異なる", i+1)
		}
	}
	// 分割の目的（リテラル事前判定）が実際に有効になっていること。
	gated := 0
	for _, r := range entries {
		if len(r.PrefilterLiterals) > 0 {
			gated++
		}
	}
	if gated == 0 {
		t.Error("PrefilterLiterals を持つエントリが 1 つも無い（分割の効果が失われている）")
	}
	// リテラルは小文字（英字を含まないこと）が前提。internal/detect の
	// containsAnyLiteral は haystack 側を小文字化して再照合するため、大文字を
	// 含むリテラルは永久に一致しない。
	for _, r := range entries {
		for _, lit := range r.PrefilterLiterals {
			if lit != strings.ToLower(lit) {
				t.Errorf("PrefilterLiterals %q に大文字が含まれる（小文字で定義すること）", lit)
			}
			if lit == "" {
				t.Error("空の PrefilterLiterals はすべての行に一致してしまう")
			}
		}
	}
}

// TestPhoneScanEquivalence は、リテラル事前判定つきの分割後の走査が分割前と
// 完全に同じマッチ列を返すことを確認する。検証は 1 本のループで 3 つの性質を同時に
// 固定する（コーパスは共通で、-race でも現実的な実行時間に収まる規模にしてある）。
//
//	(1) 事前判定でスキップされるエントリのパターンは、その行に 1 件もマッチしない
//	    （＝スキップしても取りこぼしが起きない。リテラルの必要条件性）。
//	(2) マッチしたときの値には、そのエントリの必須リテラルが必ず含まれる
//	    （(1) の逆方向。リテラル集合が値の構造から導けていることの確認）。
//	(3) 分割前の参照パターン（別インスタンス）と、internal/detect の反復プロトコル・
//	    FindAllStringSubmatchIndex の両方で同一のマッチ列を返す。
func TestPhoneScanEquivalence(t *testing.T) {
	legacy := legacyPhonePatterns()
	entries := phoneEntries(t)
	lines := phoneEquivalenceCorpus()

	// coverage[i] は参照パターン i がコーパス全体で何件マッチしたか。コーパスを
	// 編集したときに、どれかのパターンについて検証が空回りしていないかを見張る。
	coverage := make([]int, len(legacy))
	pi := 0
	for _, r := range entries {
		for _, p := range r.Patterns {
			ref := legacy[pi]
			for li, line := range lines {
				skip := len(r.PrefilterLiterals) > 0 && !containsAnyLiteralMirror(line, r.PrefilterLiterals)
				all := p.Re.FindAllStringSubmatchIndex(line, -1)
				iter := scanPatternIterative(p.Re, line)
				if skip && (len(all) > 0 || len(iter) > 0) {
					t.Fatalf("(1) 行 %q はエントリのリテラル %v をどれも含まないのにパターン %s がマッチした（事前判定で取りこぼす）",
						line, r.PrefilterLiterals, p.Re.String())
				}
				for _, m := range all {
					if len(r.PrefilterLiterals) > 0 && !containsAnyOf(line[m[2]:m[3]], r.PrefilterLiterals) {
						t.Fatalf("(2) パターン %s のマッチ値 %q が必須リテラル %v をどれも含まない",
							p.Re.String(), line[m[2]:m[3]], r.PrefilterLiterals)
					}
				}
				// (3) の参照インスタンスとの突き合わせは 4 行に 1 行で行う。正規表現
				// ソースの同一性は TestPhoneRulesPreserveLegacyPatterns が全パターンに
				// ついて完全比較しており（同一ソース ⇒ 同一挙動）、ここは並び順の取り違え
				// 等を実挙動でも捕まえる二重確認のため。全行で回すと -race の実行時間が
				// 倍増するので間引く。
				if li%4 == 0 {
					if !equalMatches(all, ref.Re.FindAllStringSubmatchIndex(line, -1)) {
						t.Fatalf("(3) 行 %q・パターン %s: FindAllStringSubmatchIndex の結果が分割前と異なる", line, p.Re.String())
					}
					if !equalMatches(iter, scanPatternIterative(ref.Re, line)) {
						t.Fatalf("(3) 行 %q・パターン %s: 反復走査の結果が分割前と異なる", line, p.Re.String())
					}
				}
				coverage[pi] += len(all)
			}
			pi++
		}
	}
	for i, n := range coverage {
		if n < 50 {
			t.Errorf("パターン %d (%s) のマッチが %d 件しかない（コーパスがこの形式を十分に生成していない）",
				i, legacy[i].Re.String(), n)
		}
	}
	t.Logf("コーパス %d 行 × %d パターンで走査結果一致（パターン別マッチ数 %v）", len(lines), len(legacy), coverage)
}

// TestBirthdatePrefilterLiteralsAreMandatory は jp-birthdate の PrefilterLiterals が
// 全パターンの必要条件（マッチ文字列にラベル語が必ず含まれる）であることを、ラベル
// 表記ゆれ × 値の表記ゆれの網羅生成で確認する。電話番号側と同じ理由（ラベルを含まない
// 行の正規表現走査を省く）でリテラル事前判定を入れているため、必要条件が崩れると
// 静かに偽陰性が出る。
func TestBirthdatePrefilterLiteralsAreMandatory(t *testing.T) {
	var target *Rule
	for _, r := range Builtin() {
		if r.ID == "jp-birthdate" {
			target = &r
			break
		}
	}
	if target == nil {
		t.Fatal("jp-birthdate ルールが Builtin() に見つかりません")
	}
	if len(target.PrefilterLiterals) == 0 {
		t.Fatal("jp-birthdate の PrefilterLiterals が空（事前判定の効果が失われている）")
	}

	labels := []string{
		"生年月日", "誕生日", "birth date", "birthdate", "birthday", "BIRTHDAY",
		"date_of_birth", "date of birth", "dob", "DOB", "Birth Date",
	}
	seps := []string{":", "：", " = ", "", " ", "(西暦):", "（西暦） : "}
	dateSeps := []string{"-", "/", ".", "年"}
	eras := []string{"1985", "昭和60", "S60", "平成元", "令和3", "R3"}
	var lines []string
	for _, l := range labels {
		for _, s := range seps {
			for _, e := range eras {
				for _, ds := range dateSeps {
					mid, tail := ds, ds
					if ds == "年" {
						mid, tail = "年", "月"
					}
					lines = append(lines, "  "+l+s+e+mid+"1"+tail+"2", l+s+e+mid+"12"+tail+"31日")
				}
				lines = append(lines, l+s+"19850102", "x "+l+s+"20001231 y")
			}
		}
	}
	// 後置ラベル形（値→「生まれ」）と、ラベルを持たない日付だけの行。
	for _, e := range eras {
		lines = append(lines, e+"年1月2日生まれ", "("+e+"/1/2)生まれ", e+"年1月2日", "1985-01-02", "20000101")
	}

	checked := 0
	for _, p := range target.Patterns {
		for _, line := range lines {
			for _, m := range p.Re.FindAllStringSubmatchIndex(line, -1) {
				if !containsAnyLiteralMirror(line[m[0]:m[1]], target.PrefilterLiterals) {
					t.Fatalf("パターン %s のマッチ %q が必須リテラル %v をどれも含まない",
						p.Re.String(), line[m[0]:m[1]], target.PrefilterLiterals)
				}
				checked++
			}
		}
	}
	if checked < 100 {
		t.Fatalf("検証したマッチ数 = %d（生成ケースが生年月日形をほとんど含んでいない）", checked)
	}
	// ラベルを含まない行では 1 件もマッチしないこと（事前判定でスキップしても
	// 結果が変わらないことの裏づけ）。
	for _, line := range lines {
		if containsAnyLiteralMirror(line, target.PrefilterLiterals) {
			continue
		}
		for _, p := range target.Patterns {
			if loc := p.Re.FindStringIndex(line); loc != nil {
				t.Fatalf("リテラルを含まない行 %q がパターン %s にマッチした（事前判定で取りこぼす）",
					line, p.Re.String())
			}
		}
	}
	t.Logf("必須リテラルを %d 件のマッチで確認（生成 %d 行）", checked, len(lines))
}

// scanPatternIterative は internal/detect の走査プロトコルを再現する。
// FindAll ではなく「キャプチャグループ 1 の終端から次のマッチを探す」反復で、
// 区切り 1 文字だけを挟んで隣接する値も取りこぼさない（detect.go の同名処理と
// 同じ理由）。分割はこの反復の途中経過にも影響しないことを確認するために使う。
func scanPatternIterative(re *regexp.Regexp, line string) [][]int {
	var out [][]int
	for pos := 0; pos < len(line); {
		m := re.FindStringSubmatchIndex(line[pos:])
		if m == nil {
			break
		}
		abs := make([]int, len(m))
		for i, v := range m {
			if v < 0 {
				abs[i] = v
				continue
			}
			abs[i] = v + pos
		}
		out = append(out, abs)
		next := abs[1]
		if len(abs) >= 4 && abs[2] >= 0 {
			next = abs[3]
		}
		if next <= pos {
			next = pos + 1
		}
		pos = next
	}
	return out
}

func equalMatches(a, b [][]int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

func containsAnyOf(s string, literals []string) bool {
	for _, lit := range literals {
		if strings.Contains(s, lit) {
			return true
		}
	}
	return false
}

// containsAnyLiteralMirror は internal/detect の containsAnyLiteral（Rule.
// PrefilterLiterals の判定）と同じ意味の照合。detect 側は非公開関数のため、
// 等価性テストではここに写しを置く（電話番号のリテラルは英字を含まないため、
// 大小無視の再照合は結果に影響しない）。
func containsAnyLiteralMirror(haystack string, literals []string) bool {
	if containsAnyOf(haystack, literals) {
		return true
	}
	return containsAnyOf(strings.ToLower(haystack), literals)
}

type validateLineProbe struct {
	line       string
	start, end int
}

// validateLineProbes は ValidateLine（rejectSeparatedDigitGroup）の挙動比較用に、
// 「値の前後に区切り＋各桁数の数字グループが隣接する」形を網羅したプローブを作る。
func validateLineProbes() []validateLineProbe {
	value := digitRun(1, 3) + "-" + digitRun(2, 4) + "-" + digitRun(3, 4)
	seps := []string{"", "-", ".", "/", " ", ",", ":"}
	widths := []int{0, 1, 2, 3, 4, 6}
	var probes []validateLineProbe
	for _, before := range seps {
		for _, wb := range widths {
			for _, after := range seps {
				for _, wa := range widths {
					prefix := ""
					if before != "" && wb > 0 {
						prefix = digitRun(wb+7, wb) + before
					}
					suffix := ""
					if after != "" && wa > 0 {
						suffix = after + digitRun(wa+13, wa)
					}
					line := prefix + value + suffix
					probes = append(probes, validateLineProbe{line: line, start: len(prefix), end: len(prefix) + len(value)})
				}
			}
		}
	}
	return probes
}

// digitRun は決定的な n 桁の数字列を返す（ソースへ実在しうる番号を書かないため、
// テストデータはすべてここから生成する）。
func digitRun(seed, n int) string {
	var b strings.Builder
	x := uint32(seed*2654435761 + 1)
	for i := 0; i < n; i++ {
		x = x*1664525 + 1013904223
		b.WriteByte(byte('0' + (x>>16)%10))
	}
	return b.String()
}

// phoneEquivalenceCorpus は等価性検証用の行コーパスを生成する。
//
//	(a) 電話番号らしい値の網羅生成（携帯・IP・固定・括弧市外局番・国際表記 × 桁数の
//	    組合せ × 区切り -/./空白//・なし・混在）を、行頭・行末・各種境界文字・
//	    ラベル付きなどの文脈へ埋め込んだもの
//	(b) 数字を含むがマッチしない行（コード・バージョン文字列・UUID・金額など、
//	    internal/detect の回帰テストが扱う形）
//	(c) 乱数生成ケース（シード固定）
func phoneEquivalenceCorpus() []string {
	var values []string
	seed := 0
	next := func(n int) string {
		seed++
		return digitRun(seed, n)
	}

	seps := []string{"", "-", ".", " ", "/"}
	// 携帯・IP 電話（0X0 + 4 + 4）を全区切り組合せで。
	for _, head := range []string{"050", "060", "070", "080", "090", "020", "0120"} {
		for _, s1 := range seps {
			for _, s2 := range seps {
				values = append(values, head+s1+next(4)+s2+next(4))
			}
		}
	}
	// 固定電話（0 + 市外局番 1〜4 桁 + 市内 1〜4 桁 + 加入者 3〜4 桁）。
	for area := 1; area <= 4; area++ {
		for mid := 1; mid <= 4; mid++ {
			for last := 3; last <= 4; last++ {
				for _, s1 := range seps {
					for _, s2 := range seps {
						values = append(values, "0"+next(area)+s1+next(mid)+s2+next(last))
					}
				}
			}
		}
	}
	// 括弧市外局番の 2 形式（0AA(BBBB)CCCC / (0AA) BBBB-CCCC）。
	for area := 1; area <= 4; area++ {
		for mid := 1; mid <= 4; mid++ {
			values = append(values, "0"+next(area)+"("+next(mid)+")"+next(4))
			for _, gap := range []string{"", " "} {
				for _, dash := range []string{"", "-"} {
					values = append(values, "("+"0"+next(area)+")"+gap+next(mid)+dash+next(4))
				}
			}
		}
	}
	// 区切りなし（9〜12 桁）と、桁あふれ・全桁同一のダミー形。
	for n := 9; n <= 12; n++ {
		values = append(values, "0"+next(n))
		values = append(values, "090"+next(n))
		values = append(values, strings.Repeat("0", n+1))
	}
	// 国際表記 +81（区切り 3 箇所 × なし/ハイフン/空白）。
	for _, s1 := range []string{"", "-", " "} {
		for _, s2 := range []string{"", "-", " "} {
			for _, s3 := range []string{"", "-", " "} {
				for mid := 1; mid <= 4; mid++ {
					for last := 3; last <= 4; last++ {
						values = append(values, "+81"+s1+next(2)+s2+next(mid)+s3+next(last))
					}
				}
			}
		}
	}
	// 各パターンの標準形を桁の異なる 24 組ずつ（区切りなし携帯・スラッシュ区切りの
	// ように上の組合せ生成では出現数が少ない形式でも、パターン別のマッチ数が
	// TestPhoneScanEquivalence の下限を安定して超えるようにする）。
	for rep := 0; rep < 24; rep++ {
		head := []string{"050", "060", "070", "080", "090"}[rep%5]
		values = append(values,
			head+"-"+next(4)+"-"+next(4),
			head+" "+next(4)+"."+next(4),
			head+"/"+next(4)+"/"+next(4),
			head+next(8),
			"0"+next(1)+"-"+next(4)+"-"+next(4),
			"0"+next(2)+"."+next(4)+"."+next(3),
			"0"+next(2)+"."+next(4)+"-"+next(3),
			"0"+next(2)+"-"+next(4)+"."+next(3),
			"0"+next(2)+"("+next(4)+")"+next(4),
			"(0"+next(2)+") "+next(4)+"-"+next(4),
			"0"+next(9),
			"+81-"+next(2)+"-"+next(4)+"-"+next(4),
		)
	}

	// 値を埋め込む文脈（行頭・行末・境界文字・ラベル・隣接数字・長いトークン内部）。
	prefixes := []string{
		"", " ", "\t", ":", "=", ",", "\"", "'", "(", "[", "/", "-", "_", "x", "A", "9", "0",
		"tel: ", "TEL=", "phone=", "電話番号：", "連絡先 ", "金額 ", "ver", "id-", "sku:",
	}
	suffixes := []string{
		"", " ", "\t", ",", "\"", ")", "]", "/", "-", "_", "x", "A", "9", "0", ".",
		" 円", "件", " (自宅)", "\n", ";",
	}
	lines := make([]string, 0, len(values)*3+4096)
	for i, v := range values {
		// 全値 × 少数の代表文脈（規模を抑える）。境界文字・ラベルの網羅は
		// 下の代表値 × 全文脈組合せが担う。
		lines = append(lines,
			v,
			prefixes[i%len(prefixes)]+v+suffixes[i%len(suffixes)],
			"tel: "+v+", fax: "+v,
		)
	}
	// 代表値については文脈を全組合せで（境界ガードの扱いを網羅する）。
	for _, v := range []string{
		"090" + digitRun(101, 4) + "-" + digitRun(102, 4),
		"090-" + digitRun(103, 4) + "-" + digitRun(104, 4),
		"03-" + digitRun(105, 4) + "-" + digitRun(106, 4),
		"03." + digitRun(107, 4) + "." + digitRun(108, 4),
		"03." + digitRun(109, 4) + "-" + digitRun(110, 4),
		"03-" + digitRun(111, 4) + "." + digitRun(112, 4),
		"0" + digitRun(113, 9),
		"(" + "03" + ")" + " " + digitRun(114, 4) + "-" + digitRun(115, 4),
		"03(" + digitRun(116, 4) + ")" + digitRun(117, 4),
		"+81-90-" + digitRun(118, 4) + "-" + digitRun(119, 4),
	} {
		for _, p := range prefixes[:16] {
			for _, s := range suffixes[:13] {
				lines = append(lines, p+v+s)
			}
		}
	}

	// (b) 数字を含むがマッチしない行（コード・型番・UUID・金額・日付など）。
	lines = append(lines,
		"const maxRetries = 3; timeout := 250 * time.Millisecond // retry budget v1.2.3 build 4567",
		"if err := retry(ctx, 5, 100*time.Millisecond); err != nil { return err }",
		"version = \"1.2.34\" // released 2026-07-25",
		"uuid = \"3f2504e0-4f89-11d3-9a0c-0305e82c3301\"",
		"total = 1234567 円 (税込 1358024 円)",
		"seq_id: 100200300400 count: 12345",
		"port := 8080 + offset*100",
		"hash = 0123456789abcdef0123456789abcdef",
		"path = /api/v2/items/1234567890/detail",
		"date = 2026/07/25 10:20:30.400",
		"matrix[0][12] = 3.14159; matrix[1][13] = 2.71828",
		"phone_pattern = `0\\d{1,4}-\\d{1,4}-\\d{3,4}`",
	)

	// (c) 乱数ケース（シード固定）。電話番号らしい文字だけを含む短い行を作る。
	// 件数は -race での実行時間（regexp が約 20 倍遅くなる）を見て抑えている。
	rng := rand.New(rand.NewSource(20260725))
	alphabet := []byte("0123456789-. /()+aZ:,\"")
	for i := 0; i < 2000; i++ {
		n := 4 + rng.Intn(28)
		var b strings.Builder
		for j := 0; j < n; j++ {
			b.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		lines = append(lines, b.String())
	}
	// 乱数の「数字寄り」ケース（マッチ密度を上げるため区切りを混ぜた桁列）。
	for i := 0; i < 1000; i++ {
		parts := make([]string, 0, 4)
		for j := 0; j <= rng.Intn(3)+1; j++ {
			parts = append(parts, digitRun(rng.Int(), 1+rng.Intn(5)))
		}
		sep := []string{"-", ".", " ", "/", "", "(", ")"}[rng.Intn(7)]
		lines = append(lines, fmt.Sprintf("%s%s", "0", strings.Join(parts, sep)))
	}
	return lines
}

// BenchmarkPhonePatternGate は「リテラル事前判定を挟んだ分割後の走査」と
// 「分割前の全パターン走査」のコスト差を、数字を含む典型的なコード行で測る。
// internal/detect 側のホットパス（BenchmarkScanLineASCIIDigitsNoMatch）で観測した
// 改善が、電話番号ルール由来であることを内部でも追えるようにするためのもの。
func BenchmarkPhonePatternGate(b *testing.B) {
	line := `const maxRetries = 3; timeout := 250 * time.Millisecond // retry budget v1.2.3 build 4567`
	legacy := legacyPhonePatterns()
	entries := phoneEntries(b)

	b.Run("legacy", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for _, p := range legacy {
				p.Re.FindStringSubmatchIndex(line)
			}
		}
	})
	b.Run("split", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for _, r := range entries {
				if len(r.PrefilterLiterals) > 0 && !containsAnyLiteralMirror(line, r.PrefilterLiterals) {
					continue
				}
				for _, p := range r.Patterns {
					p.Re.FindStringSubmatchIndex(line)
				}
			}
		}
	})
}
