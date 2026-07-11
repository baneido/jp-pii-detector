package detect

import (
	"testing"
)

// このファイルのサンプル値は非公開評価コーパス不要で実行できる:
//   - "1234567" は口座番号ルールが 7 桁＋文脈だけを要求するダミー値
//     （detect_test.go の TestScanContentUsesSourceContext と同じ方針）。
//   - "100-0001"（千代田区千代田＝皇居）は日本郵便の実在集合に含まれる
//     広く知られた公開住所の郵便番号で、埋め込みビットセットでの検証に使える。
//   - "山田太郎" は埋め込み姓名辞書に含まれる一般的な氏名リテラル
//     （dict/names_test.go・detect_test.go の TestCrossLineNameLabelThenValue と同じ方針）。

func TestSplitCSVLineBasic(t *testing.T) {
	fields, terminated := splitCSVLine("a,bb,ccc", ',')
	if !terminated {
		t.Fatal("terminated = false, want true")
	}
	want := []string{"a", "bb", "ccc"}
	if len(fields) != len(want) {
		t.Fatalf("fields = %d 件, want %d", len(fields), len(want))
	}
	for i, f := range fields {
		if got := "a,bb,ccc"[f.start:f.end]; got != want[i] {
			t.Errorf("fields[%d] = %q, want %q", i, got, want[i])
		}
	}
}

func TestSplitCSVLineTab(t *testing.T) {
	line := "a\tbb\tccc"
	fields, terminated := splitCSVLine(line, '\t')
	if !terminated || len(fields) != 3 {
		t.Fatalf("fields = %v, terminated = %v", fields, terminated)
	}
	if line[fields[1].start:fields[1].end] != "bb" {
		t.Errorf("fields[1] = %q, want bb", line[fields[1].start:fields[1].end])
	}
}

// 引用符内のカンマはフィールド区切りとして扱わない（列ズレの回帰防止）。
func TestSplitCSVLineQuotedCommaDoesNotShiftColumns(t *testing.T) {
	line := `a,"b,c",d`
	fields, terminated := splitCSVLine(line, ',')
	if !terminated {
		t.Fatal("terminated = false, want true")
	}
	want := []string{"a", "b,c", "d"}
	if len(fields) != len(want) {
		t.Fatalf("fields = %d 件, want %d: %+v", len(fields), len(want), fields)
	}
	for i, f := range fields {
		if got := line[f.start:f.end]; got != want[i] {
			t.Errorf("fields[%d] = %q, want %q", i, got, want[i])
		}
	}
}

// 区切り文字の直後に半角空白を挟んだ引用フィールドも認識する。
func TestSplitCSVLineInitialSpaceBeforeQuoteDoesNotShiftColumns(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		delim byte
		want  []string
	}{
		{"CSV", `a,  "b,c", d`, ',', []string{"a", "b,c", " d"}},
		{"TSV", "a\t  \"b\tc\"\t d", '\t', []string{"a", "b\tc", " d"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields, terminated := splitCSVLine(tt.line, tt.delim)
			if !terminated {
				t.Fatal("terminated = false, want true")
			}
			if len(fields) != len(tt.want) {
				t.Fatalf("fields = %d 件, want %d: %+v", len(fields), len(tt.want), fields)
			}
			for i, f := range fields {
				if got := tt.line[f.start:f.end]; got != tt.want[i] {
					t.Errorf("fields[%d] = %q, want %q", i, got, tt.want[i])
				}
			}
		})
	}
}

// 引用符が続かない区切り文字直後の空白は、従来どおり値の一部として保持する。
func TestSplitCSVLinePreservesInitialSpaceInUnquotedField(t *testing.T) {
	line := "a,  b , c"
	fields, terminated := splitCSVLine(line, ',')
	if !terminated {
		t.Fatal("terminated = false, want true")
	}
	want := []string{"a", "  b ", " c"}
	for i, f := range fields {
		if got := line[f.start:f.end]; got != want[i] {
			t.Errorf("fields[%d] = %q, want %q", i, got, want[i])
		}
	}
}

// "" はエスケープされた引用符 1 個として扱い、フィールドを終端しない。
func TestSplitCSVLineEscapedQuoteDoesNotTerminateField(t *testing.T) {
	line := `a,"b""c",d`
	fields, terminated := splitCSVLine(line, ',')
	if !terminated || len(fields) != 3 {
		t.Fatalf("fields = %+v, terminated = %v", fields, terminated)
	}
	if got := line[fields[2].start:fields[2].end]; got != "d" {
		t.Errorf("fields[2] = %q, want d (エスケープされた引用符でフィールドがずれていない)", got)
	}
}

// フィールド内改行で行末までに閉じ引用符が見つからない場合は terminated=false。
func TestSplitCSVLineUnterminatedQuoteFallsBack(t *testing.T) {
	_, terminated := splitCSVLine(`a,"b`, ',')
	if terminated {
		t.Fatal("terminated = true, want false (unterminated quote)")
	}
}

// RFC 4180 で許されない引用符構文は、列を誤帰属させないため不成立にする。
func TestSplitCSVLineRejectsMalformedQuotes(t *testing.T) {
	for _, line := range []string{
		`a,"b"junk,c`, // 閉じ引用符の後に区切り文字以外が続く
		`a,b"c,d`,     // 非引用フィールド内に引用符が現れる
	} {
		t.Run(line, func(t *testing.T) {
			if _, terminated := splitCSVLine(line, ','); terminated {
				t.Fatalf("splitCSVLine(%q) terminated = true, want false", line)
			}
		})
	}
}

// 不正な引用符を含むレコード以降は列境界を信頼せず、後続行にも列文脈を
// 付与しない。malformed CSV による誤検出を安全側に倒す回帰テスト。
func TestCSVColumnContextStopsAfterMalformedQuotes(t *testing.T) {
	lines := []string{
		"備考,口座番号",
		`"社内"junk,1234567`,
		"社内,7654321",
	}
	contexts := csvLineContexts("data.csv", lines)
	if len(contexts) != len(lines) {
		t.Fatalf("contexts = %d 行, want %d", len(contexts), len(lines))
	}
	for i := 1; i < len(contexts); i++ {
		if len(contexts[i].Statements) != 0 {
			t.Errorf("line %d statements = %+v, want none", i+1, contexts[i].Statements)
		}
	}
}

func TestLooksLikeCSVHeader(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{"通常のヘッダ", "郵便番号,口座番号", true},
		{"列 1 個は非ヘッダ", "郵便番号", false},
		{"数値主体の列を含むと非ヘッダ", "郵便番号,1234567", false},
		{"空フィールドを含むと非ヘッダ", "郵便番号,", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields, terminated := splitCSVLine(tt.line, ',')
			if !terminated {
				t.Fatal("terminated = false")
			}
			if got := looksLikeCSVHeader(tt.line, fields); got != tt.want {
				t.Errorf("looksLikeCSVHeader(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}

// FN の中心的な回帰テスト: ヘッダの 2 行下以降のデータ行でも列文脈が届き、
// 郵便番号・口座番号が検出できること（隣接 ±1 行の source context だけでは
// 2 行目のデータ行しか救えない、という issue #63 の FN プローブの再現）。
func TestCSVColumnContextPromotesRowsBeyondAdjacentWindow(t *testing.T) {
	d := newDetector(t, "")
	content := "郵便番号,口座番号\n" +
		"100-0001,1234567\n" +
		"100-0001,1234567\n" +
		"100-0001,1234567\n"
	fs := d.ScanContent("data.csv", content)

	wantLines := map[int]bool{2: true, 3: true, 4: true}
	gotPostal := map[int]bool{}
	gotBank := map[int]bool{}
	for _, f := range fs {
		switch f.RuleID {
		case "jp-postal-code":
			if f.Match != "100-0001" {
				t.Errorf("postal match = %q, want 100-0001", f.Match)
			}
			gotPostal[f.Line] = true
		case "jp-bank-account":
			if f.Match != "1234567" {
				t.Errorf("bank match = %q, want 1234567", f.Match)
			}
			gotBank[f.Line] = true
		default:
			t.Errorf("unexpected rule %s at line %d", f.RuleID, f.Line)
		}
	}
	for line := range wantLines {
		if !gotPostal[line] {
			t.Errorf("jp-postal-code not found at line %d (rows beyond the header should still get column context)", line)
		}
		if !gotBank[line] {
			t.Errorf("jp-bank-account not found at line %d", line)
		}
	}
}

// TSV（タブ区切り）でも同じ列文脈の仕組みが働くこと。
func TestCSVColumnContextTSV(t *testing.T) {
	d := newDetector(t, "")
	content := "郵便番号\t口座番号\n100-0001\t1234567\n100-0001\t1234567\n"
	fs := d.ScanContent("data.tsv", content)
	if len(fs) != 4 {
		t.Fatalf("findings = %d 件 %+v, want 4 (postal+bank × 2 行)", len(fs), fs)
	}
}

// ヘッダなし CSV（1 行目がデータ行）は列文脈を一切付与しない（安全側 = 現状維持）。
func TestCSVColumnContextNoHeaderIsSafe(t *testing.T) {
	d := newDetector(t, "")
	content := "1234567,1234567\n1234567,1234567\n"
	fs := d.ScanContent("data.csv", content)
	assertRules(t, fs)
}

// 引用符内カンマを含むフィールドがあっても、以降の列がずれずに正しい列文脈を
// 引き継ぐこと（RFC 4180 の引用符処理の end-to-end 確認）。
func TestCSVColumnContextQuotedFieldDoesNotShiftColumns(t *testing.T) {
	d := newDetector(t, "")
	content := "備考,口座番号\n" + `"社内メモ, 至急",1234567` + "\n"
	fs := d.ScanContent("data.csv", content)
	assertRules(t, fs, "jp-bank-account")
	if fs[0].Match != "1234567" {
		t.Fatalf("match = %q, want 1234567", fs[0].Match)
	}
}

// 区切り文字直後に空白を挟んだ引用フィールド内の区切り文字でも列がずれず、
// ヘッダから離れた行の後続列へ文脈が届くことを CSV/TSV の双方で確認する。
func TestCSVColumnContextInitialSpaceBeforeQuotedFieldDoesNotShiftColumns(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		content string
	}{
		{
			name: "CSV",
			file: "data.csv",
			content: "郵便番号, 備考, 口座番号\n" +
				"100-0001, 至急, 1234567\n" +
				`100-0001, "社内メモ, 至急", 7654321` + "\n",
		},
		{
			name: "TSV",
			file: "data.tsv",
			content: "郵便番号\t 備考\t 口座番号\n" +
				"100-0001\t 至急\t 1234567\n" +
				"100-0001\t \"社内メモ\t至急\"\t 7654321\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newDetector(t, "")
			fs := d.ScanContent(tt.file, tt.content)
			for _, f := range fs {
				if f.RuleID == "jp-bank-account" && f.Line == 3 && f.Match == "7654321" {
					return
				}
			}
			t.Fatalf("line 3 の口座番号が検出されない: %+v", fs)
		})
	}
}

// 列名が偶然「金額・件数」等の負コンテキスト語を含む場合、その列は同じ行の
// 別列由来の肯定文脈語を部分一致で拾っても抑制されること
// （「電話対応件数」のような紛らわしい列名で FP が増える既知のリスクに対する
// 具体的な回帰テスト: 「口座件数」は「口座」を含むため肯定文脈語にも部分一致
// するが、「件数」が負コンテキスト語のため抑制する）。
func TestCSVColumnContextSuppressesMisleadingHeaderWord(t *testing.T) {
	d := newDetector(t, "")
	content := "口座件数,口座番号\n1234567,1234567\n"
	fs := d.ScanContent("data.csv", content)
	assertRules(t, fs, "jp-bank-account")
	if fs[0].Column == 1 {
		t.Fatalf("finding = %+v, want the 口座番号 column (2nd field), not 口座件数", fs[0])
	}
}

// .csv/.tsv 以外の拡張子は CSV 列コンテキストの影響を受けない（sourceExtensions
// に csv/tsv は追加していないため、通常のソースコード文パーサにも csv 専用
// パーサにも分岐しない）。ヘッダ直後の行（2 行目）は既存の隣接 ±1 行の
// source context（CSV 専用ではない、汎用の仕組み）で従来どおり拾えるが、
// このテストが確認したいのは「ヘッダから 2 行以上離れた行は .txt では
// 救われない」という CSV 固有機構の拡張子ゲーティングそのもの。
func TestCSVColumnContextDoesNotApplyToOtherExtensions(t *testing.T) {
	d := newDetector(t, "")
	content := "郵便番号,口座番号\n100-0001,1234567\n100-0001,1234567\n100-0001,1234567\n"
	fs := d.ScanContent("data.txt", content)
	for _, f := range fs {
		if f.Line >= 3 {
			t.Errorf("finding beyond the adjacent row should not occur on non-CSV files: %+v", f)
		}
	}
}

// diff 走査（ScanDiffHunk）では CSV 列コンテキストを使わない
// （sourceLineContextsForDiff は CSV を素通りする）。ヘッダに隣接する行は
// 既存の ±1 行 source context で従来どおり救えるが、ヘッダから 2 行以上
// 離れた追加行は救えないままであることを確認する。
func TestCSVColumnContextDoesNotApplyToDiffScan(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanDiffHunk("data.csv", []DiffLine{
		{Text: "郵便番号,口座番号", Added: false},
		{Text: "100-0001,1234567", Added: false}, // ヘッダから 1 行下（未変更）
		{Text: "100-0001,1234567", Added: true},  // ヘッダから 2 行下（追加行）
	})
	assertRules(t, fs)

	// 同じ内容をフルスキャンすれば（sourceLineContexts 経由で）検出できることの対比。
	full := d.ScanContent("data.csv", "郵便番号,口座番号\n100-0001,1234567\n100-0001,1234567\n")
	if len(full) == 0 {
		t.Fatal("full scan should detect the same rows via CSV column context")
	}
}

// --- Part C: 氏名列（高再現率限定） ---

func TestCSVNameColumnPromotesRowsBeyondAdjacentWindow(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	content := "氏名,郵便番号\n" +
		"山田太郎,100-0001\n" +
		"山田太郎,100-0001\n" +
		"山田太郎,100-0001\n"
	fs := d.ScanContent("data.csv", content)

	gotName := map[int]bool{}
	gotPostal := map[int]bool{}
	for _, f := range fs {
		switch f.RuleID {
		case "person-name-structured":
			if f.Match != "山田太郎" {
				t.Errorf("name match = %q, want 山田太郎", f.Match)
			}
			gotName[f.Line] = true
		case "jp-postal-code":
			gotPostal[f.Line] = true
		default:
			t.Errorf("unexpected rule %s at line %d", f.RuleID, f.Line)
		}
	}
	for _, line := range []int{2, 3, 4} {
		if !gotName[line] {
			t.Errorf("person-name-structured not found at line %d", line)
		}
		if !gotPostal[line] {
			t.Errorf("jp-postal-code not found at line %d", line)
		}
	}
}

// 氏名列より前に、区切り文字直後の空白を挟んだ引用フィールドがあっても、
// 引用符内の区切り文字で列がずれず氏名を検出できることを CSV/TSV 双方で確認する。
func TestCSVNameColumnInitialSpaceBeforeQuotedFieldDoesNotShiftColumns(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		content string
	}{
		{
			name: "CSV",
			file: "data.csv",
			content: "種別, 備考, 氏名\n" +
				"通常, 至急, 山田太郎\n" +
				`通常, "社内メモ, 至急", 山田太郎` + "\n",
		},
		{
			name: "TSV",
			file: "data.tsv",
			content: "種別\t 備考\t 氏名\n" +
				"通常\t 至急\t 山田太郎\n" +
				"通常\t \"社内メモ\t至急\"\t 山田太郎\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newDetector(t, highRecallTOML)
			fs := d.ScanContent(tt.file, tt.content)
			for _, f := range fs {
				if f.RuleID == "person-name-structured" && f.Line == 3 && f.Match == "山田太郎" {
					return
				}
			}
			t.Fatalf("line 3 の氏名が検出されない: %+v", fs)
		})
	}
}

// CSV 氏名列でも min_confidence を尊重し、Medium の構造化氏名を High 設定で
// 報告しない（scanCrossLineNames と同じ信頼度ゲート）。
func TestCSVNameColumnRespectsMinimumConfidence(t *testing.T) {
	d := newDetector(t, "min_confidence = \"high\"\n[rules]\nhigh_recall = true\n")
	fs := d.ScanContent("data.csv", "氏名,備考\n山田太郎,社内\n")
	assertRules(t, fs)
}

// 高再現率が既定 OFF のときは氏名列の構造化検出も走らない（既定挙動を変えない）。
func TestCSVNameColumnDisabledByDefault(t *testing.T) {
	d := newDetector(t, "")
	fs := d.ScanContent("data.csv", "氏名,郵便番号\n山田太郎,100-0001\n")
	assertRules(t, fs, "jp-postal-code")
}

// フリガナ（カタカナ）列は、#63 実装当初は姓名辞書が漢字ベースだったため対象外
// だったが、#58（カナ・ローマ字氏名対応）でカタカナ読みが姓名辞書に追加された
// ため、ValidCrossLineName がカタカナのフルネームも通し、高再現率モードで
// person-name-structured として検出されるようになった。
func TestCSVNameColumnFuriganaIsDetectedViaKatakanaDictionary(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	fs := d.ScanContent("data.csv", "フリガナ,郵便番号\nヤマダタロウ,100-0001\n")
	assertRules(t, fs, "person-name-structured", "jp-postal-code")
}

// ヘッダなし CSV では氏名列も検出しない（安全側）。
func TestCSVNameColumnNoHeaderIsSafe(t *testing.T) {
	d := newDetector(t, highRecallTOML)
	fs := d.ScanContent("data.csv", "山田太郎,鈴木花子\n山田太郎,鈴木花子\n")
	assertRules(t, fs)
}

// CSVNameHeaderRe / CSVNameValueRe 自体の単体テストは
// internal/rule/structured_test.go（TestCSVNameRegexes）にある。ここでは
// detect.ScanContent 経由の end-to-end 挙動のみを確認する。
