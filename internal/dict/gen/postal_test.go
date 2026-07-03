package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/transform"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// bitSet はビットセット bs のインデックス n のビットが立っているかを返す（テスト用）。
func bitSet(bs []byte, n uint32) bool {
	idx := int(n >> 3)
	return idx < len(bs) && bs[idx]&(1<<(n&7)) != 0
}

func TestGeneratePostalFromCSV(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "KEN_ALL.CSV")
	bitsetPath := filepath.Join(dir, "postal_codes.bitset")

	csv := "" +
		`"13101","100  ","1000001","ﾄｳｷｮｳﾄ","ﾁﾖﾀﾞｸ","ﾁﾖﾀﾞ","東京都","千代田区","千代田"` + "\n" +
		`"13102","104  ","1040061","ﾄｳｷｮｳﾄ","ﾁｭｳｵｳｸ","ｷﾞﾝｻﾞ","東京都","中央区","銀座"` + "\n" +
		`"13103","105  ","1000011","ﾄｳｷｮｳﾄ","ﾐﾅﾄｸ","ｼﾊﾞｺｳｴﾝ","東京都","港区","芝公園"` + "\n"
	if err := os.WriteFile(input, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := generatePostal(input, "", bitsetPath); err != nil {
		t.Fatal(err)
	}

	bitset, err := os.ReadFile(bitsetPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(bitset) != dict.PostalBitsetSize {
		t.Fatalf("bitset size = %d, want %d", len(bitset), dict.PostalBitsetSize)
	}
	// 入力にある 7 桁はビットが立ち、ない 7 桁は立たない。
	for _, code := range []uint32{1000001, 1040061, 1000011} {
		if !bitSet(bitset, code) {
			t.Errorf("code %07d should be set", code)
		}
	}
	for _, code := range []uint32{1000002, 1040060, 9999999, 0} {
		if bitSet(bitset, code) {
			t.Errorf("code %07d should not be set", code)
		}
	}
}

func TestGeneratePostalFromZip(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "ken_all.zip")
	bitsetPath := filepath.Join(dir, "postal_codes.bitset")

	if err := writeZip(input, map[string]string{
		"README.txt": "ignored",
		"KEN_ALL.CSV": "" +
			`"27127","530  ","5300001","ｵｵｻｶﾌ","ｵｵｻｶｼｷﾀｸ","ｳﾒﾀﾞ","大阪府","大阪市北区","梅田"` + "\n" +
			`"01101","060  ","0600001","ﾎｯｶｲﾄﾞｳ","ｻｯﾎﾟﾛｼﾁｭｳｵｳｸ","ｷﾀ1ｼﾞｮｳﾆｼ","北海道","札幌市中央区","北一条西"` + "\n",
	}); err != nil {
		t.Fatal(err)
	}

	if err := generatePostal(input, "", bitsetPath); err != nil {
		t.Fatal(err)
	}

	bitset, err := os.ReadFile(bitsetPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []uint32{5300001, 600001} {
		if !bitSet(bitset, code) {
			t.Errorf("code %07d should be set", code)
		}
	}
	if bitSet(bitset, 5300002) {
		t.Error("code 5300002 should not be set")
	}
}

// 7 桁郵便番号を持たない行はスキップし、有効な行だけを取り込むこと（生成全体は中断しない）。
func TestGeneratePostalSkipsInvalidRows(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "KEN_ALL.CSV")
	bitsetPath := filepath.Join(dir, "postal_codes.bitset")

	csv := "" +
		`"13101","100  ","1000001","ﾄｳｷｮｳﾄ","ﾁﾖﾀﾞｸ","ﾁﾖﾀﾞ","東京都","千代田区","千代田"` + "\n" +
		`broken,row` + "\n" + // 列不足
		`"x","y","ABCDEFG","z"` + "\n" + // 7 桁数字でない
		`"13103","105  ","1000011","ﾄｳｷｮｳﾄ","ﾐﾅﾄｸ","ｼﾊﾞｺｳｴﾝ","東京都","港区","芝公園"` + "\n"
	if err := os.WriteFile(input, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := generatePostal(input, "", bitsetPath); err != nil {
		t.Fatal(err)
	}
	bitset, err := os.ReadFile(bitsetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bitSet(bitset, 1000001) || !bitSet(bitset, 1000011) {
		t.Error("有効行の 7 桁が取り込まれていない")
	}
}

// jigyosyoCSVSample は「事業所の個別郵便番号」データの実フォーマットを模した手作り
// レコード（13 列、8 列目（0 始まりで列 7）が郵便番号）。実データは Shift_JIS 配布。
func jigyosyoCSVSample() string {
	return "" +
		`"13101","ﾏﾙﾉｳﾁﾋﾞﾙ","丸の内ビル","東京都","千代田区","丸の内","一丁目1番","1008111","100","丸の内","0","0","0"` + "\n" +
		`"13104","ﾄﾁｮｳﾋﾞﾙ","都庁ビル","東京都","新宿区","西新宿","二丁目8番1号","1638001","160","新宿","0","0","0"` + "\n"
}

// toShiftJIS は UTF-8 文字列を Shift_JIS バイト列へエンコードする（テスト用）。
func toShiftJIS(t *testing.T, s string) []byte {
	t.Helper()
	b, _, err := transform.Bytes(japanese.ShiftJIS.NewEncoder(), []byte(s))
	if err != nil {
		t.Fatalf("shift_jis encode: %v", err)
	}
	return b
}

func TestGeneratePostalFromJigyosyo(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "JIGYOSYO.CSV")
	bitsetPath := filepath.Join(dir, "postal_codes.bitset")

	if err := os.WriteFile(input, toShiftJIS(t, jigyosyoCSVSample()), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := generatePostal("", input, bitsetPath); err != nil {
		t.Fatal(err)
	}

	bitset, err := os.ReadFile(bitsetPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(bitset) != dict.PostalBitsetSize {
		t.Fatalf("bitset size = %d, want %d", len(bitset), dict.PostalBitsetSize)
	}
	for _, code := range []uint32{1008111, 1638001} {
		if !bitSet(bitset, code) {
			t.Errorf("code %07d should be set", code)
		}
	}
	// 事業所名（8 列目以外）は数字化けや偶然の一致でも取り込まれないこと。
	if bitSet(bitset, 0) {
		t.Error("code 0000000 should not be set")
	}
}

func TestGeneratePostalFromJigyosyoZip(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "jigyosyo.zip")
	bitsetPath := filepath.Join(dir, "postal_codes.bitset")

	f, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("JIGYOSYO.CSV")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(toShiftJIS(t, jigyosyoCSVSample())); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if err := generatePostal("", input, bitsetPath); err != nil {
		t.Fatal(err)
	}
	bitset, err := os.ReadFile(bitsetPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []uint32{1008111, 1638001} {
		if !bitSet(bitset, code) {
			t.Errorf("code %07d should be set", code)
		}
	}
}

// ken_all 由来のコードと jigyosyo 由来のコードが同一ビットセットへマージされること
// （重複コードがあっても件数・ビットは 1 つに集約される）を確認する。
func TestGeneratePostalMergesKenAllAndJigyosyo(t *testing.T) {
	dir := t.TempDir()
	kenAllPath := filepath.Join(dir, "KEN_ALL.CSV")
	jigyosyoPath := filepath.Join(dir, "JIGYOSYO.CSV")
	bitsetPath := filepath.Join(dir, "postal_codes.bitset")

	kenAllCSV := "" +
		// 1000001 は jigyosyo 側にも同じ 7 桁が出現する重複ケースとして仕込む。
		`"13101","100  ","1000001","ﾄｳｷｮｳﾄ","ﾁﾖﾀﾞｸ","ﾁﾖﾀﾞ","東京都","千代田区","千代田"` + "\n"
	if err := os.WriteFile(kenAllPath, []byte(kenAllCSV), 0o644); err != nil {
		t.Fatal(err)
	}

	jigyosyoCSV := "" +
		`"13101","ﾏﾙﾉｳﾁﾋﾞﾙ","丸の内ビル","東京都","千代田区","丸の内","一丁目1番","1000001","100","丸の内","0","0","0"` + "\n" +
		`"13104","ﾄﾁｮｳﾋﾞﾙ","都庁ビル","東京都","新宿区","西新宿","二丁目8番1号","1638001","160","新宿","0","0","0"` + "\n"
	if err := os.WriteFile(jigyosyoPath, toShiftJIS(t, jigyosyoCSV), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := generatePostal(kenAllPath, jigyosyoPath, bitsetPath); err != nil {
		t.Fatal(err)
	}
	bitset, err := os.ReadFile(bitsetPath)
	if err != nil {
		t.Fatal(err)
	}
	// ken_all 由来（1000001、重複あり）と jigyosyo 固有（1638001）の両方が立つ。
	for _, code := range []uint32{1000001, 1638001} {
		if !bitSet(bitset, code) {
			t.Errorf("code %07d should be set", code)
		}
	}
}

// 列インデックスを取り違えると（ken_all 用の列 2 を jigyosyo データに使い回すなど）、
// 郵便番号列が非数字の事業所名列を指してしまい実質ゼロ件取り込みになる。この事故を
// readCSV の列引数で防げていることを回帰確認する。
func TestReadCSVColumnMismatchIsIgnored(t *testing.T) {
	codes := map[uint32]struct{}{}
	if err := readCSV("jigyosyo", strings.NewReader(jigyosyoCSVSample()), kenAllPostalColumn, codes); err != nil {
		t.Fatal(err)
	}
	if len(codes) != 0 {
		t.Errorf("列を取り違えた場合は何も取り込まれないはずが、%d 件取り込まれた: %v", len(codes), codes)
	}

	codes = map[uint32]struct{}{}
	if err := readCSV("jigyosyo", strings.NewReader(jigyosyoCSVSample()), jigyosyoPostalColumn, codes); err != nil {
		t.Fatal(err)
	}
	if len(codes) != 2 {
		t.Errorf("正しい列では 2 件取り込まれるはずが %d 件だった: %v", len(codes), codes)
	}
}

// TestGenerateMunicipalitiesFromCSV は record[7]（市区町村名）から municipalities.txt を
// 生成し、郡省略形・政令市の市単独形が併録され、ソート・重複排除されていることを確認する。
func TestGenerateMunicipalitiesFromCSV(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "KEN_ALL.CSV")
	out := filepath.Join(dir, "municipalities.txt")

	csv := "" +
		`"13101","100  ","1000001","ﾄｳｷｮｳﾄ","ﾁﾖﾀﾞｸ","ﾁﾖﾀﾞ","東京都","千代田区","千代田"` + "\n" +
		// 政令指定都市の区（市＋区連結）→ 市単独形も併録されるはず。
		`"01101","060  ","0600000","ﾎｯｶｲﾄﾞｳ","ｻｯﾎﾟﾛｼﾁｭｳｵｳｸ","ｲｶﾆ","北海道","札幌市中央区","以下"` + "\n" +
		`"01102","064  ","0640941","ﾎｯｶｲﾄﾞｳ","ｻｯﾎﾟﾛｼｷﾀｸ","ｱｻﾋｶﾞｵｶ","北海道","札幌市北区","旭ケ丘"` + "\n" +
		// 郡付きエントリ → 郡省略形も併録されるはず。
		`"01303","061  ","0610000","ﾎｯｶｲﾄﾞｳ","ｲｼｶﾘｸﾞﾝﾄｳﾍﾞﾂﾁｮｳ","ｲｶﾆ","北海道","石狩郡当別町","以下"` + "\n" +
		// 「郡」の字を含むが郡区分ではない市名 → 誤って省略しない（実データで踏んだ回帰）。
		`"40216","838  ","8388601","ﾌｸｵｶｹﾝ","ｵｺﾞｵﾘｼ","ｲｶﾆ","福岡県","小郡市","以下"` + "\n" +
		// ヶ/ケ 表記ゆれ → ケ に正規化される。
		`"12222","273  ","2730000","ﾁﾊﾞｹﾝ","ﾂﾙｶﾞｼ","ｲｶﾆ","千葉県","鶴ヶ島市","以下"` + "\n" +
		// 重複（東京都渋谷区が 2 レコード）→ 1 件に畳まれる。
		`"13113","150  ","1500000","ﾄｳｷｮｳﾄ","ｼﾌﾞﾔｸ","ｲｶﾆ","東京都","渋谷区","以下"` + "\n" +
		`"13113","150  ","1500001","ﾄｳｷｮｳﾄ","ｼﾌﾞﾔｸ","ｼﾌﾞﾔ","東京都","渋谷区","渋谷"` + "\n"
	if err := os.WriteFile(input, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := generateMunicipalities(input, out); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitNonCommentLines(string(data))
	got := map[string]bool{}
	for _, l := range lines {
		if got[l] {
			t.Errorf("municipalities.txt に重複エントリ: %q", l)
		}
		got[l] = true
	}

	for _, want := range []string{
		"千代田区", "札幌市中央区", "札幌市北区", "札幌市", // 政令市の区＋市単独形
		"石狩郡当別町", "当別町", // 郡付き正式表記＋省略形
		"小郡市",  // 郡の字を含むが郡区分ではない市名はそのまま（省略しない）
		"鶴ケ島市", // ヶ→ケ正規化
		"渋谷区",  // 重複排除
	} {
		if !got[want] {
			t.Errorf("municipalities.txt に %q がない: %v", want, lines)
		}
	}
	// 「郡」がついた市名の誤省略（小郡市 → 市）が起きていないこと。
	if got["市"] || got["上市"] || got["山市"] {
		t.Errorf("市名に含まれる「郡」の字を郡区分と誤認して省略した: %v", lines)
	}
	// 重複排除により渋谷区は 1 回だけ出現する。
	count := 0
	for _, l := range lines {
		if l == "渋谷区" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("渋谷区 の出現数 = %d, want 1", count)
	}
}

// TestAddMunicipalityVariants は addMunicipalityVariants 単体で、郡区分と紛らわしい
// 市名（小郡市・郡山市・郡上市・蒲郡市・大和郡山市。いずれも実データで確認済み）を
// 誤って郡省略しないことを確認する。
func TestAddMunicipalityVariants(t *testing.T) {
	tests := []struct {
		raw          string
		wantAbsent   []string
		wantContains []string
	}{
		{"小郡市", []string{"市"}, []string{"小郡市"}},
		{"郡山市", []string{"市", "山市"}, []string{"郡山市"}},
		{"郡上市", []string{"上市"}, []string{"郡上市"}},
		{"蒲郡市", []string{"市"}, []string{"蒲郡市"}},
		{"大和郡山市", []string{"山市"}, []string{"大和郡山市"}},
		{"石狩郡当別町", nil, []string{"石狩郡当別町", "当別町"}},
		{"南秋田郡大潟村", nil, []string{"南秋田郡大潟村", "大潟村"}},
		{"さいたま市中央区", nil, []string{"さいたま市中央区", "さいたま市"}},
		{"鶴ヶ島市", nil, []string{"鶴ケ島市"}},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			munis := map[string]struct{}{}
			addMunicipalityVariants(munis, tt.raw)
			for _, absent := range tt.wantAbsent {
				if _, ok := munis[absent]; ok {
					t.Errorf("addMunicipalityVariants(%q) unexpectedly produced %q: %v", tt.raw, absent, munis)
				}
			}
			for _, want := range tt.wantContains {
				if _, ok := munis[want]; !ok {
					t.Errorf("addMunicipalityVariants(%q) missing %q: %v", tt.raw, want, munis)
				}
			}
		})
	}
}

func splitNonCommentLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

func writeZip(path string, files map[string]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			_ = zw.Close()
			return err
		}
		if _, err := w.Write([]byte(body)); err != nil {
			_ = zw.Close()
			return err
		}
	}
	return zw.Close()
}
