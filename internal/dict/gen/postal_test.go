package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

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

	if err := generatePostal(input, bitsetPath); err != nil {
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

	if err := generatePostal(input, bitsetPath); err != nil {
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

	if err := generatePostal(input, bitsetPath); err != nil {
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
