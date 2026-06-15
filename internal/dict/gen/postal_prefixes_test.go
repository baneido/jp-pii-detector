package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratePostalPrefixesFromCSV(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "KEN_ALL.CSV")
	output := filepath.Join(dir, "postal_prefixes.txt")

	csv := "" +
		`"13101","100  ","1000001","ﾄｳｷｮｳﾄ","ﾁﾖﾀﾞｸ","ﾁﾖﾀﾞ","東京都","千代田区","千代田"` + "\n" +
		`"13102","104  ","1040061","ﾄｳｷｮｳﾄ","ﾁｭｳｵｳｸ","ｷﾞﾝｻﾞ","東京都","中央区","銀座"` + "\n" +
		`"13103","105  ","1000011","ﾄｳｷｮｳﾄ","ﾐﾅﾄｸ","ｼﾊﾞｺｳｴﾝ","東京都","港区","芝公園"` + "\n"
	if err := os.WriteFile(input, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := generatePostalPrefixes(input, output); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	want := "100\n104\n"
	if string(got) != want {
		t.Fatalf("generated prefixes = %q, want %q", string(got), want)
	}
}

func TestGeneratePostalPrefixesFromZip(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "ken_all.zip")
	output := filepath.Join(dir, "postal_prefixes.txt")

	if err := writeZip(input, map[string]string{
		"README.txt": "ignored",
		"KEN_ALL.CSV": "" +
			`"27127","530  ","5300001","ｵｵｻｶﾌ","ｵｵｻｶｼｷﾀｸ","ｳﾒﾀﾞ","大阪府","大阪市北区","梅田"` + "\n" +
			`"01101","060  ","0600001","ﾎｯｶｲﾄﾞｳ","ｻｯﾎﾟﾛｼﾁｭｳｵｳｸ","ｷﾀ1ｼﾞｮｳﾆｼ","北海道","札幌市中央区","北一条西"` + "\n",
	}); err != nil {
		t.Fatal(err)
	}

	if err := generatePostalPrefixes(input, output); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	want := "060\n530\n"
	if string(got) != want {
		t.Fatalf("generated prefixes = %q, want %q", string(got), want)
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
