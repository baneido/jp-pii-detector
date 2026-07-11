package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratePhoneFromCSV(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "area_codes_raw.csv")
	output := filepath.Join(dir, "area_codes.txt")

	csv := "area_code,prefecture\n" +
		"03,東京都\n" +
		"06,大阪府\n" +
		"011,北海道\n" +
		"011,北海道\n" + // 重複行は 1 件に丸める
		"052,愛知県\n"
	if err := os.WriteFile(input, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := generatePhone(input, output); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, code := range []string{"03", "06", "011", "052"} {
		if !containsLine(text, code) {
			t.Errorf("output missing area code %q:\n%s", code, text)
		}
	}
	// ヘッダ行（"area_code" 等）は市外局番の形式に一致しないため除外される。
	if containsLine(text, "area_code") {
		t.Error("header row should not be treated as an area code")
	}
	// 重複は 1 回だけ出現すること。
	if strings.Count(text, "\n011\n") != 1 {
		t.Errorf("duplicate area code 011 should appear exactly once, got text:\n%s", text)
	}
}

// 市外局番として妥当な形式（先頭 0・2〜5 桁数字）でない行はスキップし、
// 生成全体は中断しないこと。
func TestGeneratePhoneSkipsInvalidRows(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "area_codes_raw.csv")
	output := filepath.Join(dir, "area_codes.txt")

	csv := "03\n" +
		"1234\n" + // 先頭が 0 でない
		"0\n" + // 短すぎる
		"0123456\n" + // 長すぎる（6 桁）
		"0abc\n" + // 数字以外を含む
		"052\n"
	if err := os.WriteFile(input, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := generatePhone(input, output); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	if !containsLine(text, "03") || !containsLine(text, "052") {
		t.Errorf("valid rows should be kept:\n%s", text)
	}
	for _, bad := range []string{"1234", "0", "0123456", "0abc"} {
		if containsLine(text, bad) {
			t.Errorf("invalid row %q should have been skipped:\n%s", bad, text)
		}
	}
}

func TestGeneratePhoneErrorsOnEmptyInput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "empty.csv")
	output := filepath.Join(dir, "area_codes.txt")

	if err := os.WriteFile(input, []byte("area_code\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := generatePhone(input, output); err == nil {
		t.Fatal("expected error for input with no valid area codes, got nil")
	}
}

func containsLine(text, line string) bool {
	for _, l := range strings.Split(text, "\n") {
		if l == line {
			return true
		}
	}
	return false
}
