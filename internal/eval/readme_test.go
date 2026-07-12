package eval

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/privatecorpus"
)

const readmePath = "../../README.md"

// readmeRow は README の精度表の行ラベル（種別列）とルール ID の対応。
// 表に行を追加・改名したらここも更新する。
var readmeRow = map[string]string{
	"jp-my-number":            "マイナンバー（個人番号）",
	"credit-card":             "クレジットカード番号",
	"email-address":           "メールアドレス",
	"jp-phone-number":         "電話番号",
	"jp-postal-code":          "郵便番号",
	"jp-address":              "住所",
	"jp-drivers-license":      "運転免許証番号",
	"jp-passport":             "旅券（パスポート）番号",
	"jp-pension-number":       "基礎年金番号",
	"jp-residence-card":       "在留カード番号",
	"jp-bank-account":         "銀行口座番号",
	"jp-yucho-account":        "ゆうちょ銀行 記号番号",
	"jp-health-insurance":     "健康保険 保険者番号等",
	"jp-employment-insurance": "雇用保険被保険者番号",
	"jp-kaigo-insurance":      "介護保険被保険者番号",
	"jp-juminhyo-code":        "住民票コード",
	"jp-invoice-number":       "インボイス登録番号",
	"jp-birthdate":            "生年月日",
	"person-name":             "氏名",
}

var (
	// 表の各行のルール別バッジ。
	ruleBadgeRe = regexp.MustCompile(`!\[F1 [0-9.]+\]\(https://img\.shields\.io/badge/F1-[0-9.]+-[a-z]+\)`)
	// 先頭の総合バッジ（マイクロ平均 F1）。
	overallBadgeRe = regexp.MustCompile(`badge/PII検出_F1（評価データセット）-[0-9.]+-[a-z]+`)
)

func overallBadge(results []Result) string {
	text, color := Badge(Micro(results).F1)
	return fmt.Sprintf("badge/PII検出_F1（評価データセット）-%s-%s", text, color)
}

// TestReadmeBadges は README のバッジ（先頭の総合 F1 とルール別 F1）が
// 利用者の既定運用に対応するmediumプロファイルの実測値と一致することを検証する。
// -update 指定時は README のバッジを実測値で書き換えてから検証する。
func TestReadmeBadges(t *testing.T) {
	privatecorpus.Require(t)
	profiles, err := EvaluatePublishedProfiles()
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := FindProfile(profiles, "medium")
	if !ok {
		t.Fatal("medium profile not found")
	}
	results := profile.Stratified.Results
	data, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatal(err)
	}
	readme := string(data)

	if *update {
		readme = rewriteBadges(readme, results)
		if err := os.WriteFile(readmePath, []byte(readme), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("README.md のバッジを実測値で更新しました")
	}

	for _, r := range results {
		label, ok := readmeRow[r.RuleID]
		if !ok {
			t.Errorf("ルール %q の README 行ラベルが未登録（readmeRow に追加してください）", r.RuleID)
			continue
		}
		row := findRow(readme, label)
		if row == "" {
			t.Errorf("README の表に行 %q が見つからない", label)
			continue
		}
		if want := BadgeMarkdown(r.F1); !strings.Contains(row, want) {
			t.Errorf("README の %q 行のバッジが実測値と不一致: want %s（-update で更新できます）", label, want)
		}
	}
	if want := overallBadge(results); !strings.Contains(readme, want) {
		t.Errorf("README の総合バッジが実測のマイクロ平均と不一致: want %s（-update で更新できます）", want)
	}
}

// findRow は精度表から行ラベルに一致する行を返す。
func findRow(readme, label string) string {
	for line := range strings.SplitSeq(readme, "\n") {
		if strings.HasPrefix(line, "| "+label+" |") {
			return line
		}
	}
	return ""
}

// rewriteBadges は README のバッジを実測値で書き換える。
func rewriteBadges(readme string, results []Result) string {
	f1 := map[string]float64{}
	for _, r := range results {
		f1[r.RuleID] = r.F1
	}
	lines := strings.Split(readme, "\n")
	for i, line := range lines {
		for id, label := range readmeRow {
			if strings.HasPrefix(line, "| "+label+" |") {
				lines[i] = ruleBadgeRe.ReplaceAllString(line, BadgeMarkdown(f1[id]))
				break
			}
		}
	}
	out := strings.Join(lines, "\n")
	return overallBadgeRe.ReplaceAllString(out, overallBadge(results))
}
