package eval

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/baneido/jp-pii-detector/internal/privatecorpus"
)

const (
	readmePath   = "../../README.md"
	readmeENPath = "../../README.en.md"
)

// readmeRow は日本語 README の精度表の行ラベル（種別列）とルール ID の対応。
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
	// 表の各行のルール別バッジ。ラベルは URL 中も代替テキスト中も `F1` の
	// 固定文字列で翻訳の余地がないため、バッジ全体をまとめて置換する。
	ruleBadgeRe = regexp.MustCompile(`!\[F1 [0-9.]+\]\(https://img\.shields\.io/badge/F1-[0-9.]+-[a-z]+\)`)

	// 先頭の総合バッジ（マイクロ平均 F1）。
	//
	// 対応付けの方式: Markdown の代替テキスト `![PII detection F1](` をアンカーにし、
	// shields.io URL の末尾 2 セグメント（値-色）だけを部分一致グループ 1 で捕捉する。
	// 選定理由:
	//   - バッジ URL に埋め込まれたラベルは翻訳されている（日本語版
	//     `PII検出_F1（評価データセット）` / 英語版 `PII%20detection%20F1%20(eval%20dataset)`）
	//     ため、ラベル文字列でルールを引く方式は英語版で対応が取れない。
	//   - 一方 shields.io の URL は `badge/<ラベル>-<値>-<色>` という位置構造が言語に
	//     依存しない。グループ 1 の外（ラベルを含む前半）は書き換えないので、
	//     どちらの言語のラベルもそのまま保持される。
	//   - 代替テキストは両 README とも英語表記で共通なので、行番号や出現順に依存せず
	//     総合バッジだけを特定できる（ルール別バッジは代替テキストが `F1 x.xx` なので
	//     この正規表現には一致しない）。
	overallBadgeRe = regexp.MustCompile(`!\[PII detection F1\]\(https://img\.shields\.io/badge/.+-([0-9.]+-[a-z]+)\)`)

	// 英語版 README の Key features にある、バッジではない素の総合 F1 表記
	// （`**F1 0.99** under the default medium profile ...`）。数値だけをグループ 1 で
	// 捕捉し、前後の英文はそのまま残す。日本語版に同種の表記はない。
	plainF1Re = regexp.MustCompile(`\*\*F1 ([0-9.]+)\*\*`)
)

// readmeSpec は精度表記の同期対象となる README 1 ファイル分の定義。
// 日本語版と英語版では表の列構成も文面も異なるため、「そのファイルのどこを
// 見る/書き換えるか」をここで宣言し、検証と -update の双方が同じ定義を使う。
//
// 片方のファイルにしか存在しない表記の扱い: 存在する側のファイルだけを検証・更新の
// 対象とし、無い側ではその項目を単に対象外にする（欠落を理由に失敗させない）。
//   - ルール別 F1 バッジ: 日本語版のみ。英語版の Supported PII 表は
//     Type / How it is detected の 2 列でルール別 F1 列を持たないため ruleRows は nil。
//     英語版に F1 列を追加したら ruleRows を設定すれば同じ検証が効く。
//   - 本文中の素の総合 F1 表記: 英語版のみ（plainF1Re）。
//
// ただし「宣言したのに見つからない」は失敗させる（文面の書き換えでゲートが
// 素通りするのを防ぐため、各パターンはちょうど 1 件一致することを要求する）。
type readmeSpec struct {
	path      string
	ruleRows  map[string]string // nil ならルール別バッジ列を持たない
	plainF1Re *regexp.Regexp    // nil なら本文中の素の総合 F1 表記を持たない
}

func readmeSpecs() []readmeSpec {
	return []readmeSpec{
		{path: readmePath, ruleRows: readmeRow},
		{path: readmeENPath, plainF1Re: plainF1Re},
	}
}

// overallBadgeValue は総合バッジ URL の `<値>-<色>` 部分を返す。
func overallBadgeValue(results []Result) string {
	text, color := Badge(Micro(results).F1)
	return fmt.Sprintf("%s-%s", text, color)
}

// TestReadmeBadges は README（日本語版・英語版）の精度表記が、利用者の既定運用に
// 対応する medium プロファイルの実測値と一致することを検証する。
// -update 指定時は両ファイルの表記を実測値で書き換えてから検証する。
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

	for _, spec := range readmeSpecs() {
		data, err := os.ReadFile(spec.path)
		if err != nil {
			t.Fatal(err)
		}
		readme := string(data)

		if *update {
			readme = rewriteBadges(readme, spec, results)
			if err := os.WriteFile(spec.path, []byte(readme), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Logf("%s の精度表記を実測値で更新しました", spec.path)
		}
		checkReadme(t, spec, readme, results)
	}
}

// checkReadme は 1 ファイル分の精度表記を実測値と突き合わせる。
func checkReadme(t *testing.T, spec readmeSpec, readme string, results []Result) {
	t.Helper()

	// ルール別バッジ列を持つファイル（日本語版）のみ、行ごとのバッジを検証する。
	for _, r := range results {
		if spec.ruleRows == nil {
			break
		}
		label, ok := spec.ruleRows[r.RuleID]
		if !ok {
			t.Errorf("%s: ルール %q の行ラベルが未登録（readmeRow に追加してください）", spec.path, r.RuleID)
			continue
		}
		row := findRow(readme, label)
		if row == "" {
			t.Errorf("%s: 精度表に行 %q が見つからない", spec.path, label)
			continue
		}
		if want := BadgeMarkdown(r.F1); !strings.Contains(row, want) {
			t.Errorf("%s: %q 行のバッジが実測値と不一致: want %s（-update で更新できます）",
				spec.path, label, want)
		}
	}

	got, err := group1(readme, overallBadgeRe)
	if err != nil {
		t.Errorf("%s: 総合バッジを特定できない: %v", spec.path, err)
	} else if want := overallBadgeValue(results); got != want {
		t.Errorf("%s: 総合バッジが実測のマイクロ平均と不一致: got %s, want %s（-update で更新できます）",
			spec.path, got, want)
	}

	if spec.plainF1Re == nil {
		return
	}
	got, err = group1(readme, spec.plainF1Re)
	if err != nil {
		t.Errorf("%s: 本文中の総合 F1 表記を特定できない: %v", spec.path, err)
		return
	}
	if want, _ := Badge(Micro(results).F1); got != want {
		t.Errorf("%s: 本文中の総合 F1 表記が実測のマイクロ平均と不一致: got %s, want %s（-update で更新できます）",
			spec.path, got, want)
	}
}

// group1 は re がちょうど 1 件一致することを確認し、その部分一致グループ 1 を返す。
// 0 件（文面変更でアンカーが外れた）や複数件（意図しない箇所への一致）は
// 黙って素通りさせず、エラーとして扱う。
func group1(s string, re *regexp.Regexp) (string, error) {
	m := re.FindAllStringSubmatch(s, -1)
	if len(m) != 1 {
		return "", fmt.Errorf("%q への一致が %d 件（1 件であるべき）", re, len(m))
	}
	return m[0][1], nil
}

// replaceGroup1 は re の各一致について、部分一致グループ 1 の範囲だけを repl に
// 置き換える。グループ外（バッジ URL のラベルや前後の文面）は変更しないので、
// 英訳されたラベルがそのまま保持される。
func replaceGroup1(s string, re *regexp.Regexp, repl string) string {
	var b strings.Builder
	last := 0
	for _, loc := range re.FindAllStringSubmatchIndex(s, -1) {
		// loc[2]/loc[3] がグループ 1 の開始・終了位置（不一致なら -1）。
		if len(loc) < 4 || loc[2] < 0 {
			continue
		}
		b.WriteString(s[last:loc[2]])
		b.WriteString(repl)
		last = loc[3]
	}
	b.WriteString(s[last:])
	return b.String()
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

// rewriteBadges は README の精度表記を実測値で書き換える。
func rewriteBadges(readme string, spec readmeSpec, results []Result) string {
	if spec.ruleRows != nil {
		f1 := map[string]float64{}
		for _, r := range results {
			f1[r.RuleID] = r.F1
		}
		lines := strings.Split(readme, "\n")
		for i, line := range lines {
			for id, label := range spec.ruleRows {
				if strings.HasPrefix(line, "| "+label+" |") {
					lines[i] = ruleBadgeRe.ReplaceAllString(line, BadgeMarkdown(f1[id]))
					break
				}
			}
		}
		readme = strings.Join(lines, "\n")
	}
	readme = replaceGroup1(readme, overallBadgeRe, overallBadgeValue(results))
	if spec.plainF1Re != nil {
		text, _ := Badge(Micro(results).F1)
		readme = replaceGroup1(readme, spec.plainF1Re, text)
	}
	return readme
}
