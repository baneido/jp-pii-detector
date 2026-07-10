// Command gen-names は shuheilocale/japanese-personal-name-dataset（MIT
// ライセンス）の CSV から、氏名辞書（internal/dict）のカタカナ読み・
// ローマ字表記エントリを生成する。出典・ライセンスは THIRD_PARTY_NOTICES.md
// を参照。データセット本体（配布元）:
//
//	https://github.com/shuheilocale/japanese-personal-name-dataset
//
// 入力は同リポジトリの dataset/ ディレクトリにある 3 つの CSV:
//
//	last_name_org.csv         (kanji,count,hiragana,romaji)         姓・全件
//	first_name_man_opti.csv   (hiragana,romaji,kanji...)            名（男性・人気名の厳選サブセット）
//	first_name_woman_opti.csv (hiragana,romaji,kanji...)            名（女性・人気名の厳選サブセット）
//
// 名は同データセットが提供する "opti"（curated popular names）サブセットに
// 限定する。カタカナ表記の氏名はサービス名・製品名と同形になりやすく
// （例: さくら・ひかり型の誤検出）、全件（*_org.csv、数千〜1万件規模）を
// 無条件に取り込むと適合率への影響が大きいおそれがあるため、まず代表的な
// 部分集合から始め、外部評価データセット（$JP_PII_FIXTURES）で適合率を
// 確認してから拡大するという段階的な方針をとる（詳細は issue #58）。姓は
// 全件（1999 件、*_org.csv）を使う。カタカナの姓読みは一般語彙との衝突が
// 相対的に少なく、既存の漢字姓辞書と同じソース・同じ件数なので追加リスクが
// 小さいと判断した。
//
// 出力は 4 つの辞書ファイルへの追記（1 行 1 エントリ、UTF-8、既存エントリは
// 変更しない。新規エントリのみソート済みで末尾に追記する。再実行しても
// 重複は追加しない）。
//
//	go run ./internal/dict/gen-names \
//	  -last-names last_name_org.csv \
//	  -given-names-man first_name_man_opti.csv \
//	  -given-names-woman first_name_woman_opti.csv \
//	  -surnames-out internal/dict/surnames.txt \
//	  -given-names-out internal/dict/given_names.txt \
//	  -romaji-surnames-out internal/dict/romaji_surnames.txt \
//	  -romaji-given-names-out internal/dict/romaji_given_names.txt
//
// 4 文字姓（勅使河原・小比類巻 等）は現行の last_name_org.csv に収録が
// 無い（最長 3 文字）ため、このツールでは生成しない。internal/dict/surnames.txt
// に人手で追加済みの小さな代表集合を参照（各エントリのコメントに出典を記載）。
package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

func main() {
	lastNames := flag.String("last-names", "", "last_name_org.csv のパス (kanji,count,hiragana,romaji)")
	givenMan := flag.String("given-names-man", "", "first_name_man_opti.csv のパス (hiragana,romaji,kanji...)")
	givenWoman := flag.String("given-names-woman", "", "first_name_woman_opti.csv のパス (hiragana,romaji,kanji...)")
	surnamesOut := flag.String("surnames-out", "", "カタカナ読みを追記する surnames.txt のパス")
	givenNamesOut := flag.String("given-names-out", "", "カタカナ読みを追記する given_names.txt のパス")
	romajiSurnamesOut := flag.String("romaji-surnames-out", "", "ローマ字姓を書き出す romaji_surnames.txt のパス")
	romajiGivenNamesOut := flag.String("romaji-given-names-out", "", "ローマ字名を書き出す romaji_given_names.txt のパス")
	flag.Parse()

	if *lastNames == "" || *givenMan == "" || *givenWoman == "" ||
		*surnamesOut == "" || *givenNamesOut == "" ||
		*romajiSurnamesOut == "" || *romajiGivenNamesOut == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}

	if err := run(genArgs{
		lastNames:           *lastNames,
		givenMan:            *givenMan,
		givenWoman:          *givenWoman,
		surnamesOut:         *surnamesOut,
		givenNamesOut:       *givenNamesOut,
		romajiSurnamesOut:   *romajiSurnamesOut,
		romajiGivenNamesOut: *romajiGivenNamesOut,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "gen-names:", err)
		os.Exit(1)
	}
}

type genArgs struct {
	lastNames           string
	givenMan            string
	givenWoman          string
	surnamesOut         string
	givenNamesOut       string
	romajiSurnamesOut   string
	romajiGivenNamesOut string
}

// lastNameRow は last_name_org.csv の 1 行（kanji,count,hiragana,romaji）。
type lastNameRow struct {
	Kanji    string
	Hiragana string
	Romaji   string
}

// givenNameRow は first_name_{man,woman}_opti.csv の 1 行
// （hiragana,romaji,kanji...）。1 読みに複数の漢字表記が対応する。
type givenNameRow struct {
	Hiragana string
	Romaji   string
}

func run(args genArgs) error {
	lastNames, err := readLastNames(args.lastNames)
	if err != nil {
		return fmt.Errorf("read %s: %w", args.lastNames, err)
	}
	givenMan, err := readGivenNames(args.givenMan)
	if err != nil {
		return fmt.Errorf("read %s: %w", args.givenMan, err)
	}
	givenWoman, err := readGivenNames(args.givenWoman)
	if err != nil {
		return fmt.Errorf("read %s: %w", args.givenWoman, err)
	}
	givenNames := append(append([]givenNameRow(nil), givenMan...), givenWoman...)

	var katakanaSurnames, romajiSurnames []string
	for _, r := range lastNames {
		katakanaSurnames = append(katakanaSurnames, hiraganaToKatakana(r.Hiragana))
		romajiSurnames = append(romajiSurnames, r.Romaji)
	}

	var katakanaGivenNames, romajiGivenNames []string
	for _, r := range givenNames {
		katakanaGivenNames = append(katakanaGivenNames, hiraganaToKatakana(r.Hiragana))
		romajiGivenNames = append(romajiGivenNames, r.Romaji)
	}

	// 姓と同形の名は既存の辞書と同じ方針で除外する（internal/dict.TestNameDictIntegrity
	// が姓名の相互重複を禁止している。理由は given_names.txt のヘッダーコメント参照:
	// 「姓と同形の名は、弱ラベルでの偽陽性を避けるため除外している」）。既存の
	// surnames.txt の内容と、今回生成した新規カタカナ姓の両方を姓集合とみなす。
	surnameSet, err := readNonCommentLines(args.surnamesOut)
	if err != nil {
		return fmt.Errorf("read %s: %w", args.surnamesOut, err)
	}
	for _, s := range katakanaSurnames {
		surnameSet[s] = true
	}
	katakanaGivenNames = excludeSurnames(katakanaGivenNames, surnameSet)

	header := "# カタカナ読み（shuheilocale/japanese-personal-name-dataset の読み仮名列より生成。\n" +
		"# internal/dict/gen-names で再生成可能。出典・ライセンスは THIRD_PARTY_NOTICES.md 参照）。\n"
	if err := appendUniqueLines(args.surnamesOut, header, katakanaSurnames); err != nil {
		return fmt.Errorf("write %s: %w", args.surnamesOut, err)
	}
	if err := appendUniqueLines(args.givenNamesOut, header, katakanaGivenNames); err != nil {
		return fmt.Errorf("write %s: %w", args.givenNamesOut, err)
	}

	romajiSurnameHeader := "# 日本の姓のローマ字（ヘボン式）表記。person-name-romaji ルール（高再現率、既定オフ）の\n" +
		"# 姓側の共起判定に使う。全文走査での氏名検出には使わない。\n" +
		"# 出典: shuheilocale/japanese-personal-name-dataset last_name_org.csv (MIT)。\n" +
		"# 出典の著作権表示とライセンスは THIRD_PARTY_NOTICES.md を参照。\n" +
		"# internal/dict/gen-names で再生成可能。\n"
	if err := appendUniqueLines(args.romajiSurnamesOut, romajiSurnameHeader, romajiSurnames); err != nil {
		return fmt.Errorf("write %s: %w", args.romajiSurnamesOut, err)
	}

	romajiGivenHeader := "# 日本の名のローマ字（ヘボン式）表記。person-name-romaji ルール（高再現率、既定オフ）の\n" +
		"# 名側の共起判定に使う。全文走査での氏名検出には使わない。\n" +
		"# 出典: shuheilocale/japanese-personal-name-dataset\n" +
		"# first_name_man_opti.csv / first_name_woman_opti.csv (MIT、人気名の厳選サブセット)。\n" +
		"# 出典の著作権表示とライセンスは THIRD_PARTY_NOTICES.md を参照。\n" +
		"# internal/dict/gen-names で再生成可能。\n"
	if err := appendUniqueLines(args.romajiGivenNamesOut, romajiGivenHeader, romajiGivenNames); err != nil {
		return fmt.Errorf("write %s: %w", args.romajiGivenNamesOut, err)
	}
	return nil
}

// readLastNames は last_name_org.csv（kanji,count,hiragana,romaji）を読む。
func readLastNames(path string) ([]lastNameRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	var out []lastNameRow
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rec) < 4 {
			continue
		}
		out = append(out, lastNameRow{Kanji: rec[0], Hiragana: rec[2], Romaji: rec[3]})
	}
	return out, nil
}

// readGivenNames は first_name_{man,woman}_{org,opti}.csv
// （hiragana,romaji,kanji...）を読む。
func readGivenNames(path string) ([]givenNameRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	var out []givenNameRow
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rec) < 2 {
			continue
		}
		out = append(out, givenNameRow{Hiragana: rec[0], Romaji: rec[1]})
	}
	return out, nil
}

// hiraganaToKatakana はひらがな（U+3041-3096）をカタカナ（U+30A1-30F6）へ
// 変換する。両ブロックは同じ並びで隣接しているため +0x60 の単純オフセットで
// 変換できる（NFKC 等の外部依存なし）。範囲外の文字（長音記号「ー」等）は
// そのまま返す。
func hiraganaToKatakana(s string) string {
	rs := []rune(s)
	for i, r := range rs {
		if r >= 0x3041 && r <= 0x3096 {
			rs[i] = r + 0x60
		}
	}
	return string(rs)
}

// readNonCommentLines は path の既存内容を読み、空行・# コメント行を除いた
// 行の集合を返す（loadNameSet と同じ規則）。path が存在しない場合は空集合を返す。
func readNonCommentLines(path string) (map[string]bool, error) {
	out := map[string]bool{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = true
	}
	return out, sc.Err()
}

// excludeSurnames は entries から surnames に含まれる値を取り除く。姓と同形の
// 名を除外する既存の辞書方針（given_names.txt ヘッダー参照）をカタカナ読みにも
// 適用するために使う。
func excludeSurnames(entries []string, surnames map[string]bool) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !surnames[strings.TrimSpace(e)] {
			out = append(out, e)
		}
	}
	return out
}

// appendUniqueLines は path の既存内容に、entries のうち未収録のものだけを
// ソートして追記する。既存の内容は一切変更しない（再実行しても重複しない）。
// path が存在しない場合は新規作成する。追加すべき新規行が 1 つもない場合は
// ファイルに一切書き込まない（ヘッダーの重複挿入を避ける）。
func appendUniqueLines(path, header string, entries []string) (err error) {
	existing, err := readNonCommentLines(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	content := string(data)

	seen := map[string]bool{}
	var newLines []string
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" || existing[e] || seen[e] {
			continue
		}
		seen[e] = true
		newLines = append(newLines, e)
	}
	if len(newLines) == 0 {
		return nil
	}
	sort.Strings(newLines)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	var b strings.Builder
	// 既存内容が改行なしで終わっている場合に追記行と連結されないよう保護する。
	if content != "" && !strings.HasSuffix(content, "\n") {
		b.WriteByte('\n')
	}
	// ヘッダーは、既存ファイルに含まれていなければ新規ブロックの前に 1 度だけ書く。
	if !strings.Contains(content, header) {
		b.WriteString(header)
	}
	for _, l := range newLines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	_, err = f.WriteString(b.String())
	return err
}
