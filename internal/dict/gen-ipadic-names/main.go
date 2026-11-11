// Command gen-ipadic-names は IPADIC 2.7.0 の Noun.name.csv（EUC-JP）から、既定の姓名辞書
// （surnames.txt / given_names.txt）に無い姓と名を抽出し、surnames_ipadic.txt と
// given_names_ipadic.txt を作り直す。出典・ライセンスは THIRD_PARTY_NOTICES.md を参照。
//
//	go run ./internal/dict/gen-ipadic-names \
//	  -ipadic-names Noun.name.csv \
//	  -surnames internal/dict/surnames.txt \
//	  -given-names internal/dict/given_names.txt \
//	  -surnames-out internal/dict/surnames_ipadic.txt \
//	  -given-names-out internal/dict/given_names_ipadic.txt
//
// 取り込む語は、日常語や歴史上の人物名との衝突を抑えるため次に限る。
//   - 姓: 「名詞,固有名詞,人名,姓」の 2〜4 文字で、既定の名辞書と同形でないもの。漢字だけ
//     の語のほか、漢字の間に「ケ」「ノ」「ツ」を 1 つ挟む語（「松ケ崎」「一ノ関」「八ツ木」）も
//     取り込む。「ヶ」は既定辞書に合わせて「ケ」にそろえる。
//   - 名: 「名詞,固有名詞,人名,名」の 2〜4 文字で、漢字を 1 文字以上含み、残りが
//     ひらがなだけのもの（「とき江」は取り込み、「みな」「マコト」は取り込まない）。
//     姓（既定・追加分とも）と同形のものは除く（既定辞書と同じ方針）。
//
// 1 文字の姓名（「上」「尊」等）と、かなだけの名は一般語と衝突しやすいため取り込まない。
//
// -ipadic-dir（IPADIC の CSV を置いたディレクトリ）と -common-words-out を指定すると、
// 一般語の一覧 common_words.txt も作り直す。人名・地名・組織名・固有名詞の CSV を除く全品詞の
// 1〜4 文字の漢字・かなの語のうち、姓名辞書（既定・IPADIC 追加分）と同形でないもの。
// 辞書にない「<姓> <名>」を形で受けるとき、一般語の組（別紙 参照）を除くために使う。
package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/transform"
)

func main() {
	ipadic := flag.String("ipadic-names", "", "IPADIC 2.7.0 Noun.name.csv (EUC-JP) のパス")
	surnames := flag.String("surnames", "", "既定の surnames.txt")
	givenNames := flag.String("given-names", "", "既定の given_names.txt")
	surnamesOut := flag.String("surnames-out", "", "書き出す surnames_ipadic.txt")
	givenNamesOut := flag.String("given-names-out", "", "書き出す given_names_ipadic.txt")
	ipadicDir := flag.String("ipadic-dir", "", "IPADIC 2.7.0 の CSV（EUC-JP）を置いたディレクトリ（-common-words-out と併用）")
	commonOut := flag.String("common-words-out", "", "書き出す common_words.txt")
	flag.Parse()
	if *ipadic == "" || *surnames == "" || *givenNames == "" || *surnamesOut == "" || *givenNamesOut == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*ipadic, *surnames, *givenNames, *surnamesOut, *givenNamesOut); err != nil {
		fmt.Fprintln(os.Stderr, "gen-ipadic-names:", err)
		os.Exit(1)
	}
	if (*ipadicDir == "") != (*commonOut == "") {
		fmt.Fprintln(os.Stderr, "gen-ipadic-names: -ipadic-dir と -common-words-out は両方指定する")
		os.Exit(2)
	}
	if *commonOut != "" {
		if err := runCommonWords(*ipadicDir, []string{*surnames, *givenNames, *surnamesOut, *givenNamesOut}, *commonOut); err != nil {
			fmt.Fprintln(os.Stderr, "gen-ipadic-names:", err)
			os.Exit(1)
		}
	}
}

// properNounFiles は一般語の一覧から除く IPADIC の CSV（人名・地名・組織名・固有名詞）。
// 日本の姓は地名に由来するものが多く、地名を一般語に含めると辞書にない姓を落とすため。
var properNounFiles = map[string]bool{
	"Noun.name.csv": true, "Noun.place.csv": true, "Noun.org.csv": true, "Noun.proper.csv": true,
}

func runCommonWords(dir string, namePaths []string, out string) error {
	names := map[string]bool{}
	for _, p := range namePaths {
		m, err := readLines(p)
		if err != nil {
			return err
		}
		for k := range m {
			names[k] = true
		}
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.csv"))
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var words []string
	for _, p := range paths {
		if properNounFiles[filepath.Base(p)] {
			continue
		}
		surfaces, err := readSurfaces(p)
		if err != nil {
			return err
		}
		for _, w := range surfaces {
			if CommonWordShape(w) && !names[w] && !seen[w] {
				seen[w] = true
				words = append(words, w)
			}
		}
	}
	sort.Strings(words)
	return writeLines(out, "# IPADIC 2.7.0 の一般語（人名・地名・組織名・固有名詞を除く全品詞）のうち、1〜4 文字の漢字・かなの語で姓名辞書と同形でないもの。\n"+
		"# 辞書にない「<姓> <名>」を形で受けるとき、一般語の組（別紙 参照・同上 同上）を除くために使う。\n"+
		"# 出典は THIRD_PARTY_NOTICES.md の IPADIC。internal/dict/gen-ipadic-names で再生成する（手で編集しない）。\n", words)
}

// CommonWordShape は w が 1〜4 文字で、漢字・々・ひらがな（ゝゞを含む）・カタカナ・ー だけからなるかを返す。
func CommonWordShape(w string) bool {
	n := 0
	for _, r := range w {
		n++
		switch {
		case r >= 0x4E00 && r <= 0x9FFF, r == '々', r >= 0x3041 && r <= 0x3096, r == 0x309D, r == 0x309E,
			r >= 0x30A1 && r <= 0x30FA, r == 0x30FC:
		default:
			return false
		}
	}
	return n >= 1 && n <= 4
}

// readSurfaces は IPADIC の CSV（EUC-JP）の表層形（1 列目）を返す。
func readSurfaces(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(transform.NewReader(f, japanese.EUCJP.NewDecoder()))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	var out []string
	for {
		rec, err := r.Read()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if len(rec) > 0 {
			out = append(out, strings.TrimSpace(rec[0]))
		}
	}
}

func run(ipadic, surnamesPath, givenPath, surnamesOut, givenOut string) error {
	baseSurnames, err := readLines(surnamesPath)
	if err != nil {
		return err
	}
	baseGiven, err := readLines(givenPath)
	if err != nil {
		return err
	}
	ipaSurnames, ipaGiven, err := readIPADIC(ipadic)
	if err != nil {
		return err
	}
	surnames, given := Select(baseSurnames, baseGiven, ipaSurnames, ipaGiven)
	const source = "# 出典: IPADIC 2.7.0-20070801 Noun.name.csv（Noun.name.csv の SHA-256 は\n" +
		"# 792040c47410b60235af15ba84eb2771f035434e18bd3e22e84fa0968fbf2084）。著作権表示とライセンスは\n" +
		"# THIRD_PARTY_NOTICES.md を参照。internal/dict/gen-ipadic-names で再生成する（手で編集しない）。\n"
	if err := writeLines(surnamesOut, "# 既定の姓辞書（surnames.txt）に無い IPADIC の姓（漢字 2〜4 文字（間の「ケ」「ノ」「ツ」を含む）、名辞書と同形のものを除く）。\n"+source, surnames); err != nil {
		return err
	}
	return writeLines(givenOut, "# 既定の名辞書（given_names.txt）に無い IPADIC の名（漢字を含む 2〜4 文字、姓と同形のものを除く）。\n"+source, given)
}

// Select は IPADIC の姓・名から、既定辞書に無く取り込み条件を満たすものをソートして返す。
func Select(baseSurnames, baseGiven map[string]bool, ipaSurnames, ipaGiven []string) (surnames, given []string) {
	added := map[string]bool{}
	for _, s := range ipaSurnames {
		s = strings.ReplaceAll(s, "ヶ", "ケ")
		n := len([]rune(s))
		if n < 2 || n > 4 || !surnameShape(s) || baseSurnames[s] || baseGiven[s] || added[s] {
			continue
		}
		added[s] = true
		surnames = append(surnames, s)
	}
	seenGiven := map[string]bool{}
	for _, s := range ipaGiven {
		n := len([]rune(s))
		if n < 2 || n > 4 || !hanWithHiragana(s) || baseGiven[s] || baseSurnames[s] || added[s] || seenGiven[s] {
			continue
		}
		seenGiven[s] = true
		given = append(given, s)
	}
	sort.Strings(surnames)
	sort.Strings(given)
	return surnames, given
}

// surnameShape は s が漢字だけか、漢字の間に「ケ」「ノ」「ツ」を 1 つだけ挟んだ形かを返す。
func surnameShape(s string) bool {
	rs := []rune(s)
	connectors := 0
	for i, r := range rs {
		if r == 'ケ' || r == 'ノ' || r == 'ツ' {
			if i == 0 || i == len(rs)-1 {
				return false
			}
			connectors++
			continue
		}
		if !unicode.Is(unicode.Han, r) && r != '々' {
			return false
		}
	}
	return connectors <= 1
}

// hanWithHiragana は s が漢字を 1 文字以上含み、残りがひらがなだけかを返す。
func hanWithHiragana(s string) bool {
	han := false
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Han, r) || r == '々':
			han = true
		case unicode.Is(unicode.Hiragana, r):
		default:
			return false
		}
	}
	return han
}

func readIPADIC(path string) (surnames, given []string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	r := csv.NewReader(transform.NewReader(f, japanese.EUCJP.NewDecoder()))
	r.FieldsPerRecord = -1
	for {
		rec, err := r.Read()
		if err == io.EOF {
			return surnames, given, nil
		}
		if err != nil {
			return nil, nil, err
		}
		if len(rec) < 8 || rec[4] != "名詞" || rec[5] != "固有名詞" || rec[6] != "人名" {
			continue
		}
		switch rec[7] {
		case "姓":
			surnames = append(surnames, strings.TrimSpace(rec[0]))
		case "名":
			given = append(given, strings.TrimSpace(rec[0]))
		}
	}
}

func readLines(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out[line] = true
		}
	}
	return out, sc.Err()
}

func writeLines(path, header string, lines []string) error {
	return os.WriteFile(path, []byte(header+strings.Join(lines, "\n")+"\n"), 0o644)
}
