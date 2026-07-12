package detect

import (
	"path/filepath"
	"strings"
	"unicode"

	"github.com/baneido/jp-pii-detector/internal/normalize"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// CSV/TSV は「郵便番号,口座番号」のようなヘッダの下に値だけが並ぶ列指向の
// データで、隣接 ±1 行の source context（source_context.go）では 2 行目の
// データ行しか救えず、3 行目以降は文脈を失って軒並み検出漏れになる
// （FN プローブで実証済み）。ここではヘッダ行（1 行目）をパースして
// 各列のラベル語を求め、以降の全データ行の該当フィールドへ
// statementContext を付与する。フル走査（sourceLineContexts）限定で、
// diff 走査では使わない（hunk はヘッダ行を含まないことが多く、列の
// ずれた誤帰属を避けるため）。

// csvDelimiterForPath は拡張子から CSV/TSV の区切り文字を返す
// （sourceKindForPath が .csv/.tsv だけを sourceKindCSV に分類するため、
// それ以外の拡張子では呼ばれない前提）。
func csvDelimiterForPath(path string) byte {
	if strings.EqualFold(filepath.Ext(path), ".tsv") {
		return '\t'
	}
	return ','
}

// IsCSVOrTSVPath は path の拡張子が .csv/.tsv（大文字小文字を区別しない）かを
// 返す。internal/source/gitdiff.go が diff hunk 用の post-image ヘッダ行を
// `git show` で取得するかどうかの判定に使う（ヘッダ取得は CSV/TSV だけに
// 意味があり、それ以外の拡張子で無駄な git 呼び出しをしないため）。
// sourceKindForPath と判定基準がずれないよう、拡張子リストを再定義せず
// sourceKindForPath に委譲する。
func IsCSVOrTSVPath(path string) bool {
	return sourceKindForPath(path) == sourceKindCSV
}

// csvField は 1 フィールドの本文（囲み引用符を除く）のバイト範囲。
// line（正規化済み）に対する半開区間で、statementContext.Start/End と
// 同じ基準（正規化済み行の byte offset）を使う。
type csvField struct {
	start, end int
}

// splitCSVLine は正規化済みの 1 行を RFC 4180 準拠の引用符処理（"" は
// リテラルな引用符 1 個にエスケープ）でフィールドに分割する。実務でよくある
// 区切り文字直後の半角空白を挟んだ引用フィールドも認識する。ただし、引用符が
// 続かない空白は従来どおりフィールド本文に含める。フィールド内改行で引用符が
// 行末までに閉じないレコードや、閉じ引用符の後に区切り文字以外が続くなど
// 引用符の構文が不正なレコードは terminated=false を返す。
// この関数は 1 行だけを見るため、そのようなレコード（複数物理行にまたがる
// 1 論理行）を正しく再構成することはできない。呼び出し側は terminated=false
// を検出したら、csvUnterminatedRecordEnd でレコードが占める物理行を
// 特定してその範囲には列コンテキストを付与せず、レコードが閉じた次の
// 物理行から付与を再開する（列がずれた誤帰属を避けつつ、1 レコードだけの
// ためにファイル全体の文脈を失わないようにする）。
func splitCSVLine(line string, delim byte) (fields []csvField, terminated bool) {
	i, n := 0, len(line)
	afterDelimiter := false
	for {
		var f csvField
		quoteStart := i
		if afterDelimiter {
			for quoteStart < n && line[quoteStart] == ' ' {
				quoteStart++
			}
		}
		if quoteStart < n && line[quoteStart] == '"' {
			i = quoteStart
			i++ // 開き引用符
			f.start = i
			for i < n {
				if line[i] == '"' {
					if i+1 < n && line[i+1] == '"' {
						i += 2 // エスケープされた引用符（フィールド本文に含む）
						continue
					}
					break
				}
				i++
			}
			if i >= n {
				// 行末までに閉じ引用符が見つからない: フィールド内改行の可能性。
				return fields, false
			}
			f.end = i
			i++ // 閉じ引用符
			// 実務上よくある閉じ引用符後の半角空白は許容するが、それ以外の
			// 文字は RFC 4180 の引用フィールドとして不正。誤った列文脈を
			// 付与しないようレコード全体を不成立にする。
			for i < n && line[i] == ' ' {
				i++
			}
			if i < n && line[i] != delim {
				return fields, false
			}
		} else {
			f.start = i
			for i < n && line[i] != delim {
				// 非引用フィールド内の引用符も RFC 4180 では不正。引用符内の
				// 区切り文字を見誤って列がずれる可能性があるため拒否する。
				if line[i] == '"' {
					return fields, false
				}
				i++
			}
			f.end = i
		}
		fields = append(fields, f)
		if i >= n {
			break
		}
		i++ // 区切り文字を読み飛ばす
		afterDelimiter = true
	}
	return fields, true
}

// csvUnterminatedRecordEnd は、splitCSVLine が terminated=false を返した
// データ行（lines[start]）から始まるレコードが、フィールド内改行を挟んで
// 何物理行にまたがるかを RFC 4180 の引用符トグル（"" はエスケープされた
// 引用符 1 個）だけで追跡する。splitCSVLine のようなフィールド構文の妥当性
// 検証（閉じ引用符後は区切り文字のみ等）は行わず、「引用符の中か外か」だけを
// 見るため、閉じ引用符の後に不正な文字が続く（構文エラーの）行でも、その物理行
// 内で引用符が偶数個であれば 1 行だけのレコードとして扱える。
// closed=true のとき、そのレコードは lines[start:next] の物理行を占め
// （呼び出し側はこの範囲に列コンテキストを付与しない）、next からは列の
// ずれがないことが保証されるため付与を再開できる。EOF まで引用符が閉じない
// 場合は closed=false（next==len(lines)）を返し、呼び出し側は従来どおり
// それ以降の付与を打ち切る。
func csvUnterminatedRecordEnd(lines []string, start int) (next int, closed bool) {
	inQuotes := false
	for i := start; i < len(lines); i++ {
		line := normalize.Line(lines[i])
		j, n := 0, len(line)
		for j < n {
			if line[j] == '"' {
				if inQuotes && j+1 < n && line[j+1] == '"' {
					j += 2 // エスケープされた引用符（トグルしない）
					continue
				}
				inQuotes = !inQuotes
				j++
				continue
			}
			j++
		}
		if !inQuotes {
			return i + 1, true
		}
	}
	return len(lines), false
}

// looksLikeCSVHeader は 1 行目がヘッダ行らしいかのヒューリスティック。
// フィールド数が 2 以上で、かつどのフィールドも空でも数値主体でもないこと。
// 成立しない場合は「ヘッダ無し CSV」とみなし、列コンテキストを一切付与しない
// （安全側 = 現状維持）。
func looksLikeCSVHeader(line string, fields []csvField) bool {
	if len(fields) < 2 {
		return false
	}
	for _, f := range fields {
		text := strings.TrimSpace(line[f.start:f.end])
		if text == "" || isNumericMajorityText(text) {
			return false
		}
	}
	return true
}

// isNumericMajorityText は空白を除いた文字の半数以上が ASCII 数字かを返す
// （データ行の先頭行を誤ってヘッダ扱いしないための判定に使う）。
func isNumericMajorityText(s string) bool {
	var digits, total int
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		total++
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return total > 0 && digits*2 >= total
}

// csvNegativeContextWordsJP は列名に含まれると値が金額・件数・連番 ID など
// 非 PII の数字とみなせる日本語語彙。ルール個別の NegativeContext
// （internal/rule/builtin.go の digitRuleNegativeContext 等）とは別に、
// 列名（部分一致）だけで判定するルール非依存の総称リスト。
var csvNegativeContextWordsJP = []string{
	"金額", "合計", "小計", "件数", "数量", "個数", "単価", "価格",
	"注文番号", "伝票番号", "受注番号", "管理番号", "通し番号", "連番", "行番号",
}

// csvColumnSignal はヘッダの 1 フィールド本文からその列の PositiveText /
// NegativeText を求める。ASCII ラベル（bank_account 等）は
// sourceLabelTokens で識別子トークン化し（sourceContextSkipTokens で
// var/const 等の一般語を除く）、日本語ヘッダ（郵便番号 等）はトークン化
// できないため（tokenizeIdentifiers は ASCII 前提）本文そのものを
// PositiveText に使う。ok=false は「文脈を持たない列（ラベル無し）」を表す。
func csvColumnSignal(headerText string) (positive, negative string, ok bool) {
	text := strings.TrimSpace(headerText)
	if text == "" {
		return "", "", false
	}
	tokens := sourceLabelTokens(text)
	positiveParts := tokens
	if !asciiOnly(text) {
		// 日本語などの非 ASCII ヘッダは identifiers としてトークン化できない
		// ため、本文全体をそのまま追加する。matchingContexts は非 ASCII
		// キーワードを部分一致（strings.Contains）で判定するため、
		// トークン化なしでも正しく照合できる。
		positiveParts = append(append([]string{}, tokens...), text)
	}
	if len(positiveParts) == 0 {
		return "", "", false
	}
	neg := sourceNegativeText(tokens)
	for _, w := range csvNegativeContextWordsJP {
		if strings.Contains(text, w) {
			if neg == "" {
				neg = w
			} else {
				neg += " " + w
			}
		}
	}
	return strings.Join(positiveParts, " "), neg, true
}

// csvHeader はパース済みの CSV ヘッダ（フィールド単位のテキストと文脈）。
type csvHeader struct {
	text     []string
	positive []string
	negative []string
}

// parseCSVHeader は 1 行目をヘッダとしてパースする。ヘッダ行らしくない
// （looksLikeCSVHeader が false）場合や、引用符が閉じない場合は ok=false。
func parseCSVHeader(lines []string, delim byte) (csvHeader, bool) {
	if len(lines) == 0 {
		return csvHeader{}, false
	}
	norm := normalize.Line(lines[0])
	fields, terminated := splitCSVLine(norm, delim)
	if !terminated || !looksLikeCSVHeader(norm, fields) {
		return csvHeader{}, false
	}
	h := csvHeader{
		text:     make([]string, len(fields)),
		positive: make([]string, len(fields)),
		negative: make([]string, len(fields)),
	}
	for i, f := range fields {
		text := strings.TrimSpace(norm[f.start:f.end])
		h.text[i] = text
		positive, negative, ok := csvColumnSignal(text)
		if !ok {
			continue
		}
		h.positive[i] = positive
		h.negative[i] = negative
	}
	return h, true
}

// csvLineContexts は CSV/TSV ファイルのヘッダ列名から、以降の全データ行の
// 該当フィールドへ statementContext を付与する（sourceLineContexts からのみ
// 呼ばれる。フル走査限定。1 行目は自ファイルのヘッダなのでデータ行の
// 割り当ては 2 行目 (index 1) から始める）。
func csvLineContexts(file string, lines []string) []lineContext {
	out := make([]lineContext, len(lines))
	delim := csvDelimiterForPath(file)
	header, ok := parseCSVHeader(lines, delim)
	if !ok {
		return out
	}
	csvAssignColumnContexts(out, lines, delim, header, 1)
	return out
}

// csvDiffLineContexts は csvLineContexts の diff hunk 版。ヘッダは hunk 自身の
// 1 行目（lines[0]）ではなく、呼び出し側（internal/source/gitdiff.go）が
// post-image から `git show` で個別取得した 1 行（header）を使う。hunk は
// 通常ヘッダ行を含まない（変更箇所がファイル先頭付近でない限り）ため、
// csvLineContexts のようにヘッダをスキップせず lines[0] からデータ行として
// 割り当てる（万一ヘッダ自身が hunk の 1 行目に含まれていても、ラベル文字列
// 自体が数字系 PII パターンにマッチすることは実質なく、実害はない）。
//
// header が空文字、または looksLikeCSVHeader を満たさない場合は列コンテキスト
// なし（out はゼロ値のまま）を返す — 呼び出し側のヘッダ取得失敗（新規ファイル
// がまだ対象リビジョンに存在しない等）・空・ヘッダ行らしくない、のいずれでも
// 従来どおり列コンテキストなしの安全側にフォールバックする。
func csvDiffLineContexts(file, header string, lines []string) []lineContext {
	out := make([]lineContext, len(lines))
	delim := csvDelimiterForPath(file)
	h, ok := parseCSVHeader([]string{header}, delim)
	if !ok {
		return out
	}
	csvAssignColumnContexts(out, lines, delim, h, 0)
	return out
}

// csvAssignColumnContexts は header 済みの列文脈を lines[from:] の各データ行へ
// 割り当てる（csvLineContexts と csvDiffLineContexts の共通本体。前者は
// lines[0] が自ファイルのヘッダのため from=1、後者は lines 自体がヘッダを
// 含まない前提のため from=0 で呼ぶ）。
//
// 制限: フィールド内改行で引用符が物理行末までに閉じないレコードに遭遇したら
// csvUnterminatedRecordEnd でレコードの終端を lines の範囲内で探し、レコードが
// 占める物理行には列コンテキストを付与しない（列がずれた誤帰属を避ける）。
// diff hunk 版では lines が hunk 内の行に限られるため、hunk 内でレコードが
// 閉じなければ（closed=false）EOF まで閉じない場合と同じ扱いで以降の割り当てを
// 打ち切る。hunk の直前（hunk に含まれない先行部分）で引用符が開いたまま
// hunk へ突入しているケース（hunk 冒頭が引用符未閉レコードの途中）は診断
// できないが、その場合 lines[from] 自体の splitCSVLine が構文エラーとして
// terminated=false を返す可能性が高く、同じ「閉じるまで打ち切る」経路で
// 安全側に倒れる（詳細は docs/development.md）。
func csvAssignColumnContexts(out []lineContext, lines []string, delim byte, header csvHeader, from int) {
	for i := from; i < len(lines); i++ {
		norm := normalize.Line(lines[i])
		fields, terminated := splitCSVLine(norm, delim)
		if !terminated {
			// フィールド内改行（またはレコード内の構文エラー）でこの行の列は
			// 信頼できないため、レコードが占める物理行には列コンテキストを
			// 付与しない。ただしレコードが閉じ次第、次の物理行からは列の
			// ずれがないため付与を再開する（範囲内で閉じない場合のみ、
			// 従来どおり残り全体を打ち切る）。
			next, closed := csvUnterminatedRecordEnd(lines, i)
			if !closed {
				return
			}
			i = next - 1
			continue
		}
		var stmts []statementContext
		for fi, f := range fields {
			if fi >= len(header.text) || header.text[fi] == "" || f.start >= f.end {
				continue
			}
			if header.positive[fi] == "" && header.negative[fi] == "" {
				continue
			}
			stmts = append(stmts, statementContext{
				Start:        f.start,
				End:          f.end,
				PositiveText: header.positive[fi],
				NegativeText: header.negative[fi],
			})
		}
		out[i].Statements = stmts
	}
}

// scanCSVNameColumns は CSV/TSV のヘッダが氏名系の強いラベル
// （personNameLabelJP / personNameLabelASCIIStrong と列全体が完全一致）と
// なる列について、各データ行のフィールド値が氏名として妥当か（辞書照合込み）
// を検証し person-name-structured として報告する。person-name-structured は
// 高再現率限定のルールのため、crossLineName が有効なときだけ呼ばれる。
// フリガナ（カタカナ）列はラベル語彙としては一致しうるが、埋め込み姓名辞書が
// 漢字ベースのため ValidCrossLineName が値を通さず、対象外になる。
func (d *Detector) scanCSVNameColumns(file string, lines []string) []Finding {
	if rule.Medium < d.minConf {
		return nil
	}
	if d.crossLineName == nil {
		return nil
	}
	delim := csvDelimiterForPath(file)
	if len(lines) == 0 {
		return nil
	}
	headerNorm := normalize.Line(lines[0])
	headerFields, terminated := splitCSVLine(headerNorm, delim)
	if !terminated || !looksLikeCSVHeader(headerNorm, headerFields) {
		return nil
	}
	nameCols := map[int]bool{}
	for i, f := range headerFields {
		text := strings.TrimSpace(headerNorm[f.start:f.end])
		if text != "" && rule.CSVNameHeaderRe.MatchString(text) {
			nameCols[i] = true
		}
	}
	if len(nameCols) == 0 {
		return nil
	}
	var out []Finding
	for li := 1; li < len(lines); li++ {
		norm := normalize.Line(lines[li])
		fields, terminated := splitCSVLine(norm, delim)
		if !terminated {
			// csvLineContexts と同じレコード境界の追跡でスキップし、
			// 閉じた次の物理行から氏名列の検査を再開する。
			next, closed := csvUnterminatedRecordEnd(lines, li)
			if !closed {
				break
			}
			li = next - 1
			continue
		}
		var origRunes []rune
		for fi, f := range fields {
			if !nameCols[fi] || f.start >= f.end {
				continue
			}
			field := norm[f.start:f.end]
			m := rule.CSVNameValueRe.FindStringSubmatchIndex(field)
			if m == nil || m[2] < 0 {
				continue
			}
			entity := field[m[2]:m[3]]
			if !rule.ValidCrossLineName(entity) || d.allowlisted(entity) {
				continue
			}
			rs := len([]rune(norm[:f.start+m[2]]))
			re := rs + len([]rune(entity))
			if origRunes == nil {
				origRunes = []rune(lines[li])
			}
			if re > len(origRunes) {
				continue
			}
			finding := Finding{
				RuleID:      d.crossLineName.ID,
				Description: d.crossLineName.Description,
				File:        file,
				Line:        li + 1,
				Column:      rs + 1,
				Match:       string(origRunes[rs:re]),
				Confidence:  rule.Medium,
				Reason: DetectReason{
					BaseConfidence:  rule.Medium.String(),
					FinalConfidence: rule.Medium.String(),
					Validated:       true,
				},
				start:         rs,
				end:           re,
				scoreEvidence: confidenceScoreEvidence{structuredPair: true},
			}
			finalizeFindingScore(&finding)
			out = append(out, finding)
		}
	}
	return out
}
