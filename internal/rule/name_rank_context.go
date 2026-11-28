package rule

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// 2026-11-19 の公開文書の走査（4,541 件）で、既定モードのルールが取りこぼしていた氏名の形
// （person-name-role-label）と、同じ確認で見つけた誤検出の棄却。人を指す語のある無作為 440 行に
// 人手で付けた正解（姓+名 81 人）のうち、既定モードが拾えたのは 61 人だった。設計には偶数番の行の
// 見逃しだけを使い、奇数番の行は検証用に残した。

// rankTitleWords は氏名の直後に付く、既存の personNamePostTitleRe にない職名（大学の診療系の職名・
// 技術職・役所の役職）。
const rankTitleWords = `栄誉教授|診療教授|診療准教授|診療講師|診療助教|主任研究員|主幹研究員|上席研究員|研究員|学芸員|技師|技官|` +
	`課長補佐|副部長|副課長|部長|課長|室長|係長|主幹|主査`

var (
	// personNameRankTitleRe は「<賞の名前> <氏名>栄誉教授」「（<氏名>教授、<氏名>技師、…）」
	// 「<氏名>課長インタビュー」のように、氏名の直後に職名が直結する形。値は姓名辞書の完全分割を要求する
	// （「総務部長」「市民課長」のような部署名 + 職名は分割できない）。
	personNameRankTitleRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|[のにでとはがをもへや])([` + kanji + `]{3,6}?)(?:` + rankTitleWords + `)` +
			`(?:[ 、。・，,！!）)（(」がはのをにともへやらか]|$|インタビュー|コメント|メッセージ)`,
	)
	// personNameSpacedAttachedTitleRe は「副センター長の<姓> <名>特任准教授が、<姓> <名>学長の代理として」の
	// ように、空白区切りの氏名に職名が直結する形（既存のパターンは氏名と職名の間の空白が必要だった）。
	personNameSpacedAttachedTitleRe = regexp.MustCompile(
		`(?:^|[^` + kanji + `]|の)([` + kanji + `]{1,4}[ ][` + kanji + `]{1,4}?)(?:` + personTitleWords + `)` +
			// 2026-11-21 に「<姓> <名>特別任用教授 最終講義」の見逃しを実測し、職名の後の空白を加えた。
			`(?:[（(がはのをにともへ、。 ]|ら[のがはとを]|$)`,
	)
	// personNameTitleNameParenRe は「<大学><学部>准教授 <氏名>（<市名>）」のように、職名・空白・氏名の後に
	// 括弧（所属・居住地・読みがな）が続く形。行末で終わる形は personNameTitleNameLineEndRe が拾う。
	personNameTitleNameParenRe = regexp.MustCompile(
		`(?:特任教授|特任准教授|名誉教授|准教授|教授|助教|講師)[ ]+([` + kanji + `]{3,6})[（(]`,
	)
	// personNameTitleDotNameRe は「（<所在地>、代表取締役社長・<姓> <名>）は、」のように、職名と氏名を
	// 中黒でつないだ形（プレスリリースの冒頭）。コロンでつないだ形は既存のパターンが拾う。
	personNameTitleDotNameRe = regexp.MustCompile(
		`(?:社長|会長|理事長|頭取|CEO|代表取締役|代表理事|代表)・[ ]?([` + kanji + `]{1,4}[ ][` + kanji + `]{1,4}|[` + kanji + `]{3,6})(?:[）)、]|氏|$)`,
	)
	// personNameCEOLineEndRe は「右：<社名> 社長兼CEO <氏名>」のように、英字の役職名・空白・氏名で
	// 行が終わる形（写真の説明・コメントの見出し）。2026-11-28 に公開文書（企業のお知らせ）で、見出しの
	// 「会長 兼 社長 CEO　<姓><名>メッセージ」（氏名にメッセージ・コメントが直結する形）の全モードの見逃しを実測した。
	personNameCEOLineEndRe = regexp.MustCompile(
		`(?:CEO|COO|CFO|CTO|CIO)[ ]+([` + kanji + `]{1,4}[ ][` + kanji + `]{1,4}|[` + kanji + `]{3,6}?)[ ]*(?:$|のコメント|[）)]|(?:からの)?メッセージ|コメント)`,
	)
	// personNameDeptContactRe は問い合わせ先の「<団体名> 広報部 <姓> <名> TEL：…」「<課名>係 <姓> <名>
	// 電話…」のように、部署名・空白・空白区切りの氏名の直後に電話・メールのラベルが続く形。2026-11-28 に
	// 公開文書（業界団体のお知らせ）で、既定モードの見逃しを実測した。部署名の語尾と連絡先のラベルの両方を
	// 要求し、値は「<辞書の姓> <辞書の名>」に限る（validDeptContactName）。
	personNameDeptContactRe = regexp.MustCompile(
		`(?:[部課室係]|センター|事務局|グループ|チーム)[ ]+([` + kanji + `]{1,4}[ ][` + kanji + `]{1,3})[ ]*(?:TEL|Tel|tel|電話|E-mail|e-mail|Email|メール)`,
	)
	// personNameAffiliationNoTitleRe は「<学部>の<氏名>教授が」「<講座名>学の<氏名>診療講師らの」のように、
	// 所属 + の + 氏名 + 教員の職名。所属と職名の両方が手がかりになるので、名が辞書にない氏名も
	// 「辞書の姓 + 1〜3 字の名」で採る（validSurnamePrefixName）。
	personNameAffiliationNoTitleRe = regexp.MustCompile(
		`(?:学部|研究科|学科|学府|学環|学群|研究所|研究院|センター|大学院|大学|病院|科学|内科|外科|講座|研究室)の([` + kanji + `]{3,6}?)` +
			// 2026-11-25 に「<学部>の<氏名>特命教授らの」で「特命」まで値に入る範囲の誤りを実測し、特命・招へい・名誉を足した。
			`(?:特任|特命|特定|特別|客員|診療|名誉|招へい|招聘)?(?:准教授|教授|講師|助教)(?:ら?[がはのとを、]|ら)`,
	)
)

// rejectRankTitleFragment は personNameRankTitleRe の値の追加検証。肩書きの一部を名として取り込んだ形
// （rejectPostTitleFragment）に加えて、「<部署>部長」「<姓><部署>課長」のように値が部署の語で終わる形と、
// 値の直前が「副」「元」などで職名の途中から始まる形を通さない。
func rejectRankTitleFragment(line string, start, end int) bool {
	v := line[start:end]
	for _, s := range []string{"総務", "企画", "財政", "財務", "人事", "営業", "事業", "管理", "政策", "福祉", "教育", "建設", "経理", "広報", "技術", "研究", "開発", "本部", "支部", "学芸", "主任", "専門", "統括", "担当", "特命", "特任", "客員", "名誉", "栄誉", "招聘"} {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	// 「<姓>本部長を中心に」は「<姓> + 本部長」で、「本」は名の一部ではない。
	if strings.HasSuffix(v, "本") && strings.HasPrefix(line[end:], "部長") {
		return false
	}
	// 「<姓>第一部長ら」は「<姓> + 第一部長」で、「第一」は名ではない。
	if strings.Contains(v, "第") {
		return false
	}
	if dict.IsMunicipalityOrPrefecture(v) || dict.MunicipalitySuffixMatch(v) {
		return false
	}
	return rejectPostTitleFragment(line, start, end)
}

// rejectSpacedAttachedTitleFragment は personNameSpacedAttachedTitleRe の値の追加検証。名の部分が
// 肩書きの頭（特任・名誉・客員・副）で終わる形を通さない。
func rejectSpacedAttachedTitleFragment(line string, start, end int) bool {
	v := line[start:end]
	for _, s := range []string{"准", "副", "特任", "名誉", "客員", "元", "前", "栄誉", "特別", "主任", "上席"} {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	return true
}

// rejectDigitsInURL は桁数だけが手がかりの番号（基礎年金番号・介護保険の被保険者番号）の値が、URL の
// 中の数字である場合に棄却する（2026-11-19 にオープンデータのカタログ CSV で実測した偽陽性。
// データセットの URL「…/dataset/<自治体コード>_<10 桁>」の 10 桁が、同じ行のデータセット名
// 「国民年金」「介護保険サービス提供事業者一覧」を手がかりに報告されていた）。値の前を空白・カンマ・
// 引用符までさかのぼり、その範囲に「://」があれば URL の一部とみなす。
func rejectDigitsInURL(line string, start, _ int) bool {
	i := strings.LastIndexAny(line[:start], " \t,\"'<>（(「")
	return !strings.Contains(line[i+1:start], "://")
}

// rejectBetweenPhoneNumbers は jp-health-insurance の「4 桁 + 空白 + 4 桁」の値が、空白で並んだ 2 つの
// 電話番号の「前の番号の末尾 4 桁 + 次の番号の市外局番」である場合に棄却する（2026-11-19 に市の
// 国民健康保険の窓口案内「給付係 <電話番号> <電話番号>」で実測した偽陽性。前の行の「保険証」が
// 手がかりになっていた）。値の直前が「数字 + ハイフン」、または直後が「ハイフン + 数字」のときを
// 電話番号の一部とみなす。
func rejectBetweenPhoneNumbers(line string, start, end int) bool {
	if start >= 2 && line[start-1] == '-' && isASCIIDigit(line[start-2]) {
		return false
	}
	if end+1 < len(line) && line[end] == '-' && isASCIIDigit(line[end+1]) {
		return false
	}
	return true
}

// rejectOccurrenceDateLabel は jp-birthdate の値の前のラベルが「発生年月日」（事故・事案の発生日）で
// ある場合に棄却する（2026-11-19 に競技団体の処分の公表ページで実測した偽陽性。「発生年月日」は
// 「生年月日」を含むので、次の行の日付が生年月日として報告されていた）。値の前で最後に現れる
// 「生年月日」の直前が「発」のときに棄却する。
func rejectOccurrenceDateLabel(line string, start, _ int) bool {
	head := line[:start]
	i := strings.LastIndex(head, "生年月日")
	if i < 0 {
		return true
	}
	return !strings.HasSuffix(head[:i], "発")
}

// givenEndsWithKun は空白区切りの「<姓> <名>君」の「君」まで名として取り込んだ値かを返す
// （2026-11-19 に国会・市議会の会議録の「○議長（<姓>　<名>君）」「<職名>　<姓>　<名>君」で実測した
// 範囲の誤り）。名が 2 字以上で「君」で終わり、名の辞書にないときを取り込みとみなす。
func givenEndsWithKun(given string) bool {
	return utf8.RuneCountInString(given) >= 2 && strings.HasSuffix(given, "君") && !dict.IsGivenName(given)
}

// rejectTrailingKun は地方議会の発言者ラベル「○議長（<姓>　<名>君）」の値が「君」まで含むときに棄却する
// （「君」を除いた範囲は国会の会議録用の発言者ラベルのパターンが拾う）。
func rejectTrailingKun(line string, start, end int) bool {
	v := line[start:end]
	return !(strings.HasSuffix(v, "君") && utf8.RuneCountInString(v) >= 3)
}

// rejectHonorificOrgAbbrevOrOaza は高再現率の敬称パターンで、団体の名前・略称に付く「さん」「様」
// （「<分野>学会様」「<社名>総研さん」「全連小さん」）、行事・制度の名前（「十五夜さん」「一芸さん」）、
// 住所の「大字<地名>氏」を敬称付きの氏名とみなさない（2026-11-19 に学会のお知らせ・国会の会議録・
// 省庁の議事録・市の人材バンクの案内・オープンデータの校区一覧で実測した高再現率モードの偽陽性。
// いずれも特定の個人を指さない）。
func rejectHonorificOrgAbbrevOrOaza(line string, start, end int) bool {
	v := line[start:end]
	rest := line[end:]
	// 「大字飯氏」は地名（大字 + 「氏」で終わる地名）。
	if strings.HasPrefix(v, "大字") && strings.HasPrefix(rest, "氏") {
		return false
	}
	if !strings.HasPrefix(rest, "さん") && !strings.HasPrefix(rest, "様") {
		return true
	}
	switch v {
	case "一芸", "十五夜", "全連小", "全日中", "全高長", "総研":
		return false
	}
	for _, s := range []string{"学会", "総研", "連合会", "連盟"} {
		if strings.HasSuffix(v, s) && utf8.RuneCountInString(v) > utf8.RuneCountInString(s) {
			return false
		}
	}
	return true
}

// validDeptContactName は personNameDeptContactRe の値を検証する。「<辞書の姓> <辞書の名>」を要求する
// （部署名の後ろの「総務 担当」「企画 調整」のような一般語の組は名の辞書を通らない）。
func validDeptContactName(v string) bool {
	f := strings.Fields(strings.TrimSpace(v))
	if len(f) != 2 || !validSpacedSurnameGiven(v) || !notOrgName(v) {
		return false
	}
	return dict.IsGivenName(f[1]) && !dict.IsCommonWord(f[1]) && !dict.IsCommonWord(f[0]+f[1])
}
