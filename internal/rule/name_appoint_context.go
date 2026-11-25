package rule

import (
	"regexp"
)

// 2026-11-25 の公開文書の走査（8,083 件）で、既定モードのルールが取りこぼしていた氏名の形
// （person-name-role-label）。人を指す語のある無作為 1,060 行に人手で付けた正解（姓+名 113 人）のうち、
// 既定モードが拾えたのは 84 人だった。偶数番の行の見逃しだけを設計に使い、奇数番の行は検証用に残した。

// appointTitles は就任・写真の説明・自組織の役員紹介で氏名に付く、組織の長と役員の職名。
const appointTitles = `代表取締役社長|代表取締役会長|代表取締役|取締役社長|取締役会長|専務取締役|常務取締役|取締役|執行役員|` +
	`副社長|社長|副会長|会長|理事長|代表理事|専務理事|常務理事|副学長|学長|総長|校長|園長|館長|所長|病院長|院長|頭取|総裁|` +
	`副市長|市長|副町長|町長|村長|副知事|知事|委員長|支店長|工場長|本部長|部長|監督|主将`

var (
	// personNameGaAppointRe は「<氏名>が社長就任。」「<氏名>氏が代表取締役社長に就任」のように、氏名・「が」・
	// 職名・「就任」が続く形（企業の沿革で実測。「<職名>に<氏名>が就任」は拾えていた）。値は姓 + 名の
	// 完全分割を要求する。
	personNameGaAppointRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|[、はにでてりしの])([` + kanji + `]{3,6}?)(?:氏|さん)?が` +
			`(?:第[0-9一二三四五六七八九十]{1,3}代)?[` + kanji + katakana + `ー]{0,10}?(?:` + appointTitles + `)(?:に|へ)?(?:就任|着任|昇格)`,
	)
	// personNameTitleAppointRe は「取締役交代　<氏名>社長就任」のように、氏名に直結した職名の直後が
	// 「就任」「退任」である形（企業の沿革で実測。既存のパターンは職名の後を区切り・助詞・行末に限っていた）。
	personNameTitleAppointRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|[、はにでの])([` + kanji + `]{3,6}?)(?:` + appointTitles + `)(?:に|を)?(?:就任|退任|着任)`,
	)
	// personNameAppointedDesuRe は「<町内会名>会長に就任した<氏名>です。」のように、就任を述べる連体修飾に
	// 氏名と「です」が続く自己紹介の文（病院の広報誌で実測）。
	personNameAppointedDesuRe = regexp.MustCompile(
		`(?:に就任した|に就任しました|に就任いたしました|に着任した|に着任しました|に着任いたしました|を務める|を務めます|を務めております|を拝命した|を拝命しました)[、 ]?` +
			`(` + spacedKanjiName + `|[` + kanji + `]{3,6})(?:です|と申します|でございます)`,
	)
	// personNameHeadColonHonorificRe は「新院長：<氏名> 先生・就任」のように、施設の長の職名・コロン・氏名の
	// 後に敬称が続く形（病院のお知らせで実測。敬称のない行末の形は personNameHeadColonLineEndRe が拾う）。
	personNameHeadColonHonorificRe = regexp.MustCompile(
		`(?:^|[ ・、])(?:名誉|副|前|元|新|現)?(?:病院長|院長|センター長|施設長|事務長|事務局長|所長|館長|園長|校長|学長|理事長|会長|社長)` +
			`[ ]?[:：][ ]?([` + kanji + `]{3,6}?|` + spacedKanjiName + `)[ ]?(?:先生|氏|さん|医師)(?:[ ・、。（(]|$)`,
	)
	// personNameProgramLabelUjiLineRe は「報告：<氏名>氏」のように、催しの次第の役（報告・講演・司会）・
	// コロン・氏名・敬称だけの行（博物館の研究会の案内で実測。「報告者：」「講師：」は拾えていた）。
	personNameProgramLabelUjiLineRe = regexp.MustCompile(
		`^[ ]*(?:報告|講演|基調講演|特別講演|記念講演|発表|発題|講評|解説|司会|進行|挨拶|あいさつ|コメント|話題提供|趣旨説明|総括|座長|通訳|演奏|指揮|出演|朗読|講話|対談|案内)` +
			`[ ]?[:：][ ]?([` + kanji + `]{3,6}?|` + spacedKanjiName + `)[ ]?(?:氏|さん|先生)[ ]*$`,
	)
	// personNamePhotoCaptionRe は「（左：<氏名> 代表取締役 、中央：<氏名>市長」のように、写真の説明の
	// 位置の語・コロンに氏名と職名・敬称が続く形（企業のお知らせで実測）。
	personNamePhotoCaptionRe = regexp.MustCompile(
		`(?:左|右|中央|左から|右から|左端|右端)[ ]?[:：][ ]?(?:当社|弊社|当院|本学|当行)?[ ]?([` + kanji + `]{3,6}?|` + spacedKanjiName + `)[ ]?` +
			`(?:` + appointTitles + `|` + personTitleWords + `|氏|さん|様|先生|選手)`,
	)
	// personNameSelfOrgAttachedExecRe は「右： 当社 <氏名>代表取締役社長兼 CEO」のように、自組織を指す語・
	// 空白の後の氏名に役員の職名が直結する形（企業のお知らせで実測。「当社 <姓> <名>が」は拾えていた）。
	personNameSelfOrgAttachedExecRe = regexp.MustCompile(
		`(?:当社|弊社|当行|当院|当会|当協会|当法人)[ ]([` + kanji + `]{3,6}?)(?:` + appointTitles + `)`,
	)
	// personNameHeadSpacedLineRe は「学校長 <姓> <名>」のように、行全体が組織の長の職名・空白・空白区切りの
	// 氏名である形（学校だよりの署名で実測。後ろに中黒の飾りが付くことがある）。姓が辞書に無くても、
	// 2 語とも一般語でなければ通す（validHeadSpacedName）。
	personNameHeadSpacedLineRe = regexp.MustCompile(
		`^[ ]*(?:学校長|校長|園長|学長|理事長|病院長|院長|館長|所長|会長|代表取締役社長|代表取締役|社長)[ ]{1,3}(` + spacedKanjiName + `)[ ]*[・]?[ ]*$`,
	)
)

// validHeadSpacedName は personNameHeadSpacedLineRe の値の検証。姓が辞書にある形（validSpacedHonorificName）に
// 加えて、辞書に無い姓でも 2 語のどちらも一般語でなく、職名で終わらない形（ValidUncommonSpacedName）を通す。
// 行全体が「組織の長の職名 + 2 語」である形に限っているので、「院長 外来 担当」のような一般語の組だけが
// 紛れ込む（どちらも一般語なので落ちる）。
func validHeadSpacedName(v string) bool {
	if validSpacedHonorificName(v) {
		return true
	}
	if !notOrgName(v) || !notPlaceholderName(v) || endsWithTitleWord(v) {
		return false
	}
	return ValidUncommonSpacedName(v)
}

// kaigoProviderLabelRe は値の直前（県名などを挟んでもよい）の「指定番号」「事業所番号」。
var kaigoProviderLabelRe = regexp.MustCompile(`(?:指定番号|事業所番号|事業者番号)[ :：]{0,3}[` + kanji + katakana + `ー]{0,6}[ ]{0,2}$`)

// rejectKaigoProviderNumber は「介護保険指定番号 <県名> <10 桁> 号」のように、値の直前のラベルが事業所の
// 指定番号である形を棄却する（2026-11-25 に病院の重要事項説明書で実測した jp-kaigo-insurance の偽陽性。
// 事業所の番号で、個人の被保険者番号ではない）。
func rejectKaigoProviderNumber(line string, start, end int) bool {
	if start < 0 || start > len(line) {
		return true
	}
	lineStart, _ := physicalLineBounds(line, start, start)
	return !kaigoProviderLabelRe.MatchString(line[lineStart:start])
}
