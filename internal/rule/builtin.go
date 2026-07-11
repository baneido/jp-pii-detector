package rule

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/baneido/jp-pii-detector/internal/checksum"
	"github.com/baneido/jp-pii-detector/internal/dict"
)

// dg は数字エンティティ用の境界ガード付きパターンを生成する。
// 前後が数字でないことを保証する（RE2 は lookaround 非対応のため
// キャプチャグループで切り出す）。
func dg(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9])(` + core + `)(?:[^0-9]|$)`)
}

// dgNoAlnum は dg と同じ境界ガードに加え、前後の ASCII 英字も除外する。
// hex ハッシュや UUID など英数字トークンの内部に偶然現れた数字列を、
// 独立した番号として切り出さないために使う。
func dgNoAlnum(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9A-Za-z])(` + core + `)(?:[^0-9A-Za-z]|$)`)
}

// dgNoDigitBeforeNoAlnumHyphenAfter は左側は数字連結だけを除外し、右側は ASCII
// 英数字・ハイフン連結を除外する。電話番号のように ASCII ラベル直後へ値が続く
// "smartphone090..." は拾いつつ、UUID のようなハイフン区切りトークン内部は
// 除外するために使う。
func dgNoDigitBeforeNoAlnumHyphenAfter(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9])(` + core + `)(?:[^0-9A-Za-z-]|$)`)
}

// dgNoAlnumHyphen は英数字とハイフンで連結されたトークンの内部を除外する。
// UUID のようなハイフン区切り識別子の一部を、番号として切り出さないために使う。
func dgNoAlnumHyphen(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9A-Za-z-])(` + core + `)(?:[^0-9A-Za-z-]|$)`)
}

// dgNoSlash は dg と同じ境界ガードに加え、直前のスラッシュも除外する。
// URL のパス区切り（例: /articles/4608392522393）を数字列の一部と
// みなして誤検出するのを防ぐ。
func dgNoSlash(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9/])(` + core + `)(?:[^0-9]|$)`)
}

// dgNoSlashAlnumHyphen は dgNoSlash と dgNoAlnumHyphen を組み合わせた
// 境界ガード。URL パス直後の数字列と、英数字・ハイフン連結トークン内部を除外する。
func dgNoSlashAlnumHyphen(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9A-Za-z/-])(` + core + `)(?:[^0-9A-Za-z-]|$)`)
}

// ag は英数字エンティティ用の境界ガード付きパターンを生成する。
func ag(core string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[^0-9A-Za-z])(` + core + `)(?:[^0-9A-Za-z]|$)`)
}

// rejectSeparatedDigitGroup は、候補の直前または直後に separators のいずれかと
// 指定桁数の数字グループが隣接する場合だけ棄却する ValidateLine を返す。共有境界
// ガードを厳しくすると、独立した別番号や年が隣接しただけでも全数値ルールが偽陰性
// になるため、長い区切り数字トークンの部分一致が問題になる新規パターンにだけ使う。
func rejectSeparatedDigitGroup(separators string, widths ...int) func(string, int, int) bool {
	hasRejectedWidth := func(width int) bool {
		for _, rejected := range widths {
			if width == rejected {
				return true
			}
		}
		return false
	}
	return func(line string, start, end int) bool {
		if start > 0 && strings.ContainsRune(separators, rune(line[start-1])) {
			i := start - 2
			last := i
			for i >= 0 && line[i] >= '0' && line[i] <= '9' {
				i--
			}
			if hasRejectedWidth(last - i) {
				return false
			}
		}

		if end < len(line) && strings.ContainsRune(separators, rune(line[end])) {
			i := end + 1
			first := i
			for i < len(line) && line[i] >= '0' && line[i] <= '9' {
				i++
			}
			if hasRejectedWidth(i - first) {
				return false
			}
		}
		return true
	}
}

// stripSeparators は番号表記の区切り文字（ハイフン・半角スペース・ドット・
// 丸括弧）を除去する。マイナンバー・クレジットカードの呼び出しはこれらの
// 区切り文字を元々捕捉しない（正規表現側にハイフン・空白しか含まない）ため、
// ドット・丸括弧の追加は無効化に影響しない。電話番号（括弧市外局番・
// ドット区切り携帯）と運転免許（ハイフン区切り 4-4-4）の新パターンが
// この拡張に依存する。
func stripSeparators(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '-', ' ', '.', '(', ')':
			return -1
		}
		return r
	}, s)
}

const (
	kanji    = `\x{4E00}-\x{9FFF}\x{3005}` // 漢字 + 々
	hiragana = `\x{3041}-\x{3096}`
	// katakana はカタカナ + ー に加え、結合濁点・半濁点（\x{3099}\x{309A}）を含む。
	// normalize.Line は半角カナの濁点・半濁点（ﾞﾟ）を 1 ルーン = 1 ルーンの不変条件を
	// 保つため未合成の結合文字のまま全角カナへ畳む（例: ｶﾞ → カ + \x{3099}）ため、
	// この文字クラスに含めないと半角カナ由来の濁音・半濁音を含む値
	// （フリガナ: ﾔﾏﾀﾞ 等）が氏名・住所の値パターンから漏れる。jp-pii-detector:ignore
	katakana = `\x{30A1}-\x{30FA}\x{30FC}\x{3099}\x{309A}`

	// hiraganaNoParticle は hiragana から助詞「で・に・は・を」を除いた文字クラス
	// （\x{3067}=で \x{306B}=に \x{306F}=は \x{3092}=を を穴あきで除外）。市区町村と
	// banchiDash（マーカーなしダッシュ連結）の間のギャップ専用。ひらがな全体を
	// 除外すると「丸の内2-1-5」「霞が関3-2-1」のような実在住所（間に「の」「が」を
	// 含む）まで棄却してしまうため、スコア表記「3-2で勝利」・ISO 日付「2025-07-02に」
	// のように市区町村へ直結しやすい助詞だけを狙って除く。「はりまや町」等ひらがなを
	// 含む町名がダッシュ表記住所の直前に来るケースの FN は許容範囲とする
	// （現状でもマーカーなしダッシュ形は取れておらず実質的後退は限定的）。
	hiraganaNoParticle = `\x{3041}-\x{3066}\x{3068}-\x{306A}\x{306C}-\x{306E}\x{3070}-\x{3091}\x{3093}-\x{3096}`

	// kanjiDigits は漢数字の位取り表現に使う文字（〇・一〜九・十・百・千）。
	kanjiDigits = `〇一二三四五六七八九十百千`

	digitRuleRequireContextWindow = 40

	// banchiMarked は番地表現（丁目→番地→号）のうち、丁目・番・号のいずれかの
	// マーカーが必ず含まれる形だけを最後まで捕捉する終端パターン。次を捕捉:
	//   2丁目10番7号 / 2丁目10-7 / 10番地の7 / 10番7号 / 2丁目（番地なし）
	// 構造は「N丁目」＋「任意の番地ブロック（番/号/ダッシュ連結）」、または
	// マーカー付き番地ブロック単独（丁目なし）。号は終端（号の後ろは続かない）と
	// することで、号の後ろの部屋番号・電話番号や、丁目の後ろの「階」の数字など、
	// 単位もダッシュも伴わない裸の数字列を吸収しない。RE2 は線形時間なので
	// 連鎖長による破滅的バックトラックは起きない。
	banchiMarked = `(?:` +
		`\d{1,4}丁目(?:\d{1,4}番地?(?:の?\d{1,4})?号?|\d{1,4}号|\d{1,4}(?:-\d{1,4})+)?` +
		`|\d{1,4}番地?(?:の?\d{1,4})?号?` +
		`|\d{1,4}号` +
		`)`

	// banchiDash はマーカー（丁目/番/号）を伴わない、ダッシュ連結のみの番地表現
	// （2-1-5 等）。丁目/番/号のような明示的な番地マーカーが一切ないため、
	// 市区町村名の直後に他の数字列（試合のスコア「3-2」・ISO 日付
	// 「2025-07-02」等）が来ただけの文を誤って番地とみなしやすい。そのため
	// jp-address / jp-address-high-recall では、このパターン専用に市区町村と
	// の間のギャップを hiraganaNoParticle に制限し、末尾が実在する暦日形なら
	// 棄却する Validate（notCalendarDateBanchi）を追加で必須にする。
	banchiDash = `\d{1,4}(?:-\d{1,4})+`

	// banchiKanji は漢数字表記の番地（神南一丁目十九番十一号 等）。ASCII 数字は
	// 使わずダッシュ形も持たない（ダッシュ連結は漢数字では実質使われないため）。
	// 丁目・番・号のいずれかのマーカーを必ず含む。
	banchiKanji = `(?:` +
		`[` + kanjiDigits + `]{1,6}丁目(?:[` + kanjiDigits + `]{1,6}番地?(?:の?[` + kanjiDigits + `]{1,6})?号?)?` +
		`|[` + kanjiDigits + `]{1,6}番地?(?:の?[` + kanjiDigits + `]{1,6})?号?` +
		`|[` + kanjiDigits + `]{1,6}号` +
		`)`
)

// 氏名ルールで共用する部分パターン。正規化済みの行を前提とする
// （全角コロン `：`・全角イコール `＝`・全角スペースは正規化で半角になる）。
var (
	// personNameLabelJP は値の前に来る氏名系の日本語ラベル（語そのものが人物を
	// 表す強いラベル）。氏名漢字 / 氏名カナ / お名前カナ 等は末尾サフィックスで吸収する。
	// 「フリガナ」は濁点未合成形（フリ(?:ガ|カ\x{3099})ナ）も許す。半角カナ由来の
	// 「ﾌﾘｶﾞﾅ」は normalize.Line で「フリカ」+ 結合濁点 + 「ナ」（ガではなくカ+結合濁点）
	// に畳まれるため、これがないと半角カナ表記のラベル行を取りこぼす。
	personNameLabelJP = `(?:氏名|お名前|ご氏名|名前|姓名|フリ(?:ガ|カ\x{3099})ナ|ふりがな|フルネーム|` +
		`患者名|契約者名|利用者名|顧客名|会員名|申込者名|請求先名|受取人|担当者名)(?:漢字|カナ|かな)?`
	// personNameLabelASCIIStrong は語そのものが「人」を表す ASCII キー。
	// 辞書照合なしで検出する（収録外の人名も拾う）。user_name / account_name /
	// contact_name はハンドル名・システム名でありうるため強ラベルには入れず、
	// 辞書照合つきの弱ラベル側で扱う。normalize は ASCII の大小文字を変換しない
	// ため、`(?i:...)` で FULL_NAME: / CustomerName: のような大文字・キャメル
	// ケース表記も拾う（#48）。あわせて PrefilterLiterals 側
	// （containsAnyLiteral）も大文字小文字を無視しないと、正規表現に到達する前に
	// 行がスキップされてしまう点に注意。
	personNameLabelASCIIStrong = `(?i:full_?name|customer_?name|patient_?name|applicant_?name)`
	// personNameBoundary は強・弱ラベル共通の前方境界。識別子連結文字
	// （英数字・_）に加えて漢字・かなも禁止し、登録名前 / 会社名 / 変数名前 のように
	// ラベル語が複合名詞の一部になっているケースを除外する。
	personNameBoundary = `(?:^|[^` + kanji + hiragana + katakana + `0-9A-Za-z_])`
	// personNameBareNameBoundary は裸の name ラベル専用の前方境界。上記に加えて
	// kebab-case の `-` と dotted key の `.` も禁止し、project-name / company-name /
	// project.name など末尾が name の非人物キーを誤検出しないようにする。
	personNameBareNameBoundary = `(?:^|[^-.` + kanji + hiragana + katakana + `0-9A-Za-z_])`
	// personNameSep はラベルと値の区切り。キー側の閉じ引用符（"name":）と
	// 値側の開き引用符・括弧（: "山田" / ：「山田」）の両方を許容する。
	personNameSep = `["']?\s*[:=]\s*["'「『（(]?\s*`
	// personNameSepOrBracket は personNameSep に加え、コロン・イコールなしで
	// 鉤括弧・丸括弧が値に直結するケース（ご氏名「田中美咲」等。jp-pii-detector:ignore）も区切りとして
	// 許容する。強いラベル（personNameLabelJP / personNameLabelASCIIStrong）専用。
	// 弱いラベル（姓・名 等）は日常語との衝突を避けるため personNameSep のまま
	// コロン必須とする（#48）。
	personNameSepOrBracket = `(?:` + personNameSep + `|[「『（(])`
	// personNameValue は氏名の値（漢字・かな・カナ列。任意で半角スペース
	// 区切りの 2 語）。強いラベル用に 2 文字以上を要求する。カタカナ中黒
	// （U+30FB、「ジョン・スミス」等）も値の一部として許容する（#48）。
	// 既知の軽微な限界: `氏名: 山田 様` のように値の後に敬称が続くと、敬称まで
	// マスク対象に含まれうる（検出の成否・評価には影響しない表示上の過剰取り込み）。
	personNameValue = `[` + kanji + hiragana + katakana + `\x{30FB}]{2,12}` +
		`(?:[ ][` + kanji + hiragana + katakana + `\x{30FB}]{1,12})?`
	// personNameValueShort は弱いラベル（姓・名の単一フィールド）用。1 文字も
	// 捕捉し、長さ・人名らしさの最終判断は validSurnameField 等の検証器に委ねる。
	personNameValueShort = `[` + kanji + hiragana + katakana + `]{1,12}` +
		`(?:[ ][` + kanji + hiragana + katakana + `]{1,12})?`
	romajiNameValue = `[A-Za-z]{2,15}[ ][A-Za-z]{2,15}`
	// romajiNameEndBoundary は 2 語の直後にさらに英数字・_ が続くケースを除外する。
	// RE2 は lookahead 非対応のため、値の外側で終端・記号・空白終端を消費する。
	romajiNameEndBoundary = `(?:$|[^0-9A-Za-z_[:space:]]|[[:space:]]+(?:$|[^0-9A-Za-z_[:space:]]))`
	// personNameValueShortFallback は弱いラベルの見逃し（FN）修正用フォールバック。
	// personNameValueShort は末尾の助詞・敬称も同じ文字クラスに含まれるため貪欲に
	// 取り込んでしまい（例: 「山田さんへ連絡」を丸ごと 1 語として捕捉）、姓名辞書に
	// 一致せず検出を落とすことがある。この派生パターンは非貪欲キャプチャ（group 1、
	// 自前で括弧を持つ。呼び出し側で personNameValueShort のように再度括弧で
	// 囲まないこと）の直後に personNameTrailingParticles のいずれかが続くことを
	// 必須にすることで、最初に助詞・敬称が現れた位置で先頭セグメントを切り出す
	// （1 回だけ剥がす）。助詞・敬称自体は non-capturing のため検出スパンには
	// 含まれない。通常どおり値の直後に助詞が続かない行では一致せず、
	// personNameValueShort 側のパターンのみが有効になる。
	personNameValueShortFallback = `([` + kanji + hiragana + katakana + `]{1,12}?)` +
		`(?:` + strings.Join(personNameTrailingParticles, "|") + `)`
)

// personNameTrailingParticles は氏名の値の直後に続きうる助詞・敬称
// （personNameValueShortFallback 専用）。値と地続きの文（「山田さんへ連絡」等）を
// 辞書照合前に切り離すために使う。
var personNameTrailingParticles = []string{
	// 敬称
	"さん", "様", "殿", "先生", "先輩", "君", "ちゃん", "氏",
	// 複合助詞（単独助詞より先に試しても結果に影響しないが、可読性のため先に置く）
	"とは", "では", "でも", "には", "からは", "までは", "より",
	// 単独助詞
	"から", "まで", "は", "が", "を", "に", "で", "と", "も", "の", "へ", "や", "な", "か",
}

// person-name ルールの一部パターンは、辞書検証ありの Medium 判定と辞書照合
// なしの Low 判定を同一正規表現の 2 枚組（twin）で持つ。twin 間で正規表現
// オブジェクトを共有し、二重コンパイルを避けるためパッケージ変数として
// 定義する。
var (
	// personNameStrongLabelRe は強いラベル（氏名系日本語ラベル / full_name 等）
	// 用パターン。personNameSepOrBracket により、コロンなしで鉤括弧が値に直結する
	// ケースにも対応する（#48、詳細は personNameSepOrBracket のコメント参照）。
	personNameStrongLabelRe = regexp.MustCompile(
		personNameBoundary +
			`(?:` + personNameLabelJP + `|` + personNameLabelASCIIStrong + `)` +
			personNameSepOrBracket +
			`(` + personNameValue + `)`,
	)
	// personNameUserNameRe は姓名どちらが入るか不定の ASCII キー
	// （user_name / account_name / contact_name）用パターン。
	personNameUserNameRe = regexp.MustCompile(
		personNameBoundary +
			`(?:user_?name|account_?name|contact_?name)` +
			personNameSep +
			`(` + personNameValueShort + `)`,
	)
	// personNameBareRe は裸の name ラベル用パターン。`(?i:name)` により
	// NAME: / Name: のような大文字表記も拾う（#48）。
	personNameBareRe = regexp.MustCompile(
		personNameBareNameBoundary +
			`(?i:name)` +
			personNameSep +
			`(` + personNameValueShort + `)`,
	)
	// personNameUserNameFallbackRe / personNameBareFallbackRe は上記 2 つの
	// 見逃し修正フォールバック版（personNameValueShortFallback を使い、値の
	// 直後に助詞・敬称が続くケースを拾う）。twin と同様、Medium/Low の 2
	// Pattern で正規表現オブジェクトを共有する。
	personNameUserNameFallbackRe = regexp.MustCompile(
		personNameBoundary +
			`(?:user_?name|account_?name|contact_?name)` +
			personNameSep +
			personNameValueShortFallback,
	)
	personNameBareFallbackRe = regexp.MustCompile(
		personNameBareNameBoundary +
			`name` +
			personNameSep +
			personNameValueShortFallback,
	)
)

// personNamePlaceholders は氏名の値として現れるダミー語（人名ではない）。
// 値の正規表現が末尾の仮名を貪欲に取り込む（未定 → 未定です）ため、完全一致では
// なく部分一致（strings.Contains）で棄却する。
var personNamePlaceholders = []string{
	"未定", "不明", "該当なし", "該当無し", "なし", "無し", "非公開", "匿名",
	"名無し", "未設定", "未記入", "記入例", "空欄", "テスト", "サンプル", "ダミー",
}

// notPlaceholderName は氏名候補 v がプレースホルダ（未定・テスト等）を含まない
// ことを返す。氏名ルールの Validate に使い、ラベルはあるが値がダミーの行
// （氏名: 未定 / 氏名: 未定です など）を棄却する。
func notPlaceholderName(v string) bool {
	v = strings.TrimSpace(v)
	for _, s := range personNamePlaceholders {
		if strings.Contains(v, s) {
			return false
		}
	}
	return true
}

// personNameOrgSuffixes は組織・団体名の語尾。高再現率の敬称パターンで
// 「田中商事様」「○○株式会社様」のような組織名を棄却するために使う。
// 単漢字の語尾（部・課・店・社 等）は姓（阿部・服部 等）と衝突するため含めない。
var personNameOrgSuffixes = []string{
	"株式会社", "有限会社", "合同会社", "合資会社", "会社", "商事", "商店", "銀行",
	"信用金庫", "工業", "産業", "製作所", "事務所", "病院", "医院", "大学", "学校",
	"学園", "学院", "協会", "財団", "法人", "組合", "支店", "本店", "支社", "本社",
}

// notOrgName は氏名候補 v が組織名の語尾で終わらないことを返す。敬称（様/さん）は
// 人物を強く示すため、辞書照合（allowlist）ではなく組織語尾の除外（denylist）で
// 偽陽性を抑え、辞書未収録の実在人名を巻き添えで落とさないようにする。
func notOrgName(v string) bool {
	v = strings.TrimSpace(v)
	for _, s := range personNameOrgSuffixes {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	return true
}

// personNameRoleSuffixes は職業・役割・部署を表す語尾。敬称パターンの実測 FP
// である 本屋さん・運転手さん（職業）、取引先様・関係者様・保護者様・御中様
// （役割語）、経理部殿・総務課殿（部署）を棄却するために使う。単漢字の語尾
// （屋・部・課 等）は姓（阿部・服部・土屋・北条 等）と衝突するため、
// honorificPersonNameValid は辞書照合（dict.IsPersonName）を先に評価する順序で
// この denylist を適用し、辞書収録済みの衝突姓を巻き添えにしない。
var personNameRoleSuffixes = []string{
	"者", "員", "手", "屋", "師", "士", "長", "生", "部", "課", "係", "室", "先", "中",
}

// notRoleWord は氏名候補 v が職業・役割・部署の語尾（personNameRoleSuffixes）で
// 終わらないことを返す。
func notRoleWord(v string) bool {
	v = strings.TrimSpace(v)
	for _, s := range personNameRoleSuffixes {
		if strings.HasSuffix(v, s) {
			return false
		}
	}
	return true
}

// honorificPersonNameValid は敬称（様/さん/氏/殿）付き漢字氏名候補 v の検証器。
// 組織名の語尾（notOrgName）は常に棄却する。姓名辞書（dict.IsPersonName）に
// 一致すれば単漢字語尾の姓（阿部・土屋 等）でも許可し、辞書に無い値だけを
// 職業・役割・部署語尾（notRoleWord）で追加検証する。この評価順序により、
// 辞書未収録の実在人名（denylist 非該当）は引き続き Medium で検出される
// （detect_test.go の「敬称 + 辞書外の姓」ケースを参照）。
func honorificPersonNameValid(v string) bool {
	v = strings.TrimSpace(v)
	if !notOrgName(v) {
		return false
	}
	if dict.IsPersonName(v) {
		return true
	}
	return notRoleWord(v)
}

// 弱いラベル（姓・名・last_name 等）の値検証。1 文字の単独要素は日常語と
// 衝突しやすいため、単独要素は 2 文字以上かつラベル種別（姓/名）に一致する
// 場合のみ許可する。「姓 + 名」に分割できる完全な氏名はラベル種別を問わず許可する。
//
// 例外: 姓ラベル（姓/名字/苗字/last_name）専用の validSurnameField のみ、
// 辞書収録済みの実在 1 文字姓（林・森・原・東 等 75 件）を allow1CharSurname
// で許可する（#48）。名フィールド・姓名不定フィールドは「名: 東」のような
// 方角語等との衝突を避けるため現状どおり 1 文字を許可しない。
func validSurnameField(v string) bool { return validNameFieldOpt(v, true, false, true) }
func validGivenField(v string) bool   { return validNameFieldOpt(v, false, true, false) }

// validFullNameField は姓・名のいずれか、または姓+名に分割できる値を許可する
// （name / user_name など姓名どちらが入るか不定のフィールド用）。
func validFullNameField(v string) bool { return validNameFieldOpt(v, true, true, false) }

func validNameFieldOpt(v string, allowSurname, allowGiven, allow1CharSurname bool) bool {
	// 半角カナ由来の濁点・半濁点（結合文字のまま normalize.Line を通過している）を
	// 辞書照合前に合成する（ﾀﾞ → タ+結合濁点 → ダ）。
	v = dict.ComposeKana(strings.TrimSpace(v))
	if dict.SplitsAsFullName(v) {
		return true
	}
	if len([]rune(v)) < 2 {
		return allow1CharSurname && allowSurname && dict.IsSurname(v)
	}
	return (allowSurname && dict.IsSurname(v)) || (allowGiven && dict.IsGivenName(v))
}

// validRomajiFullName は person-name-romaji ルールの値検証。値は半角スペース
// 区切りの英単語 2 語（語順不問）で、小文字化したうえで一方がローマ字姓辞書、
// もう一方がローマ字名辞書に収録されている場合のみ true を返す（Yamada Taro /
// Taro Yamada のどちらの語順も許可する）。単語が 2 つでない場合は false。
func validRomajiFullName(v string) bool {
	fields := strings.Fields(v)
	if len(fields) != 2 {
		return false
	}
	a, b := strings.ToLower(fields[0]), strings.ToLower(fields[1])
	return (dict.IsRomajiSurname(a) && dict.IsRomajiGivenName(b)) ||
		(dict.IsRomajiGivenName(a) && dict.IsRomajiSurname(b))
}

// bankNameSuffixes は銀行名の業態サフィックス（この語の直前に実在する金融機関名が
// 続く場合のみ、bankNameCandidateRe が候補として切り出す）。
var bankNameSuffixes = []string{"銀行", "信用金庫", "信用組合", "信金", "信組", "労働金庫", "ろうきん", "農協"}

// bankNameCandidateRe は「(金融機関名候補)(業態サフィックス)」の形を切り出す
// アンカー正規表現。キャプチャグループ 1 はサフィックスを含む候補で、
// ContextPattern.ValidateSuffixes が辞書に一致する最長の接尾部分を検証する。
// これにより、銀行名の直前に助詞や熟語が空白なしで続く日本語文でも、
// 完全な金融機関名（例: "三菱UFJ銀行"）だけを回収できる。
// 数百〜千語規模の辞書を Context の線形走査に混ぜないための専用経路
// （internal/detect の ContextPattern・bankNameSuffixes の Literals ゲートを参照）。
var bankNameCandidateRe = regexp.MustCompile(
	`([` + kanji + hiragana + katakana + `A-Za-z]{1,12}(?:銀行|信用金庫|信用組合|信金|信組|労働金庫|ろうきん|農協))`,
)

// bankCodeAccountRe は「金融機関コード4桁-支店コード3桁-口座番号7桁」の
// 構造から金融機関コードだけを候補として切り出す。候補は ValidBankCode で
// 実在性を検証するため、単なる 4-3-7 桁のバージョン番号等は文脈にならない。
// 支店辞書は Issue #61 のスコープ外なので、支店コードは桁構造だけを見る。
var bankCodeAccountRe = regexp.MustCompile(
	`(?:^|[^0-9])(\d{4})[- ]\d{3}[- ]\d{7}(?:[^0-9]|$)`,
)

func isYuchoBankName(s string) bool {
	return s == "ゆうちょ銀行"
}

// validStrictFullName は姓+名の分割（dict.FullNameSplit）が成立し、かつ名側の
// 成分が 2 文字以上であることを要求する、姓名辞書検証のうち最も厳しい検証。
// 単独の姓・名一致（渋谷・大和・本田のような地名・企業名と同形の姓を含む）は
// 許可しない。person-name-structured（クロスライン、structured.go）と裸の
// name ラベルで使う（同一行の他フィールドより誤検出リスクが高いため）。
func validStrictFullName(v string) bool {
	v = strings.TrimSpace(v)
	_, given, ok := dict.SplitFullName(v)
	return ok && len([]rune(given)) >= 2
}

// validPersonNameFullSplit は姓+名の分割（dict.FullNameSplit）が成立する
// 場合のみ許可する。担当ラベル（person-name-high-recall）の Medium パターン用。
// 単独の姓一致（SurnameOnly）は validPersonNameSurnameOnly 側の Low パターンで
// 別途扱うため、ここには含めない（渋谷・大和・本田のような地名・企業名と同形の
// 姓が Medium に一律昇格するのを避ける）。
func validPersonNameFullSplit(v string) bool {
	return dict.MatchPersonName(strings.TrimSpace(v)) == dict.FullNameSplit
}

// validPersonNameSurnameOnly は単独の姓一致（dict.SurnameOnly）の場合のみ許可
// する。担当ラベル（person-name-high-recall）の Low パターン用。
func validPersonNameSurnameOnly(v string) bool {
	return dict.MatchPersonName(strings.TrimSpace(v)) == dict.SurnameOnly
}

// digitRuleNegativeContext / digitRuleUnitAdjacentNegativeContext と、各語が
// どの近接判定クラス（通貨接頭・通貨接尾・カウンタ接尾・採番ラベル接頭・
// 汎用窓語）に属するかの分類は internal/rule/negative_context.go に同居する
// （ClassifyNegativeKeyword が単一の情報源）。internal/detect 側はこの分類を
// 呼ぶだけで、語彙を独自に分類しない。

// jp-birthdate ルールで共用する部分パターン。
var (
	// birthdateLabel はラベル部（日本語 2 語 + 英語表記ゆれ）。英語ラベルは
	// "dob" のような短い略記が adobe / wardrobe 等の単語内部に現れうるため、
	// personNameBoundary と同じ前方境界（非英数字・非漢字かな）を英語側にのみ
	// 付与してスコープを絞る（`adobe:` 等は前方が英字のため境界で除外される）。
	// 日本語ラベルには前方境界を課さない。「対象者の生年月日:」のような、
	// ラベル直前に助詞・漢字が続く既存の使い方をそのまま許容するため。
	// 大小文字は英語ラベルのみ区別しない（日本語ラベルに大小文字はないため無関係）。
	birthdateLabel = `(?:生年月日|誕生日|` + personNameBoundary +
		`(?i:birth\s?date|birthday|date[_ ]of[_ ]birth|dob))`
	// birthdateLabelSep はラベルと値の区切り。ラベル直後に「(西暦)」等の注記が
	// 挟まる表記を許容してから、既存の区切り（コロン/イコール）を許容する。
	birthdateLabelSep = `(?:[(（][^)）]{1,10}[)）])?\s*[:=]?\s*`
)

// Builtin は組み込みルール一覧を返す。
func Builtin() []Rule {
	return []Rule{
		{
			ID:              "jp-my-number",
			Description:     "マイナンバー（個人番号）",
			Prefilter:       PrefilterDigit,
			Context:         []string{"マイナンバー", "個人番号", "mynumber", "my number", "my_number"},
			NegativeContext: digitRuleUnitAdjacentNegativeContext,
			Validate:        validMyNumber,
			Patterns: []Pattern{
				{Re: dgNoAlnumHyphen(`\d{12}`), Base: Medium},
				// 前後にハイフンが続く場合はクレジットカード等の
				// 4-4-4-4 グループの一部とみなして除外する。
				{Re: dgNoAlnumHyphen(`\d{4}-\d{4}-\d{4}`), Base: Medium},
				// 空白区切り（4-4-4 / 6-6）。stripSeparators は元々半角スペースを
				// 除去するため Validate 側の変更は不要。
				{Re: dgNoAlnumHyphen(`\d{4} \d{4} \d{4}`), Base: Medium,
					ValidateLine: rejectSeparatedDigitGroup(" ", 4)},
				{Re: dgNoAlnumHyphen(`\d{6} \d{6}`), Base: Medium,
					ValidateLine: rejectSeparatedDigitGroup(" ", 6)},
			},
		},
		{
			ID:          "jp-phone-number",
			Description: "電話番号（携帯・固定・IP・国際表記）",
			Prefilter:   PrefilterDigit,
			Context:     []string{"電話", "携帯", "連絡先", "tel", "phone", "fax", "mobile", "denwa"},
			// 桁ベースの区切りなし固定電話パターンは業務 ID・型番等と衝突しやすいため、
			// 金額・数量・連番 ID 文脈で棄却する。既存パターンは従来の検出挙動を
			// 維持するため IgnoreNegativeContext で適用対象から外す。
			NegativeContext:      digitRuleNegativeContext,
			RequireContextWindow: digitRuleRequireContextWindow,
			Validate:             validPhone,
			Patterns: []Pattern{
				// 区切りあり携帯・IP 電話（060/070/080/090/050）
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0[5-9]0-\d{4}-\d{4}`), Base: High, IgnoreNegativeContext: true},
				// 空白・ドット区切り携帯・IP 電話
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0[5-9]0[ .]\d{4}[ .]\d{4}`), Base: Medium,
					ValidateLine: rejectSeparatedDigitGroup(" .", 1)},
				// 区切りなし携帯・IP 電話
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0[5-9]0\d{8}`), Base: Medium, IgnoreNegativeContext: true},
				// 区切りあり固定電話（市外局番 2〜5 桁）。末尾は 3〜4 桁を許容し、
				// フリーダイヤル・ナビダイヤル等の末尾 3 桁表記も拾う。
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{1,4}-\d{1,4}-\d{3,4}`), Base: Medium, IgnoreNegativeContext: true},
				// 括弧市外局番（市外局番の直後に市内局番を括弧書き、または
				// 市外局番全体を括弧で囲む表記）。
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{1,4}\(\d{1,4}\)\d{4}`), Base: Medium},
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`\(0\d{1,4}\)\s?\d{1,4}-?\d{4}`), Base: Medium},
				// 区切りなし固定電話（10 桁）。裸の \d{10} は型番・伝票番号等との
				// 衝突が非常に多く単独では出せないため、コンテキストキーワード必須
				// （RequireContext）にした上で validPhone が市外局番辞書
				// （dict.ValidAreaCode）で先頭一致の実在性を検証する。
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{9}`), Base: Medium, RequireContext: true},
				// 国際表記 +81
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`\+81[- ]?\d{1,4}[- ]?\d{1,4}[- ]?\d{3,4}`), Base: High, IgnoreNegativeContext: true},
			},
		},
		{
			ID:              "jp-postal-code",
			Description:     "郵便番号",
			Prefilter:       PrefilterDigit,
			Context:         []string{"郵便番号", "郵便", "住所", "postal", "zipcode", "zip code", "〒"},
			NegativeContext: digitRuleUnitAdjacentNegativeContext,
			// RequireContextWindow: 未設定（行全体探索）だと、廃番の品番のような
			// NNN-NNNN 形式の数字列が、行のずっと離れた場所にある「郵便」の
			// 部分一致だけで Medium 成立してしまっていた（#54）。他の digit 系
			// RequireContext ルール（jp-bank-account 等）と同じ
			// digitRuleRequireContextWindow に揃える。
			RequireContextWindow: digitRuleRequireContextWindow,
			// 7 桁完全一致（ビットセット生成済みのとき。未生成なら上位 3 桁実在チェック）。
			Validate: dict.ValidPostalCode,
			Patterns: []Pattern{
				{Re: dg(`〒\s?\d{3}-?\d{4}`), Base: High},
				{Re: dg(`\d{3}-\d{4}`), Base: Medium, RequireContext: true},
			},
		},
		{
			// 数字番地（マーカー付き / ダッシュ連結のみ）。漢数字番地は Prefilter が
			// 異なる（数字を含まない行もありうる）ため、同一 ID "jp-address" の
			// 第 2 エントリとして下に分けて定義する（detect.New は ID セットで
			// disable 判定するため、同一 ID の複数エントリは両立する）。
			ID:          "jp-address",
			Description: "住所（都道府県〜番地）",
			Prefilter:   PrefilterDigit,
			Context:     []string{"住所", "所在地", "自宅", "address", "居住"},
			Patterns: []Pattern{
				// マーカー付き番地（丁目/番/号）。既存どおり緩いギャップを許す
				// （マーカー自体が強いシグナルのため誤検出リスクが低い）。
				{Re: regexp.MustCompile(
					`((?:北海道|東京都|京都府|大阪府|[` + kanji + `]{2,3}県)` +
						`[` + kanji + hiragana + katakana + `0-9A-Za-z]{1,20}?[市区町村]` +
						`[` + kanji + hiragana + katakana + `0-9-]{0,30}?` +
						banchiMarked + `)`,
				), Base: High},
				// マーカーなしダッシュ連結（2-1-5 等）。市区町村直後の助詞「で・に・
				// は・を」を挟んだスコア表記・ISO 日付の誤検出を避けるため、
				// ギャップを助詞抜き文字クラスに制限し、さらに末尾が実在する
				// 暦日形（YYYY-MM-DD）なら Validate で棄却する。
				{Re: regexp.MustCompile(
					`((?:北海道|東京都|京都府|大阪府|[` + kanji + `]{2,3}県)` +
						`[` + kanji + hiragana + katakana + `0-9A-Za-z]{1,20}?[市区町村]` +
						`[` + kanji + hiraganaNoParticle + katakana + `0-9-]{0,30}?` +
						banchiDash + `)`,
				), Base: High, Validate: notCalendarDateBanchi},
			},
		},
		{
			// 漢数字番地（神南一丁目十九番十一号 等）。ASCII 数字を含まない行にも
			// マッチさせる必要があるため、既存の PrefilterDigit ではなく
			// PrefilterCJK + 都道府県リテラルで別途プリフィルタする。
			ID:                "jp-address",
			Description:       "住所（都道府県〜番地）",
			Prefilter:         PrefilterCJK,
			PrefilterLiterals: []string{"都", "道", "府", "県"},
			Context:           []string{"住所", "所在地", "自宅", "address", "居住"},
			Patterns: []Pattern{
				{Re: regexp.MustCompile(
					`((?:北海道|東京都|京都府|大阪府|[` + kanji + `]{2,3}県)` +
						`[` + kanji + hiragana + katakana + `0-9A-Za-z]{1,20}?[市区町村]` +
						`[` + kanji + hiragana + katakana + `0-9-]{0,30}?` +
						banchiKanji + `)`,
				), Base: High},
			},
		},
		{
			ID:          "jp-address-high-recall",
			Description: "住所（都道府県なし・高再現率）",
			Prefilter:   PrefilterDigit,
			Context:     []string{"住所", "所在地", "勤務地", "勤務先", "自宅", "address"},
			// 市区町村として辞書に実在しない語（「通学区域」等の一般語尾）を
			// municipality と誤認した検出を棄却する。既定の jp-address には
			// 付けない（郡省略・表記揺れで実在住所を drop する FN リスクが
			// 高再現率でない既定ルールでは相対的に大きいため）。
			Validate: dict.MunicipalitySuffixMatch,
			Patterns: []Pattern{
				{Re: regexp.MustCompile(
					`(?:住所|所在地|勤務地|勤務先|自宅|address)?\s*[:=]?\s*(` +
						`[` + kanji + hiragana + katakana + `]{1,15}[市区町村]` +
						`[` + kanji + hiragana + katakana + `0-9-]{0,30}?` +
						banchiMarked + `)`,
				), Base: Medium},
				{Re: regexp.MustCompile(
					`(?:住所|所在地|勤務地|勤務先|自宅|address)?\s*[:=]?\s*(` +
						`[` + kanji + hiragana + katakana + `]{1,15}[市区町村]` +
						`[` + kanji + hiraganaNoParticle + katakana + `0-9-]{0,30}?` +
						banchiDash + `)`,
				), Base: Medium, Validate: notCalendarDateBanchi},
			},
		},
		{
			ID:          "email-address",
			Description: "メールアドレス",
			Prefilter:   PrefilterAt,
			Validate:    validEmail,
			Patterns: []Pattern{
				// 右境界ガード `(?:[^A-Za-z0-9_%+:-]|$)` を捕捉グループの外に置き、
				// user@gmail.com_suffix / user@gmail.com+suffix のように直後が
				// 英数字・_ % + - : で続く（メールアドレスの一部ではない）部分一致を
				// 棄却する。`:` は git@github.com:owner/repo.git のような
				// scp 形式の SSH URL をメールとして切り出さないために含める。
				// `.` は除外集合に含めないため、文末ピリオド
				// （…は user@example.com.）は従来どおり検出できる。
				{Re: regexp.MustCompile(`(?:^|[^A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:[^A-Za-z0-9_%+:-]|$)`), Base: High},
			},
		},
		{
			ID:              "credit-card",
			Description:     "クレジットカード番号（Luhn + ブランドプレフィックス検証）",
			Prefilter:       PrefilterDigit,
			Context:         []string{"クレジット", "カード番号", "credit", "card"},
			NegativeContext: digitRuleUnitAdjacentNegativeContext,
			Validate: func(m string) bool {
				return checksum.CreditCard(stripSeparators(m))
			},
			// パターンを 2 つに分ける理由:
			//  1) 区切りなし・区切りあり両方を拾うが、直前がスラッシュの
			//     数字列（URL パスの記事 ID 等）は誤検出を避けるため除外する。
			//  2) 区切り（- または空白）を 1 つ以上含むカード番号は、直前が
			//     スラッシュでも拾う（区切り付きの数字列はまず URL ID ではない）。
			// この割り切りにより、スラッシュ直後の「区切りなし」カード番号は
			// 検出できないが、URL の記事 ID と区別できないため意図的に許容する。
			Patterns: []Pattern{
				{Re: dgNoSlashAlnumHyphen(`\d(?:[- ]?\d){12,18}`), Base: High},
				{Re: dgNoAlnumHyphen(`\d(?:[- ]?\d){0,5}[- ]\d(?:[- ]?\d){6,17}`), Base: High},
			},
		},
		{
			ID:          "jp-drivers-license",
			Description: "運転免許証番号",
			Prefilter:   PrefilterDigit,
			Context: []string{"免許", "driver_license", "drivers_license", "driver's license",
				"drivers license", "driver license", "license no", "license number", "licence"},
			NegativeContext:      digitRuleNegativeContext,
			RequireContextWindow: digitRuleRequireContextWindow,
			Validate:             validDriversLicense,
			Patterns: []Pattern{
				{Re: dg(`\d{12}`), Base: High, RequireContext: true},
				// ハイフン区切り（4-4-4）。dgNoAlnumHyphen で UUID 等のハイフン区切り
				// トークンの内部を除外する（dg ではなく my-number と同じ境界ガード）。
				{Re: dgNoAlnumHyphen(`\d{4}-\d{4}-\d{4}`), Base: High, RequireContext: true},
			},
		},
		{
			ID:              "jp-passport",
			Description:     "旅券（パスポート）番号",
			Prefilter:       PrefilterDigit,
			Context:         []string{"パスポート", "旅券", "passport"},
			NegativeContext: digitRuleUnitAdjacentNegativeContext,
			Validate:        validPassport,
			Patterns: []Pattern{
				// 英字 2 桁と数字 7 桁の間の半角スペースは任意（例: "AB 1234567"）。
				// 英字は小文字表記（ab1234567 等）も許容する（#42 プローブ FN 解消）。
				{Re: ag(`[A-Za-z]{2} ?\d{7}`), Base: High, RequireContext: true,
					ValidateLine: rejectSeparatedDigitGroup(" ", 1)},
			},
		},
		{
			ID:                   "jp-pension-number",
			Description:          "基礎年金番号",
			Prefilter:            PrefilterDigit,
			Context:              []string{"年金", "pension", "nenkin"},
			NegativeContext:      digitRuleNegativeContext,
			RequireContextWindow: digitRuleRequireContextWindow,
			Validate:             validPensionNumber,
			Patterns: []Pattern{
				// ハイフン・半角スペースいずれの区切りも許容する（Validate は
				// stripSeparators で区切り文字を除いた上で判定する）。
				{Re: dg(`\d{4}[- ]?\d{6}`), Base: High, RequireContext: true,
					ValidateLine: rejectSeparatedDigitGroup(" ", 1)},
			},
		},
		{
			ID:          "jp-residence-card",
			Description: "在留カード番号・特別永住者証明書番号",
			Prefilter:   PrefilterDigit,
			// 特別永住者証明書番号は在留カードと同一形式（英字2+数字8+英字2）のため
			// パターンは共用し、Context に特別永住者証明書関連の語を追加して拾う。
			Context: []string{"在留", "residence card", "zairyu",
				"特別永住", "特別永住者証明書", "永住者証明書", "special permanent"},
			NegativeContext: digitRuleUnitAdjacentNegativeContext,
			Validate:        validResidenceCard,
			Patterns: []Pattern{
				// 英字は小文字表記（ab12345678cd 等）も許容する（#42 プローブ FN 解消）。
				{Re: ag(`[A-Za-z]{2}\d{8}[A-Za-z]{2}`), Base: High, RequireContext: true},
			},
		},
		{
			ID:          "jp-bank-account",
			Description: "銀行口座番号",
			Prefilter:   PrefilterDigit,
			Context:     []string{"口座", "普通預金", "当座預金", "支店番号", "account number", "account_no", "bank account", "kouza"},
			// 実在の銀行・信用金庫・労働金庫名（"三菱UFJ銀行" 等）を辞書照合で
			// 検証し、既存の 8 語 Context だけでは拾えない「銀行名＋支店＋
			// 普通/当座」のような典型的な記載形式（例: [銀行名] 渋谷支店
			// 普通 [7桁の口座番号]）を検出可能にする。1,100 語規模の辞書を
			// Context の線形走査に混ぜないため、bankNameSuffixes の安価な
			// リテラルゲートを通過した行だけ bankNameCandidateRe を評価する
			// （詳細は internal/dict/bank_names.go・docs/development.md）。
			// 注: このコメント自体が dogfooding で自己検出されないよう、
			// 具体的な銀行名・口座番号の実値は書かない。
			ContextPatterns: []ContextPattern{
				{Re: bankNameCandidateRe, Validate: dict.IsBankName, ValidateSuffixes: true, Literals: bankNameSuffixes},
				{Re: bankCodeAccountRe, Validate: dict.ValidBankCode},
			},
			NegativeContext:      digitRuleNegativeContext,
			RequireContextWindow: digitRuleRequireContextWindow,
			Validate:             validBankAccount,
			Patterns: []Pattern{
				{Re: dg(`\d{7}`), Base: Medium, RequireContext: true, ValidateLine: rejectYuchoAccountSuffix},
			},
		},
		{
			ID:          "jp-yucho-account",
			Description: "ゆうちょ銀行 記号番号",
			Prefilter:   PrefilterDigit,
			Context:     []string{"ゆうちょ", "郵便貯金", "記号", "日本郵政", "郵便局", "yucho", "japan post", "japan post bank"},
			// 銀行名候補の専用経路は「ゆうちょ銀行」表記だけを文脈として使う。
			// 任意の銀行名は通常の銀行口座ルール（jp-bank-account）側の文脈で扱う。
			ContextPatterns: []ContextPattern{
				{Re: bankNameCandidateRe, Validate: isYuchoBankName, ValidateSuffixes: true, Literals: bankNameSuffixes},
			},
			NegativeContext:      digitRuleNegativeContext,
			RequireContextWindow: digitRuleRequireContextWindow,
			Validate:             validYuchoAccount,
			Patterns: []Pattern{
				// 記号（5 桁、先頭は必ず "1"）＋番号（7〜8 桁、末尾は必ず
				// "1"）をハイフンで相関させた表記。記号・番号の
				// ラベルが別々に書かれる形式（記号: … 番号: …）は将来の拡張対象
				// とし、誤検出リスクを抑えるためこの表記に限定する。チェック
				// ディジットの具体式は未確認のため（要追加調査）、全桁同一の
				// ダミー値のみ Validate で棄却する。
				{Re: dgNoAlnumHyphen(`1\d{4}-\d{6,7}1`), Base: High, RequireContext: true},
			},
		},
		{
			// jp-health-insurance より前に登録する。両ルールの 8 桁パターンが
			// 同一行・同一箇所で重なった場合、resolveOverlaps は「同信頼度・
			// 同じ長さなら先勝ち」で決着するため、ラベル直結という強いシグナルを
			// 持つ jp-birthdate 側を優先させる（TestBirthdateWinsOverHealthInsuranceOverlap）。
			ID:          "jp-birthdate",
			Description: "生年月日（ラベル付き）",
			Prefilter:   PrefilterDigit,
			// 形式（西暦・和暦・区切りなし8桁）だけでなく、実在する暦日かを検証する。
			// 2023-99-99 や 2023-02-29（閏年でない）などを棄却する。
			Validate: validBirthdate,
			Patterns: []Pattern{
				// 区切りあり形式。西暦 4 桁、または和暦（元号の漢字表記 or
				// 明治/大正/昭和/平成/令和を表す単字アルファベット略記 M/T/S/H/R）＋
				// 年（1-2 桁の数字、または改元年を表す「元」）。
				{Re: regexp.MustCompile(
					birthdateLabel + birthdateLabelSep +
						`((?:(?:19|20)\d{2}|(?:明治|大正|昭和|平成|令和|[MTSHR])(?:元|\d{1,2}))[年/.-]\d{1,2}[月/.-]\d{1,2}日?)`,
				), Base: Medium},
				// ラベル直結・区切りなしの 8 桁連結（YYYYMMDD）。DB エクスポート等で
				// 最頻出の表記。月日のレンジをパターン側で絞り込み、ラベルへの
				// 直結を必須とすることで、処理日・有効期限など無関係な 8 桁列や、
				// ラベルなしの裸 8 桁を拾わない。
				{Re: regexp.MustCompile(
					birthdateLabel + birthdateLabelSep +
						`((?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))(?:[^0-9]|$)`,
				), Base: Medium},
			},
		},
		{
			ID:                   "jp-health-insurance",
			Description:          "健康保険 保険者番号・被保険者番号",
			Prefilter:            PrefilterDigit,
			Context:              []string{"保険者番号", "被保険者", "保険証", "health insurance", "hokensha"},
			NegativeContext:      digitRuleNegativeContext,
			RequireContextWindow: digitRuleRequireContextWindow,
			Validate:             validHealthInsurance,
			Patterns: []Pattern{
				{Re: dg(`\d{8}`), Base: Medium, RequireContext: true},
			},
		},
		{
			ID:                   "jp-employment-insurance",
			Description:          "雇用保険被保険者番号",
			Prefilter:            PrefilterDigit,
			Context:              []string{"雇用保険", "被保険者番号", "koyou hoken", "employment insurance"},
			NegativeContext:      digitRuleNegativeContext,
			RequireContextWindow: digitRuleRequireContextWindow,
			Validate:             validEmploymentInsurance,
			Patterns: []Pattern{
				// 区切りあり（4桁-6桁-1桁）は書式自体が固有の形状のため
				// コンテキストなしで High とする（電話番号の区切りあり表記と同様）。
				{Re: dg(`\d{4}-\d{6}-\d`), Base: High},
				// 区切りなし 11 桁は桁数のみが手がかりのため周辺語を必須にする。
				{Re: dg(`\d{11}`), Base: Medium, RequireContext: true},
			},
		},
		{
			ID:                   "jp-kaigo-insurance",
			Description:          "介護保険被保険者番号",
			Prefilter:            PrefilterDigit,
			Context:              []string{"介護保険", "要介護", "被保険者証", "kaigo hoken"},
			NegativeContext:      digitRuleNegativeContext,
			RequireContextWindow: digitRuleRequireContextWindow,
			Validate:             validKaigoInsurance,
			Patterns: []Pattern{
				// 10 桁は基礎年金番号（4桁-6桁、区切りなしでも同じ 10 桁形状）と
				// 桁数が衝突するが、両ルールとも RequireContext:true のため
				// 「介護保険」「年金」いずれか異なるキーワードが同一 40 ルーン窓に
				// 共存しない限り同時発火しない。
				{Re: dg(`\d{10}`), Base: Medium, RequireContext: true},
			},
		},
		{
			ID:          "jp-juminhyo-code",
			Description: "住民票コード",
			Prefilter:   PrefilterDigit,
			Context:     []string{"住民票コード", "住民票", "juminhyo"},
			// 検査数字の公式算式を一次資料から独立検証できていないため、
			// 未検証の算式で実在値を棄却せず、11 桁の形状と周辺語を必須にする。
			// 全桁同一のみ、明らかなダミー値として除外する。
			Validate: func(m string) bool {
				return !checksum.AllSame(m)
			},
			Patterns: []Pattern{
				{Re: dg(`\d{11}`), Base: High, RequireContext: true},
			},
		},
		{
			ID:          "jp-invoice-number",
			Description: "適格請求書発行事業者登録番号（インボイス登録番号）",
			Prefilter:   PrefilterDigit,
			Context:     []string{"登録番号", "適格請求書", "インボイス", "invoice number", "invoice registration"},
			// T + 13 桁の末尾 13 桁を法人番号の検査用数字（checksum.CorporateNumber）
			// で検証する。個人事業主分の登録番号も法人番号と同一の採番体系
			// （検査用数字を含む 13 桁）のため同じ検証式が使える。
			Validate: func(m string) bool {
				return checksum.CorporateNumber(strings.TrimPrefix(m, "T"))
			},
			Patterns: []Pattern{
				// T + 13 桁（法人は法人番号と同一の 13 桁、個人事業主等は
				// 別途 13 桁が採番される）。
				{Re: ag(`T\d{13}`), Base: Medium, RequireContext: true},
			},
		},
		{
			ID:          "person-name",
			Description: "氏名（ラベル付き）",
			Prefilter:   PrefilterCJK,
			// ラベル語を 1 つも含まない行（日本語コメント等）は正規表現走査を
			// まるごとスキップする（ホットパス最適化）。"フリガナ" は半角カナ
			// 「ﾌﾘｶﾞﾅ」が normalize.Line で濁点未合成のまま畳まれた形
			// （フリ・カ・結合濁点・ナ。"フリガナ" の合成済み ガ ではない）。
			PrefilterLiterals: []string{
				"名", "姓", "苗字", "フリガナ", "フリガナ", "ふりがな", "フルネーム", "受取人", "name",
			},
			// プレースホルダ（未定・該当なし・テスト等）の値はすべてのパターンで
			// 棄却する。非人物キー（project_name 等）はラベルの前方境界で除外する。
			Validate: notPlaceholderName,
			Patterns: []Pattern{
				// 強いラベル: 氏名系の日本語ラベルと、語そのものが「人」を表す
				// 複合 ASCII キー（full_name / customer_name 等）。前方境界
				// personNameBoundary で漢字・かな直後（登録名前: 等）を除外する。
				// JSON/YAML のキー引用符（"氏名":）と値の引用符・括弧にも対応。
				// personNameSepOrBracket により、コロンなしで鉤括弧が値に直結する
				// ケースにも対応する（#48、詳細は personNameSepOrBracket のコメント参照）。
				// 同一正規表現の 2 枚組（twin）: 値が姓名辞書に一致すれば Medium
				// （既定 min_confidence=medium で報告）、一致しない収録外の実在
				// 人名は Low のまま拾う。resolveOverlaps が同一スパンで信頼度の
				// 高い Medium を残す。
				{Re: personNameStrongLabelRe, Base: Medium, Validate: dict.IsPersonName},
				{Re: personNameStrongLabelRe, Base: Low},
				// 弱いラベル: 姓側（姓・名字・苗字・last_name）。validSurnameField が
				// 姓名辞書で検証済み（単独要素は 2 文字以上の姓、または姓+名に
				// 分割できる氏名のみ許可）のため、Base は Medium。
				{Re: regexp.MustCompile(
					personNameBoundary +
						`(?:姓|名字|苗字|last_?name)` +
						personNameSep +
						`(` + personNameValueShort + `)`,
				), Base: Medium, Validate: validSurnameField},
				// 姓側の見逃し修正フォールバック: 値の直後に助詞・敬称が続き辞書照合に
				// 失敗するケース（姓: 山田さんへ連絡 jp-pii-detector:ignore）で、
				// 先頭セグメントだけを切り出して再照合する
				// （personNameValueShortFallback を参照）。plain パターンと
				// 同じ validSurnameField で検証されるため Base も同じ Medium。
				{Re: regexp.MustCompile(
					personNameBoundary +
						`(?:姓|名字|苗字|last_?name)` +
						personNameSep +
						personNameValueShortFallback,
				), Base: Medium, Validate: validSurnameField},
				// 弱いラベル: 名側（名・first_name）。validGivenField が姓名辞書で
				// 検証済み（単独要素は 2 文字以上の名、または姓+名に分割できる
				// 氏名のみ許可。1 文字名（学・実 等）と姓（名: 田中）は棄却）
				// のため、Base は Medium。
				{Re: regexp.MustCompile(
					personNameBoundary +
						`(?:名|first_?name)` +
						personNameSep +
						`(` + personNameValueShort + `)`,
				), Base: Medium, Validate: validGivenField},
				// 名側の見逃し修正フォールバック（姓側と同様）。
				{Re: regexp.MustCompile(
					personNameBoundary +
						`(?:名|first_?name)` +
						personNameSep +
						personNameValueShortFallback,
				), Base: Medium, Validate: validGivenField},
				// 弱いラベル: 姓名どちらが入るか不定の ASCII キー
				// （user_name / account_name / contact_name）。ハンドル名・システム名
				// （管理者・共有アカウント 等）は姓名辞書で棄却する。同一正規表現の
				// 2 枚組: 姓+名に分割できる値のみ Medium（dict.SplitsAsFullName）。
				// name フィールドの値が単独の姓（大和 等、地名・一般名詞と同形になり
				// やすい）のみの場合は Low のまま昇格させない。
				{Re: personNameUserNameRe, Base: Medium, Validate: dict.SplitsAsFullName},
				{Re: personNameUserNameRe, Base: Low, Validate: validFullNameField},
				// 姓名不定 ASCII キーの見逃し修正フォールバック（姓側と同様）。plain
				// パターンと同じ 2 枚組の判定基準（dict.SplitsAsFullName /
				// validFullNameField）に揃える。
				{Re: personNameUserNameFallbackRe, Base: Medium, Validate: dict.SplitsAsFullName},
				{Re: personNameUserNameFallbackRe, Base: Low, Validate: validFullNameField},
				// 裸の name ラベル。kebab-case / dotted key（project-name /
				// project.name 等）の末尾 name を誤検出しないよう前方境界で `-` `.`
				// も禁止し、値は姓名辞書で検証する（name: 株式会社 等を棄却）。
				// `(?i:name)` により NAME: / Name: のような大文字表記も拾う（#48）。
				// user_name 系と同様、姓+名に分割できる値のみ Medium とし、
				// 値が単独の姓（大和 等）のみの場合は Low のまま昇格させない。
				{Re: personNameBareRe, Base: Medium, Validate: dict.SplitsAsFullName},
				{Re: personNameBareRe, Base: Low, Validate: validFullNameField},
				// 裸の name ラベルの見逃し修正フォールバック（user_name 系と同様）。
				{Re: personNameBareFallbackRe, Base: Medium, Validate: dict.SplitsAsFullName},
				{Re: personNameBareFallbackRe, Base: Low, Validate: validFullNameField},
			},
		},
		{
			ID:                "person-name-high-recall",
			Description:       "氏名（敬称・担当者アンカー付き・高再現率）",
			Prefilter:         PrefilterCJK,
			PrefilterLiterals: []string{"担当", "宛名", "連絡先", "様", "さん", "氏", "殿"},
			Validate:          notPlaceholderName,
			Patterns: []Pattern{
				// 担当者・宛名・連絡先ラベル。敬称のような強い人物シグナルが無いため、
				// 組織名・部署名（営業部 等）の誤検出を姓名辞書（allowlist）で抑える。
				// 収録外の実在人名は取りこぼす（コンパクト辞書による再現率の上限）。
				//
				// 同一正規表現に対し、判定根拠（dict.MatchPersonName）ごとに信頼度を
				// 作り分ける 2 Pattern に分割する（Medium 一括を回避）。姓+名の分割
				// （FullNameSplit）は強い根拠として Medium のまま。単独の姓一致
				// （SurnameOnly）は地名・企業名と同形の姓（渋谷・大和・本田 等）を
				// 含みうるため Low に降格する。単独の名一致（GivenOnly）は根拠が弱く
				// 誤検出リスクが高いためどちらのパターンにも含めない（取りこぼす）。
				{Re: regexp.MustCompile(
					`(?:担当|担当者|宛名|連絡先)` + personNameSep +
						`([` + kanji + `]{2,8}(?:[ ][` + kanji + `]{1,8})?)`,
				), Base: Medium, Validate: validPersonNameFullSplit},
				{Re: regexp.MustCompile(
					`(?:担当|担当者|宛名|連絡先)` + personNameSep +
						`([` + kanji + `]{2,8}(?:[ ][` + kanji + `]{1,8})?)`,
				), Base: Low, Validate: validPersonNameSurnameOnly},
				// 敬称アンカー（氏名の漢字表記 + 様/さん/氏/殿）。組織語尾
				// （notOrgName）は常に棄却し、辞書一致（dict.IsPersonName）を
				// 優先しつつ、辞書に無い値は職業・役割・部署の語尾 denylist
				// （notRoleWord）でも検証する（honorificPersonNameValid）。
				// これにより辞書未収録の実在人名（denylist 非該当）は Medium の
				// まま検出しつつ、職業語・役割語・部署語を伴う実測 FP を追加で
				// 棄却する。
				{Re: regexp.MustCompile(
					`(?:^|[^` + kanji + hiragana + katakana + `])` +
						`([` + kanji + `]{2,8})(?:様|さん|氏|殿)`,
				), Base: Medium, Validate: honorificPersonNameValid},
				// 敬称アンカー（ひらがな・カタカナの氏名 + 様/さん/氏/殿）。この
				// 文字種には notRoleWord のような語尾 denylist が効かないほど
				// 日常語との衝突が多いため、辞書一致必須の allowlist 方式
				// （dict.IsPersonName）で検証する。辞書収録済みのひらがな名
				// （例: さくら）は敬称付きでも検出され、日常語（例: たくさん・
				// みなさん）は辞書不在で棄却される。カタカナ人名は辞書未収録の
				// ため、外来語名の敬称付き表記はこのパターンでは解消しない
				// （辞書拡充は別課題として切り離す）。
				{Re: regexp.MustCompile(
					`(?:^|[^` + kanji + hiragana + katakana + `])` +
						`([` + hiragana + katakana + `]{2,8})(?:様|さん|氏|殿)`,
				), Base: Medium, Validate: dict.IsPersonName},
			},
		},
		{
			ID:          "person-name-structured",
			Description: "氏名（構造化・ラベルと値が別行・高再現率）",
			Prefilter:   PrefilterCJK,
			// このルールは単一行パターンを持たない。フォーム形式で氏名ラベルと値が
			// 別の行に分かれるケース（氏名:\n山田太郎 等）を、detect.ScanContent の
			// クロスライン走査（scanCrossLineNames）が CrossLineNameLabelRe /
			// CrossLineNameValueRe / ValidCrossLineName を使って検出する。
			// 高再現率モードでのみ有効（HighRecallRuleIDs）。
		},
		{
			ID:          "person-name-romaji",
			Description: "氏名（ローマ字表記・高再現率）",
			// 値が ASCII 文字（[A-Za-z]）のみのため PrefilterCJK は使えない
			// （person-name ルールは CJK 前提でこの行を素通りする）。代わりに
			// PrefilterLiterals の "name" だけでホットパスを絞る。
			Prefilter:         PrefilterNone,
			PrefilterLiterals: []string{"name"},
			// 姓辞書・名辞書の共起（語順不問）を必須にする。ヘボン式の表記揺れ
			// （Itô/Itoh/Ito 等）や、辞書外の英単語（Ken/Kai/Mori 等）との衝突は
			// 網羅できないため、初期実装は高再現率モード限定（既定オフ、
			// HighRecallRuleIDs）とする。
			Validate: validRomajiFullName,
			Patterns: []Pattern{
				// 強い ASCII ラベル（full_name / customer_name 等）。
				{Re: regexp.MustCompile(
					personNameBoundary +
						personNameLabelASCIIStrong +
						personNameSep +
						`(` + romajiNameValue + `)` + romajiNameEndBoundary,
				), Base: Medium},
				// 裸の name ラベル。kebab-case / dotted key は除外する
				// （personNameBareNameBoundary、person-name ルールと同様）。
				{Re: regexp.MustCompile(
					personNameBareNameBoundary +
						`name` +
						personNameSep +
						`(` + romajiNameValue + `)` + romajiNameEndBoundary,
				), Base: Medium},
			},
		},
	}
}

// validMyNumber はマイナンバー（個人番号）の検査用数字に加え、ダミー値で
// よく使われる「先頭ゼロ埋め連番」（0000001 等）を棄却する。マイナンバーは
// 日付を符号化しないため、先頭 8 桁が暦日に見えることだけでは棄却しない。
func validMyNumber(m string) bool {
	d := stripSeparators(m)
	if !checksum.MyNumber(d) {
		return false
	}
	if checksum.IsZeroPaddedSequential(d) {
		return false
	}
	return true
}

// validDriversLicense は運転免許証番号（12 桁）のダミー値を棄却する。
// 検査用数字アルゴリズムは公式に非公開のためリバースエンジニアリング由来の
// 実装は採用せず、先頭桁（公安委員会コードは 10 以上 = 先頭桁が 0 でない）と、
// 全桁同一・ゼロ埋め連番のみを見る。
func validDriversLicense(m string) bool {
	// ハイフン区切り（4-4-4）はセパレータを除去してから判定する（区切り文字は
	// チェックディジットではないため、AllSame 判定がハイフンに惑わされて
	// "0000-0000-0000" のようなプレースホルダを通過させないようにする）。連続
	// 12 桁は元々区切りを含まないため stripSeparators は無害（no-op）。
	d := stripSeparators(m)
	return d != "" && d[0] != '0' && !checksum.AllSame(d) && !checksum.IsZeroPaddedSequential(d)
}

// validBankAccount は銀行口座番号（7 桁）の全桁同一のダミー値を棄却する。
// 口座番号自体は検査用数字を持たず、連番も実在しうるため、それ以上の
// ヒューリスティックは適用しない。
func validBankAccount(m string) bool {
	return !checksum.AllSame(m)
}

// validPensionNumber は基礎年金番号（4 桁-6 桁）の全桁同一のダミー値を棄却する。
// マッチはハイフン・半角スペースいずれの区切りも含みうるため、AllSame 判定が
// 区切り文字に惑わされて "0000-000000" のようなプレースホルダを通過させない
// よう stripSeparators で除去してから判定する。年金番号自体は検査用数字を
// 持たず、連番も実在しうるため、それ以上のヒューリスティックは適用しない。
func validPensionNumber(m string) bool {
	return !checksum.AllSame(stripSeparators(m))
}

// validEmploymentInsurance は雇用保険被保険者番号（4桁-6桁-1桁 または区切りなし
// 11桁）の全桁同一のダミー値を棄却する。区切りあり表記のハイフンに AllSame 判定が
// 惑わされないよう stripSeparators で除去してから判定する。検査用数字を持たず、
// 連番も実在しうるため、それ以上のヒューリスティックは適用しない。
func validEmploymentInsurance(m string) bool {
	return !checksum.AllSame(stripSeparators(m))
}

// validKaigoInsurance は介護保険被保険者番号（10 桁）の全桁同一のダミー値を
// 棄却する。検査用数字を持たず、連番も実在しうるため、それ以上の
// ヒューリスティックは適用しない。
func validKaigoInsurance(m string) bool {
	return !checksum.AllSame(m)
}

// rejectYuchoAccountSuffix は、通常の 7 桁口座番号パターンが
// 「ゆうちょ記号5桁-番号7桁」の番号部分だけを拾う隣接汚染を防ぐ。
// ゆうちょ形式全体は jp-yucho-account が専用の文脈と境界で判定する。
func rejectYuchoAccountSuffix(line string, start, _ int) bool {
	if start < 6 || line[start-1] != '-' {
		return true
	}
	symbol := line[start-6 : start-1]
	if symbol[0] != '1' {
		return true
	}
	for i := 1; i < len(symbol); i++ {
		if symbol[i] < '0' || symbol[i] > '9' {
			return true
		}
	}
	return false
}

// validHealthInsurance は健康保険 保険者番号・被保険者番号（8 桁）の全桁同一の
// ダミー値を棄却する。連番も実在しうるため、それ以上のヒューリスティックは
// 適用しない。
func validHealthInsurance(m string) bool {
	return !checksum.AllSame(m)
}

// validPassport は旅券（パスポート）番号（英字 2 + 数字 7）の末尾 7 桁が
// 全桁同一の明らかなダミー値（0000000 等）を棄却する。旅券冊子記号の先頭
// 文字制限（[T,M] 等）は外務省/ICAO の一次情報で裏取りができるまで導入しない
// （docs/detection-methods.md 参照）。
func validPassport(m string) bool {
	if len(m) < 7 {
		return false
	}
	return !checksum.AllSame(m[len(m)-7:])
}

// validResidenceCard は在留カード番号（英 2 + 数 8 + 英 2）のうち、
// 出入国在留管理庁の文字集合仕様で使われない英字 I・O を含む値と、
// 数字 8 桁が全桁同一のダミー値を棄却する。パターン側が小文字表記
// （ab12345678cd 等）も許容するため、I・O 除外判定も大小文字を区別しない
// （i・o も同様に棄却する）。
func validResidenceCard(m string) bool {
	if len(m) != 12 {
		return false
	}
	letters := m[:2] + m[10:]
	if strings.ContainsAny(letters, "IOio") {
		return false
	}
	return !checksum.AllSame(m[2:10])
}

func validPhone(m string) bool {
	d := stripSeparators(strings.TrimPrefix(m, "+"))
	if checksum.AllSame(d) {
		return false
	}
	if strings.HasPrefix(d, "81") {
		// 国番号を除いた市外局番以下は、固定 9 桁 / 携帯・IP 10 桁
		// （先頭 0 なし）。10 桁は携帯・IP のプレフィックス X0 のみ。
		rest := d[2:]
		switch len(rest) {
		case 9:
			return rest[0] != '0'
		case 10:
			return rest[0] >= '5' && rest[0] <= '9' && rest[1] == '0'
		}
		return false
	}
	// 国内表記は先頭 0。固定電話は計 10 桁、11 桁は携帯・IP（0[5-9]0）のみ。
	if len(d) == 0 || d[0] != '0' {
		return false
	}
	switch len(d) {
	case 10:
		if strings.ContainsAny(m, "- ") {
			return d[1] != '0'
		}
		// 区切りなし固定電話は市外局番辞書（dict.ValidAreaCode）で先頭一致の
		// 実在性を検証する。area_codes.txt は seed のため、区切りあり表記では
		// この辞書を必須にしない。
		_, ok := dict.ValidAreaCode(d)
		return ok
	case 11:
		return d[1] >= '5' && d[1] <= '9' && d[2] == '0'
	}
	return false
}

// validYuchoAccount はゆうちょ銀行の記号（5 桁・先頭は必ず "1"）・番号
// （7〜8 桁・末尾 1）がハイフンで相関した表記かを検証する。記号 4 桁目に意味を持つ
// チェックディジット式が存在するとされるが、公開情報からは具体式を確認できな
// かったため（要追加調査）実装していない。全桁同一のダミー値（"11111-1111111"
// 等）だけを明白な非 PII として棄却する。
func validYuchoAccount(m string) bool {
	symbol, number, ok := strings.Cut(m, "-")
	if !ok || len(symbol) != 5 || symbol[0] != '1' ||
		(len(number) != 7 && len(number) != 8) || number[len(number)-1] != '1' {
		return false
	}
	return !checksum.AllSame(symbol) && !checksum.AllSame(number)
}

// birthdateRe は jp-birthdate の区切りあり捕捉値（西暦 4 桁 or 和暦元号＋年・月・日）
// を分解する。グループ: 1=西暦年 / 2=元号（漢字 or 単字アルファベット略記）/
// 3=和暦年（数字、または改元年を表す「元」）/ 4=月 / 5=日。区切りはルールの
// 正規表現と同じ（年→月は [年/.-]、月→日は [月/.-]、末尾 日?）。
var birthdateRe = regexp.MustCompile(
	`^(?:((?:19|20)\d{2})|(明治|大正|昭和|平成|令和|[MTSHR])(元|\d{1,2}))[年/.-](\d{1,2})[月/.-](\d{1,2})日?$`)

// birthdateDigitsRe は jp-birthdate の「ラベル直結・区切りなし8桁」捕捉値
// （YYYYMMDD）を分解する。月日のレンジは検出側の正規表現で既に絞り込み済み
// なので、ここでは西暦年/月/日への分解のみを行う。グループ: 1=西暦年 / 2=月 / 3=日。
var birthdateDigitsRe = regexp.MustCompile(`^((?:19|20)\d{2})(\d{2})(\d{2})$`)

// birthdateEraAbbrev は運転免許証・保険証等の転記で一般的な元号の単字
// アルファベット略記を正式名称へ変換する。
var birthdateEraAbbrev = map[string]string{
	"M": "明治",
	"T": "大正",
	"S": "昭和",
	"H": "平成",
	"R": "令和",
}

// warekiEra は元号の改元年（西暦）と、その元号で取りうる最大の和暦年を返す。
// 改元年を元年（1 年）とし、西暦 = start + 和暦年 - 1 で換算する。令和は
// 現時点で終期がないため正規表現の上限（2 桁）まで許容する。
func warekiEra(era string) (start, maxYear int, ok bool) {
	switch era {
	case "明治": // 1868–1912（明治45年7月30日まで）
		return 1868, 45, true
	case "大正": // 1912–1926（大正15年12月25日まで）
		return 1912, 15, true
	case "昭和": // 1926–1989（昭和64年1月7日まで）
		return 1926, 64, true
	case "平成": // 1989–2019（平成31年4月30日まで）
		return 1989, 31, true
	case "令和": // 2019–（終期なし）
		return 2019, 99, true
	}
	return 0, 0, false
}

// validBirthdate は捕捉した生年月日が実在する暦日かを検証する。形式上は
// 成立しても暦として無効な値（2023-99-99 / 2023-02-29 / 昭和65年… 等）を棄却する。
// 未来日や年齢の妥当性までは判定しない（信頼度ではなく検出可否のみを扱うため）。
// まず区切りなし8桁（YYYYMMDD）として解釈を試み、ダメなら区切りあり形式
// （西暦 or 和暦、単字アルファベット略記・元年を含む）として解釈する。
func validBirthdate(m string) bool {
	if sub := birthdateDigitsRe.FindStringSubmatch(m); sub != nil {
		year, _ := strconv.Atoi(sub[1])
		month, _ := strconv.Atoi(sub[2])
		day, _ := strconv.Atoi(sub[3])
		return validCalendarDate(year, month, day)
	}
	sub := birthdateRe.FindStringSubmatch(m)
	if sub == nil {
		return false
	}
	var year int
	if sub[1] != "" {
		year, _ = strconv.Atoi(sub[1])
	} else {
		era := sub[2]
		if full, ok := birthdateEraAbbrev[era]; ok {
			era = full
		}
		var eraYear int
		if sub[3] == "元" {
			eraYear = 1
		} else {
			eraYear, _ = strconv.Atoi(sub[3])
		}
		start, maxYear, ok := warekiEra(era)
		if !ok || eraYear < 1 || eraYear > maxYear {
			return false
		}
		year = start + eraYear - 1
	}
	month, _ := strconv.Atoi(sub[4])
	day, _ := strconv.Atoi(sub[5])
	return validCalendarDate(year, month, day)
}

// validCalendarDate は西暦の年月日が実在する日付かを time.Date の
// ラウンドトリップで検証する（閏年・月ごとの日数を含む）。
func validCalendarDate(year, month, day int) bool {
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return false
	}
	t := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	return t.Year() == year && int(t.Month()) == month && t.Day() == day
}

// addressTailDashRe は住所候補の末尾にあるダッシュ連結の番地ブロック
// （マーカーなし。banchiDash と同じ形）を切り出す。
var addressTailDashRe = regexp.MustCompile(`(\d{1,4}(?:-\d{1,4})+)$`)

// notCalendarDateBanchi は banchiDash（マーカーなしダッシュ連結）で終わる住所候補
// v の末尾が「YYYY-MM-DD」形の 3 成分で、かつ先頭が西暦として妥当な範囲
// （1900〜2100）かつ実在する暦日のときだけ棄却する（ISO 日付の誤検出対策）。
// 2 成分（例: 大字直番地の「1993-1」）は年月とも解釈できてしまい、その形の FN が
// 大きいため意図的に棄却しない（助詞除外のギャップ制限で実質カバーする）。
func notCalendarDateBanchi(v string) bool {
	m := addressTailDashRe.FindStringSubmatch(v)
	if m == nil {
		return true
	}
	parts := strings.Split(m[1], "-")
	if len(parts) != 3 {
		return true
	}
	year, err1 := strconv.Atoi(parts[0])
	month, err2 := strconv.Atoi(parts[1])
	day, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || year < 1900 || year > 2100 {
		return true
	}
	return !validCalendarDate(year, month, day)
}

// emailDummyWords はメールのダミー値でよく使われるローカル部・ドメイン第 1
// ラベルの語（personNamePlaceholders と同じ「部分一致 denylist」方式で棄却）。
// 既知の限界: 部分一致のため、これらの語を偶然含む実在のローカル部・ドメイン
// （barclays.co.jp の "bar" 等）を巻き添えで棄却しうる。hoge@fuga.co.jp や
// test1@sample.com のような明らかなダミー値の抑制を優先するトレードオフ。
var emailDummyWords = []string{"hoge", "fuga", "dummy", "hogehoge", "sample", "foo", "bar"}

// containsEmailDummyWord は s（ローカル部またはドメイン第 1 ラベル）が
// emailDummyWords のいずれかを部分一致で含むかを返す。
func containsEmailDummyWord(s string) bool {
	s = strings.ToLower(s)
	for _, w := range emailDummyWords {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// validEmail は予約済みドメイン（RFC 2606/6761）・ダミー値でよく使われる
// ローカル部/ドメイン語等を除外する。
func validEmail(m string) bool {
	at := strings.LastIndexByte(m, '@')
	if at <= 0 || at == len(m)-1 {
		return false
	}
	local := m[:at]
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return false
	}
	if !containsASCIIAlnum(local) {
		return false
	}
	domain := strings.ToLower(m[at+1:])
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	if containsEmailDummyWord(local) || containsEmailDummyWord(labels[0]) {
		return false
	}
	tld := labels[len(labels)-1]
	switch tld {
	case "test", "invalid", "localhost", "example", "local":
		return false
	}
	return !slices.Contains(labels, "example") && dict.ValidTLD(tld)
}

// containsASCIIAlnum はローカル部に英数字が 1 文字以上あるかを返す。
// ローカル部はパターンの文字クラス上 ASCII のみのためバイト走査でよい。
func containsASCIIAlnum(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			return true
		}
	}
	return false
}
