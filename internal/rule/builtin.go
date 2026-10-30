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
// 丸括弧・スラッシュ）を除去する。マイナンバー・クレジットカードの呼び出しは
// これらの区切り文字を元々捕捉しない（正規表現側にハイフン・空白しか
// 含まない）ため、ドット・丸括弧・スラッシュの追加は無効化に影響しない。
// 電話番号（括弧市外局番・ドット区切り携帯）と運転免許（ハイフン区切り
// 4-4-4）の新パターンがドット・丸括弧の拡張に依存する。スラッシュは
// マイナンバーのスラッシュ区切り 6-6 と電話番号のスラッシュ区切り携帯の
// 新パターンが依存する（区切りを除いた 12 桁 / 10-11 桁でチェックディジット・
// 市外局番辞書照合が成立するようにするため）。
func stripSeparators(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '-', ' ', '.', '(', ')', '/':
			return -1
		}
		return r
	}, s)
}

const (
	// kanji は CJK 統合漢字 + 々 に加え、人名で使われる CJK 互換漢字（U+F900–U+FAFF。
	// 「山﨑」の 﨑 U+FA11 は互換ブロックにあるが統合漢字扱いで NFKC でも変わらない）と
	// 拡張 B 以降（U+20000–U+2FA1F。「𠮷田」の 𠮷 U+20BB7 等）を含む。統合漢字の範囲だけだと
	// これらを含む氏名が値パターンの途中で切れ、全ルールモードが取りこぼす（長崎県の
	// 特定商取引法の処分公表で実測）。辞書照合は dict 側で新字体へ畳む（foldNameVariants）。
	kanji    = `\x{4E00}-\x{9FFF}\x{3005}\x{F900}-\x{FAFF}\x{20000}-\x{2FA1F}`
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
	// healthInsurance6DigitContextWindow は国民健康保険の 6 桁保険者番号に
	// 限定した肯定文脈窓。6 桁は日常の金額・件数・コードと衝突しやすいため、
	// 「保険者番号」ラベルが値へほぼ直結する範囲だけを許容する。
	healthInsurance6DigitContextWindow = 12

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

// jp-address-high-recall の一部パターンは、辞書検証ありの Base High 判定と
// 従来どおりの Base Medium 判定を同一正規表現の 2 枚組（twin）で持つ
// （person-name の辞書検証 twin と同じ手法。250 行目付近のコメント参照）。twin 間で
// 正規表現オブジェクトを共有し、二重コンパイルを避けるためパッケージ変数として
// 定義する。マーカー付き番地（addressHighRecallMarkedRe）・漢数字番地
// （addressHighRecallKanjiRe）・マーカーなしダッシュ連結（addressHighRecallDashRe）の
// 3 形すべてに twin を適用する。High 側は、Rule.Validate
// （dict.MunicipalitySuffixMatch、市区町村マッチ）に加えて、市区町村マッチ直後の
// ギャップが ABR 町字マスター由来の実在町字名で始まる場合
// （dict.MunicipalityThenTownMatch）だけ Pattern.Validate を通過する。町字辞書は
// 昇格専用のエビデンスであり、不一致は棄却ではなく Medium への据え置きにしか
// ならないため recall には影響しない。
//
// ダッシュ連結（banchiDash）の High 側だけは、Pattern.Validate に
// dict.MunicipalityThenTownMatch 単体ではなく notCalendarDateBanchiAndRealTown
// （notCalendarDateBanchi との AND 合成。定義・理由は同関数のコメント参照）を使う。
// banchiDash は丁目・番・号のような明示的な番地マーカーを伴わないため、市区町村名の
// 直後に ISO 日付（2025-07-02 等）が来ただけの文を誤って番地とみなしやすく、
// Medium 側は元々 notCalendarDateBanchi でこれを棄却している（banchiDash 自体の
// コメント参照）。この日付棄却を High 側でも維持しないと、市区町村の直後がたまたま
// 実在町字名の場合に ISO 日付が無条件で High 判定になってしまう。
//
// 経緯（PR #127 で意図的に見送った既知の制限を解消）: このダッシュ形 twin は
// 当初見送られていた。TestPromotionContextWindowBoundary（detect_test.go）が
// コンテキスト窓境界の検証に使う固定サンプルの町字部分（旧サンプルの町名）が
// ABR 町字マスターの実在町字名と偶然一致しており、無条件の辞書昇格を追加すると、
// 同テストが検証する「窓のちょうど外側では昇格しない」が辞書昇格経路の混入で
// 壊れるためだった。同テストのサンプル値を、町字マスターに前方一致しない架空の
// 町名（go run で機械確認済み）へ差し替えたことでこの衝突が解消されたため、他の
// 2 形と同じ twin 方式を適用できるようになった
// （internal/detect/address_town_promotion_test.go の
// TestAddressHighRecallDashFormPromotesWithRealTown も参照）。
var (
	addressHighRecallMarkedRe = regexp.MustCompile(
		`(?:住所|所在地|勤務地|勤務先|自宅|address)?\s*[:=]?\s*(` +
			`[` + kanji + hiragana + katakana + `]{1,15}[市区町村]` +
			`[` + kanji + hiragana + katakana + `0-9-]{0,30}?` +
			banchiMarked + `)`,
	)
	addressHighRecallKanjiRe = regexp.MustCompile(
		`(?:住所|所在地|勤務地|勤務先|自宅|address)?\s*[:=]?\s*(` +
			`[` + kanji + hiragana + katakana + `]{1,15}[市区町村]` +
			`[` + kanji + hiragana + katakana + `0-9-]{0,30}?` +
			banchiKanji + `)`,
	)
	// addressHighRecallDashRe はマーカーなしダッシュ連結（banchiDash）用。ギャップは
	// hiraganaNoParticle（助詞抜き）に制限する（banchiDash 自体のコメント参照）。
	// High/Medium 双方の Pattern がこの Re を共有する。
	addressHighRecallDashRe = regexp.MustCompile(
		`(?:住所|所在地|勤務地|勤務先|自宅|address)?\s*[:=]?\s*(` +
			`[` + kanji + hiragana + katakana + `]{1,15}[市区町村]` +
			`[` + kanji + hiraganaNoParticle + katakana + `0-9-]{0,30}?` +
			banchiDash + `)`,
	)
)

// addressLabeledPrefix は jp-address 第 3 エントリ（都道府県なし・ラベル必須）の
// 必須プレフィクス。jp-address-high-recall（上記 addressHighRecall*Re）はここが
// `(?:…)?` の任意だが、この第 3 エントリは既定プロファイルでも安全に使えるよう
// ラベルを必須にする。語彙は既定 jp-address の Context と揃え、
// jp-address-high-recall にだけある勤務地・勤務先は含めない
// （TestHighRecallRulesDisabledByDefault 等が「勤務地: …」を jp-address 側の
// 非検出として固定しているため、この語彙差自体が既存動作の保護になる）。
const addressLabeledPrefix = `(?:住所|所在地|自宅|居住|address)\s*[:=]?\s*`

// jp-address 第 3 エントリが使う部分パターン。市区町村部分・番地部分の文字
// クラス/ギャップは addressHighRecallMarkedRe / addressHighRecallDashRe の定義を
// そのまま再利用し、先頭にだけ addressLabeledPrefix（ラベル必須）を焼き込む。
// キャプチャグループ 1 にはラベルを含めない（値は市区町村から番地まで）。
var (
	// addressLabeledPrefectureAnchoredRe は値が都道府県名で始まるかどうかの判定
	// （addressLabeledMunicipalityValid 専用）。既存 2 エントリ（都道府県あり）が
	// 既に検出する値とこの第 3 エントリが重複して検出しないようにする。重複すると、
	// 同一スパンの複数候補を resolveOverlaps が集約する際にこの新エントリ
	// （Validated な分だけ内部スコアが高い）が既存エントリより優先されてしまい、
	// TestReasonNotValidatedWhenNoValidator 等「マーカー付き番地パターンに
	// Validate は無い」ことを前提にした既存テストを壊す。
	addressLabeledPrefectureAnchoredRe = regexp.MustCompile(
		`^(?:北海道|東京都|京都府|大阪府|[` + kanji + `]{2,3}県)`,
	)
	addressLabeledMarkedRe = regexp.MustCompile(
		addressLabeledPrefix + `(` +
			`[` + kanji + hiragana + katakana + `]{1,15}[市区町村]` +
			`[` + kanji + hiragana + katakana + `0-9-]{0,30}?` +
			banchiMarked + `)`,
	)
	// addressLabeledDashRe はマーカーなしダッシュ連結（banchiDash）用。ギャップは
	// addressHighRecallDashRe と同じ hiraganaNoParticle（助詞抜き）に制限する。
	addressLabeledDashRe = regexp.MustCompile(
		addressLabeledPrefix + `(` +
			`[` + kanji + hiragana + katakana + `]{1,15}[市区町村]` +
			`[` + kanji + hiraganaNoParticle + katakana + `0-9-]{0,30}?` +
			banchiDash + `)`,
	)
)

// addressLabeledMunicipalityValid は jp-address 第 3 エントリのルールレベル
// Validate。値が都道府県名で始まる場合（既存 2 エントリの担当領域）を棄却してから
// dict.MunicipalitySuffixMatch（実在市区町村ゲート。jp-address-high-recall と
// 同じ）を適用する。
func addressLabeledMunicipalityValid(v string) bool {
	if addressLabeledPrefectureAnchoredRe.MatchString(v) {
		return false
	}
	return dict.MunicipalitySuffixMatch(v)
}

// MatchesLabeledNoPrefectureAddress は、正規化済みの行 normalizedLine が
// jp-address 第 3 エントリ（都道府県なし・ラベル必須住所。addressLabeledMarkedRe /
// addressLabeledDashRe とその Validate 群、上記参照）の検出対象になるかを返す。
// internal/corpusv2 が非公開評価コーパスの Want 帰属を決定的に移行する際、
// 「この値を第 3 エントリが検出するか」を判定する唯一の情報源として使うための
// エクスポートで、判定ロジック自体は第 3 エントリが使う正規表現・Validate を
// そのまま再利用する（ここでは再実装しない）。第 3 エントリの正規表現・辞書検証を
// 変更すれば、この関数の判定も自動的に追随する。
//
// 第 3 エントリは同一正規表現の 2 枚組（twin、addressLabeledMarkedRe /
// addressLabeledDashRe それぞれに High/Medium）を持つため、「検出対象になる」は
// twin のどちらか一方でも成立すれば true とする（呼び出し側の要件どおり）。
// 各 twin の Medium 側は Rule.Validate（addressLabeledMunicipalityValid）だけを
// 追加要求し、High 側はそれに加えてさらに厳しい Pattern.Validate
// （dict.MunicipalityThenTownMatch / notCalendarDateBanchiAndRealTown）を要求する
// 真部分集合になっている。そのため Medium 側の条件さえ満たせば twin 全体としては
// 必ず成立しており、High 側の追加検証まで重ねて評価する必要はない
// （マーカー付きは addressLabeledMunicipalityValid、ダッシュ連結はそれに加えて
// notCalendarDateBanchi を満たせば十分）。
//
// 1 行に複数の候補が含まれる場合に備え、FindAllStringSubmatch で候補を尽くす
// （internal/detect.ScanLine の各 Pattern は行全体を逐次走査するため、判定を
// 最初の 1 候補だけに限定すると挙動が食い違いうる）。
func MatchesLabeledNoPrefectureAddress(normalizedLine string) bool {
	for _, m := range addressLabeledMarkedRe.FindAllStringSubmatch(normalizedLine, -1) {
		if addressLabeledMunicipalityValid(m[1]) {
			return true
		}
	}
	for _, m := range addressLabeledDashRe.FindAllStringSubmatch(normalizedLine, -1) {
		if addressLabeledMunicipalityValid(m[1]) && notCalendarDateBanchi(m[1]) {
			return true
		}
	}
	return false
}

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
	// personNameLabelASCIIStrong と同じく `(?i:...)` で大文字・キャメルケース表記
	// （USER_NAME: / UserName: 等）も拾う。normalize は ASCII の大小文字を変換
	// しないため、これがないと同じ ASCII ラベルでも full_name 系だけが大文字表記に
	// 対応し、user_name 系だけ取りこぼすという不整合になる。
	personNameUserNameRe = regexp.MustCompile(
		personNameBoundary +
			`(?i:user_?name|account_?name|contact_?name)` +
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
	// フォールバック版も plain 版と同じ `(?i:...)` を使う。plain 版だけ大文字対応
	// だと、大文字ラベルでは plain 形（値が単独）は拾えるのに、値の直後に助詞・
	// 敬称が続くフォールバック形だけ拾えない、という twin 内での不整合になる。
	personNameUserNameFallbackRe = regexp.MustCompile(
		personNameBoundary +
			`(?i:user_?name|account_?name|contact_?name)` +
			personNameSep +
			personNameValueShortFallback,
	)
	personNameBareFallbackRe = regexp.MustCompile(
		personNameBareNameBoundary +
			`(?i:name)` +
			personNameSep +
			personNameValueShortFallback,
	)
	// personNameRepLabelRe は代表者ラベル（字間スペース付きの「代 表 者」を含む）と、
	// 任意の役職名（代表取締役・代表理事 等）を挟んだ氏名の値を拾う
	// （person-name-role-label）。役職名は値に含めず、続く漢字列だけを捕捉する。
	// 愛媛県の処分公表で「代表者名：<姓>　<名>」（ラベル末尾に「名」が付く表記）を全ルールモードが
	// 取りこぼしたため、「代表者名」「代表者氏名」「代表者の氏名」もラベルとして許容する。
	personNameRepLabelRe = regexp.MustCompile(
		`代[ 　]?表[ 　]?者(?:の?氏名|名)?` + personNameSep +
			`(?:(?:代表取締役社長|代表取締役会長|代表取締役|代表執行役社長|代表執行役|代表理事長|代表理事|代表社員|取締役社長|理事長|社長|会長|院長|学長|組合長)[ 　]*)?` +
			`([` + kanji + `]{2,8}(?:[ ][` + kanji + `]{1,8})?)`,
	)
	// tantoList* は personNameTantoListRe の部品（担当ラベル、姓、読み括弧、区切り、右アンカー）。
	tantoListPrefix  = `担当者?[：:][ ]*`
	tantoListName    = `[` + kanji + `]{1,4}`
	tantoListReading = `(?:[(（][ぁ-ゖー]{1,8}[)）])?`
	tantoListItem    = tantoListName + tantoListReading
	tantoListSep     = `[ ]*[・、,･][ ]*`
	tantoListEnd     = `(?:[ ]*[)）]|[ ]*$|[ ]{2,}|[ ]*(?i:tel)|[ ]*電話)`
	// personNameSpacedValue は空白区切りのラベル（士業の肩書・役員の役職名・当事者ラベル）の
	// 後に続く氏名の値。PDF のレイアウト抽出（pdftotext -layout）では姓と名の間が複数の
	// 空白になるため 1〜3 個を許容する。値の検証（姓名辞書の完全分割）は空白の個数に
	// 依存しない（dict.SplitFullName は空白で 2 フィールドに分ける）。
	personNameSpacedValue = `([` + kanji + `]{2,8}(?:[ ]{1,3}[` + kanji + `]{1,8})?)`
	// personNameProfessionTitleRe は士業・裁判官の肩書の直後に空白区切りで続く氏名を
	// 拾う（person-name-role-label）。判決書の当事者欄「訴訟代理人弁護士　<姓><名>」
	// 「裁判長裁判官　<姓> <名>」や、登記・申請書の「司法書士　<姓><名>」で、コロンの
	// ないラベルを既定ルールが取りこぼす見逃しを公開判決文で実測した。肩書は値に
	// 含めず、空白（全角は正規化で半角になる）の直後の漢字列だけを捕捉する。
	// 「弁護士法人」「弁護士会」のように肩書に漢字が直結する語は空白を要求する
	// ことで対象外にし、値は姓名辞書の完全分割（姓+名）でのみ報告する。
	personNameProfessionTitleRe = regexp.MustCompile(
		`(?:弁護士|弁理士|司法書士|行政書士|税理士|公認会計士|社会保険労務士|裁判官)[ ]+` +
			personNameSpacedValue,
	)
	// personNameContactTitleRe は報道発表資料・お知らせの問合せ先欄に頻出する
	// 「<部署>課長　<姓>　Tel 045-xxx-xxxx」形式（役職 + 空白 + 担当者の姓 + 空白 +
	// 電話ラベル）の氏名を拾う（person-name-role-label）。自治体の記者発表 PDF で
	// 全ルールモードが取りこぼす見逃しを実測した。組織名・役職・電話番号と結合して
	// 特定の職員を識別できるため、姓のみでも個人情報に当たる。役職語と電話ラベルの
	// 両側アンカーを要求し、値は姓名辞書ゲート（姓のみ／姓+名）で検証する。
	// personNameExecTitleRe は法人の代表者の役職名（代表取締役 等）の直後に空白・「である」・
	// 開き括弧で続く氏名を拾う（person-name-role-label）。行政処分の公表文書で
	// 「同社の代表取締役である<姓><名>は」「代表取締役（<姓><名>）に対する業務禁止命令」の
	// ように「代表者：」ラベルを伴わない表記を全ルールモードが取りこぼす見逃しを実測した。
	// 法人役員の氏名も生存する個人を識別でき個人情報に当たる。役職名は代表権を示す語と、
	// 会社法上の役員で登記事項でもある取締役・監査役に限定し（社長・会長単独は含めない）、
	// 値は姓名辞書の完全分割（姓+名）でのみ報告する。市の監督処分の公表 PDF で
	// 「<法人名>   取締役   <姓>   <名>」（pdftotext -layout の複数空白）を全ルールモードが
	// 取りこぼす見逃しを実測したため、姓と名の間の空白は 1〜3 個を許容する
	// （personNameSpacedValue）。
	// 中国地方整備局の監督処分の公表 PDF で、均等割付の役職名が字間スペース付きで抽出された
	// 「<法人名> 代 表 取 締 役   <姓>   <名>」も全ルールモードが取りこぼしたため、
	// 「代 表 取 締 役」（字間の半角スペース 1 個。プリフィルタ「代 表」に一致する形）も許容する。
	personNameExecTitleRe = regexp.MustCompile(
		`(?:代表取締役社長|代表取締役会長|代表取締役副社長|代表取締役|代 表 取 締 役|代表執行役社長|代表執行役|代表理事長|代表理事|代表社員|取締役社長|取締役会長|取締役|監査役)` +
			// 2026-10-30 14:00 に、上場企業の公告・報道発表で「代表取締役社長 ＣＯＯ <姓> <名>」のように
			// 役職名と氏名の間に CEO・COO 等の略称が入る表記を全モードで取りこぼす見逃しを実測した。
			`(?:[ ]*兼?(?:CEO|COO|CFO|CTO|ＣＥＯ|ＣＯＯ|ＣＦＯ|ＣＴＯ))?` +
			`(?:[ ]+|であった|である|[(（][ ]*)` +
			personNameSpacedValue,
	)
	// personNameExecTitleAndRe は「代表取締役であった<姓><名>及び<従業員>」のように、役職名 +
	// 「である／であった」の後の氏名に漢字「及び」が直結して personNameExecTitleRe の貪欲な値に
	// 取り込まれる表記を拾う（高知県の監督処分簿で実測）。値は最短一致で「及び」の手前までとし、
	// 姓名辞書の完全分割（姓+名）でのみ報告する。
	personNameExecTitleAndRe = regexp.MustCompile(
		`(?:代表取締役社長|代表取締役会長|代表取締役副社長|代表取締役|代表執行役社長|代表執行役|代表理事長|代表理事|代表社員|取締役社長|取締役会長|取締役|監査役)` +
			`(?:であった|である)([` + kanji + `]{2,8}?)及び`,
	)
	// personNamePartyLabelRe は審査申立・訴訟の当事者ラベル（審査申立人・請求人・原告・
	// 被告 等）の直後に空白区切りで続く氏名と、「（総代）<姓> <名>」を拾う
	// （person-name-role-label）。選挙管理委員会の裁決書・公表資料の当事者欄で、私人の
	// 氏名を全ルールモードが取りこぼす見逃しを実測した。コロンのない表記のため、
	// 士業の肩書と同じく姓名辞書の完全分割（姓+名）でのみ報告する。
	personNamePartyLabelRe = regexp.MustCompile(
		`(?:(?:審査申立人|異議申立人|申立人|審査請求人|請求人|原告|被告|控訴人|上告人)[ ]+(?:[(（]総代[)）][ ]*)?|[(（]総代[)）][ ]*)` +
			personNameSpacedValue,
	)
	// personNameYagoKotoRe は個人事業主の「<屋号>こと<姓><名>」表記（特定商取引法に基づく
	// 行政処分の公表文書・執行事例一覧で事業者名として頻出）の氏名を拾う
	// （person-name-role-label）。屋号に続く「こと」の後は事業主本人の氏名であり、個人事業主の
	// 氏名は生存する個人を識別でき個人情報に当たる。県の処分公表で全ルールモードが取りこぼす
	// 見逃しを実測した。「すること」「大切なこと」のような一般文の「こと」と区別するため、
	// 直前に屋号末尾となる漢字・カタカナ・英数字・長音・閉じ括弧を要求し、値は姓名辞書の
	// 完全分割（姓+名）でのみ報告する。
	personNameYagoKotoRe = regexp.MustCompile(
		`[` + kanji + katakana + `A-Za-z0-9ー’')）]こと[ ]?` +
			`([` + kanji + `]{2,8}(?:[ ][` + kanji + `]{1,8})?)`,
	)
	// personNameKojinSuffixRe は「<姓><名>（個人）」「<姓><名>（個人事業主）」のように、行政処分の
	// 公表文書で処分対象が自然人であることを括弧書きで明示した氏名を拾う
	// （person-name-role-label）。括弧書きが人であることを示すため強い根拠になるが、
	// 値は姓名辞書の完全分割（姓+名）でのみ報告する。直前は漢字以外（行頭・読点等）に限る。
	personNameKojinSuffixRe = regexp.MustCompile(
		`(?:^|[^` + kanji + `])` +
			`([` + kanji + `]{2,8}(?:[ ][` + kanji + `]{1,8})?)` +
			`[ ]?[(（](?:個人|個人事業主|個人事業者)[)）]`,
	)
	// 国の地方整備局の記者発表資料では電話ラベルの代わりに「（内線2251）」が続き、
	// pdftotext -layout で姓と名の間が最大 4 個の空白になる「人事課長   <姓>    <名>   （内線…）」
	// を全ルールモードが取りこぼす見逃しを実測した。役職語と内線番号の括弧で両側が
	// アンカーされるため、姓名間の空白は 1〜4 個まで許容する。
	// 同局の記者発表で「上下水道調整官 <姓> <名>（内線…）」「契約管理官 <姓> <名> （内線…）」の
	// ように「〜官」の職名を全ルールモードが取りこぼしたため、国の機関の職名（管理官・調整官・
	// 専門官 等）も役職語に含める（右側の電話・内線アンカーは同じく必須）。氏名と「（内線」の
	// 間に空白が無い表記もあるため、右側の空白は 0 個以上とする。
	// 関東地方整備局の記者発表では問合せ先が「課長補佐   <姓>（<よみ>） （内線：…）」のように
	// 氏名の直後にひらがなの読み括弧を挟む表記で、全ルールモードが取りこぼす見逃しを実測した
	// （同一資料群で 10 件超）。読み括弧はふりがなとして人名であることをむしろ補強するため、
	// 氏名と電話・内線アンカーの間にひらがな（空白込み 1〜12 字）の括弧を 1 つだけ許容する。
	// 読み括弧はキャプチャ外のため、報告スパンは氏名のみ。あわせて「不動産業適正化推進官」の
	// ような「推進官」も役職語に含める。
	personNameContactTitleRe = regexp.MustCompile(
		`(?:課長|係長|部長|室長|所長|局長|館長|センター長|課長補佐|担当係長|担当課長|担当部長|管理官|調整官|専門官|企画官|調査官|対策官|分析官|監理官|推進官)[ ]+` +
			`([` + kanji + `]{1,4}(?:[ ]{1,4}[` + kanji + `]{1,4})?)` +
			`(?:[ ]*[(（][ぁ-ゖー ]{1,12}[)）])?` +
			`[ ]*(?:(?i:tel)|電話|[(（]内線)`,
	)
	// personNameContactTitlePhoneRe は「〜課長 <姓> <電話番号>」のように、Tel・電話の
	// 前置きなしで姓の直後に電話番号が続く問合せ先を拾う（市の報道発表で実測）。
	// personNameContactTitleRe の右アンカーに電話番号を足すと、「課長 <姓> 電話 <番号>」で
	// 値が「<姓> 電話」まで伸びて辞書検証で落ちる（RE2 は検証失敗後に短い一致へ戻らない）
	// ため、値を姓 1 語に限った別パターンにしている。
	personNameContactTitlePhoneRe = regexp.MustCompile(
		`(?:課長|係長|部長|室長|所長|局長|館長|センター長|課長補佐|担当係長|担当課長|担当部長|管理官|調整官|専門官|企画官|調査官|対策官|分析官|監理官|推進官)[ ]+` +
			`([` + kanji + `]{1,4})[ ]+[0-9]{2,5}-[0-9]{1,4}-[0-9]{3,4}`,
	)
	// personNameWithReadingRe は「<姓> <名>（<せい> <めい>）」のように、空白区切りの漢字の
	// 姓名の直後に、同じく空白区切りのひらがなの読みが括弧で続く表記を拾う
	// （person-name-role-label）。委員名簿・講演者紹介・問合せ先・知事のあいさつ文で、
	// ラベルも敬称もないため全ルールモードが取りこぼす見逃しを公開文書（県・市・国の
	// 記者発表）で実測した。姓名と読みの両方が 2 語に分かれる形に限り、先頭語が姓名辞書の
	// 姓であることを要求する（validSpacedSurnameGiven）。
	// 2026-10-30 12:00 に「立命館大学の<姓> <名>（<せい> <めい>）教授」のように、直前が助詞「の」の
	// ために取りこぼす見逃しを実測したため、直前の文字として「の」も許す。
	personNameWithReadingRe = regexp.MustCompile(
		`(?:^|[^` + kanji + hiragana + katakana + `]|の)` +
			`([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + `]{1,4})[ ]*[(（][ぁ-ゖー]{1,8}[ ]{1,3}[ぁ-ゖー]{1,8}[)）]`,
	)
	// personNameTantoReadingRe は「担当 <姓>(<よみ>)」のように、コロンのない担当欄で姓の
	// 直後にひらがなの読みが括弧で続く表記を拾う（市の報道発表の問合せ先で実測）。
	// 読み括弧が人名の根拠になるため、コロン必須の担当ラベル（#48）の例外として扱う。
	personNameTantoReadingRe = regexp.MustCompile(
		`担当[ ]+([` + kanji + `]{1,4})[(（][ぁ-ゖー]{1,8}[)）]`,
	)
	// personNameTitleLineEndRe は「課長補佐 <姓> <名>」「国税庁長官 <姓> <名>」のように、
	// 行政機関の職名の直後に空白区切りの姓名が来て行が終わる表記を拾う
	// （person-name-role-label）。国の記者発表の担当者一覧・通知文の発信者欄で全ルール
	// モードが取りこぼす見逃しを実測した。行末で終わる姓名の 2 語に限り、先頭語が姓名
	// 辞書の姓であることを要求する（validSpacedSurnameGiven）。
	personNameTitleLineEndRe = regexp.MustCompile(
		`(?:課長|課長補佐|係長|部長|室長|所長|副所長|局長|館長|副館長|センター長|長官|次長|` +
			`管理官|調整官|専門官|企画官|調査官|対策官|分析官|監理官|推進官|` +
			// 団体・企業・自治体の長と、入札公告の発信者欄（2026-10-30 に実測した見逃し）。
			`理事長|会長|社長|学長|院長|校長|議長|総裁|頭取|知事|市長|町長|村長|区長|教育長|` +
			`契約責任者|契約担当役|` +
			// 講演・研修の講師紹介と社労士法人の代表者（2026-10-30 04:00 に実測した見逃し）。
			`教授|准教授|講師|施設長|代表社員)[ ]+` +
			// pdftotext -layout では姓と名の間が 4 個の空白になる表記も実測したため 1〜4 個を
			// 許容し、行末の直前に敬称（氏・様・先生）が付く「<職名> <姓> <名> 氏」も拾う。
			// 敬称は報告スパンに含めない（名は最短一致にして「<名>氏」の氏を取り込まない）。
			`([` + kanji + `]{1,4}[ ]{1,4}[` + kanji + `]{1,4}?)[ ]*(?:氏|様|先生)?[ ]*$`,
	)
	// personNameTantoDeptSlashRe は「（担当：調査部／<姓>）」「（担当：社会情報部／<姓>、<姓>）」の
	// ように、担当欄で部署名と姓をスラッシュで区切る表記を拾う（独立行政法人の調査公表資料で
	// 実測した見逃し）。部署語尾 + スラッシュの直後という位置は担当者の姓とほぼ確実なため、
	// 姓のみの一致も Medium で報告する。2 人目（読点の後）は personNameTantoDeptSlash2Re で拾う。
	personNameTantoDeptSlashRe = regexp.MustCompile(
		`担当[：:][ ]*[` + kanji + `]{0,10}(?:部|課|係|室|班|局|センター|グループ)[／/][ ]*` +
			`([` + kanji + `]{1,4})(?:[ ]*[、,][ ]*[` + kanji + `]{1,4}){0,3}[ ]*[)）]`,
	)
	personNameTantoDeptSlash2Re = regexp.MustCompile(
		`担当[：:][ ]*[` + kanji + `]{0,10}(?:部|課|係|室|班|局|センター|グループ)[／/][ ]*` +
			`[` + kanji + `]{1,4}[ ]*[、,][ ]*([` + kanji + `]{1,4})(?:[ ]*[、,][ ]*[` + kanji + `]{1,4}){0,2}[ ]*[)）]`,
	)
	// personNameTantoListRe は「担当：<姓>・<姓>・<姓>」「（担当者：<姓>、<姓>）」のように、
	// 担当欄に複数の姓を中黒・読点で並べた表記の各姓を拾う（person-name-role-label）。
	// 既存の担当ラベルは先頭の姓しか捕捉せず、2 人目以降を全ルールモードが取りこぼす
	// 見逃しを自治体・独立行政法人の報道発表で実測した（2026-10-30 04:00、10 件超）。
	// 姓が 2 つ以上並び、閉じ括弧・行末・2 個以上の空白・電話ラベルで終わる場合に限る
	// （RE2 は繰り返しグループの各要素を捕捉できないため、位置ごとに別の正規表現にする）。
	// 姓の直後のひらがなの読み括弧（<姓>（<せい>））も許容する。各値は姓名辞書の
	// 姓（または姓+名）で検証する。並びの構造が担当者名であることを強く示すため Medium。
	personNameTantoListRe = []*regexp.Regexp{
		regexp.MustCompile(tantoListPrefix + `(` + tantoListName + `)` + tantoListReading + `(?:` + tantoListSep + tantoListItem + `){1,3}` + tantoListEnd),
		regexp.MustCompile(tantoListPrefix + tantoListItem + tantoListSep + `(` + tantoListName + `)` + tantoListReading + `(?:` + tantoListSep + tantoListItem + `){0,2}` + tantoListEnd),
		regexp.MustCompile(tantoListPrefix + `(?:` + tantoListItem + tantoListSep + `){2}(` + tantoListName + `)` + tantoListReading + `(?:` + tantoListSep + tantoListItem + `)?` + tantoListEnd),
		regexp.MustCompile(tantoListPrefix + `(?:` + tantoListItem + tantoListSep + `){3}(` + tantoListName + `)` + tantoListReading + tantoListEnd),
	}
	// orgHeadColonTitle は法人の長の職名と、コロンまでに挟まる「兼社長」「社長執行役員」「グループ」「CEO」と
	// 空白（personNameOrgHeadColonRe・personNameOrgHeadColonIkaRe で共用）。
	orgHeadColonTitle = `(?:理事長|代表取締役社長|代表取締役会長|代表取締役|代表執行役社長|取締役社長|社長執行役員|社長|会長|学長|総長|機構長|所長|代表理事|頭取|董事長|CEO|ＣＥＯ)` +
		`(?:[ ]*(?:兼社長|兼CEO|兼ＣＥＯ|社長執行役員|グループ|CEO|ＣＥＯ))*[ ]*`
	// personNameOrgHeadColonRe は報道発表の冒頭の法人紹介「（〇〇県〇〇市、理事長：<姓><名>、
	// 以下「機構」）」「（理事長：<姓><名>    本部：…）」のように、法人の長の職名 + コロンの
	// 後に続く氏名を拾う（person-name-role-label）。独立行政法人・企業の報道発表で全ルール
	// モードが取りこぼす見逃しを実測した（2026-10-30 04:00）。値の後に読点・閉じ括弧・
	// 2 個以上の空白・行末のいずれかを要求し、姓名辞書の完全分割（姓+名）でのみ報告する。
	//
	// 2026-10-30 12:00 に、企業の報道発表で「代表取締役社長 CEO：<姓> <名>）」「代表取締役会長兼社長CEO：
	// <姓> <名>、」「代表取締役 社長執行役員 CEO：」「董事長兼CEO：」「理事長 : <姓> <名>、」のように、
	// 職名とコロンの間に「兼社長」「社長執行役員」「グループ」「CEO」や空白が入る表記と、名が辞書に
	// ない空白区切りの「<姓> <名>」を全モードで取りこぼす見逃しを実測した（新規 1500 文書で約 70 件）。
	// 職名の後に orgHeadColonTail の語を挟むことを許し、空白で 2 語に分かれた値は姓だけ辞書で確かめる
	// （validFullSplitOrSpacedSurnameGiven）。
	personNameOrgHeadColonRe = regexp.MustCompile(
		orgHeadColonTitle + `[：:][ ]*` +
			`([` + kanji + `]{2,8}(?:[ ][` + kanji + `]{1,8})?)(?:[ ]*[、,)）]|[ ]{2,}|[ ]*$)`,
	)
	// personNameOrgHeadColonIkaRe は「（本社：<所在地>、代表取締役社長：<姓><名> 以下、当社）」のように、
	// 無空白の氏名の直後が空白 +「以下」になる法人紹介を拾う（2026-10-30 12:00 実測の見逃し）。
	// personNameOrgHeadColonRe は「<姓><名> 以下」を空白区切りの 2 語として取り込んでしまうため別に持つ。
	personNameOrgHeadColonIkaRe = regexp.MustCompile(
		orgHeadColonTitle + `[：:][ ]*([` + kanji + `]{2,8})[ ]+以下`,
	)
	// personNameSeatNumberRe は農業委員会・議会の会議録の出席者表「出席   委    員     1番     <姓>    <名>」
	// 「会長 ５番 <姓> <名>」のように、議席番号「N番」の直後に空白区切りの姓名が来て行が終わる表記を
	// 拾う（person-name-role-label）。役職名が均等割付で分かれ、氏名にラベルも敬称もないため全モードで
	// 取りこぼしていた（2026-10-30 12:00 に町の農業委員会の議事録 12 文書・約 90 件を実測）。
	// 姓は辞書、名は 1〜3 文字で職名でないこと（validSpacedSurnameGiven）を要求する。
	personNameSeatNumberRe = regexp.MustCompile(
		`(?:^|[ ])[0-9０-９]{1,2}[ ]*番[ ]+([` + kanji + `]{1,4}[ ]{1,6}[` + kanji + `]{1,3})[ ]*$`,
	)
	// personNameBusinessOperatorLabelRe は特定商取引法に基づく行政処分の公表資料の処分対象
	// 欄「事業者：<姓> <名>（65 歳）」（均等割付の字間スペース付き「事  業  者：」を含む）の
	// 氏名を拾う（person-name-role-label）。個人事業者が処分対象の場合、事業者欄の値は
	// 本人の氏名であり個人情報に当たる。県の処分公表 PDF で全ルールモードが取りこぼす
	// 見逃しを実測した。法人名・屋号は姓名辞書の完全分割を通らないため報告しない。
	personNameBusinessOperatorLabelRe = regexp.MustCompile(
		`事[ ]{0,2}業[ ]{0,2}者` + personNameSep +
			`([` + kanji + `]{2,8}(?:[ ]{1,3}[` + kanji + `]{1,8})?)`,
	)
	// personNameDefinedAsOperatorRe は処分公表の本文冒頭「「<姓><名>」（以下「事業者」という。）
	// に対し」のように、鉤括弧で示した処分対象者を「事業者」等と定義する表記の氏名を拾う
	// （person-name-role-label）。県の処分公表で全ルールモードが取りこぼす見逃しを実測した。
	// 定義語は処分対象を指す語に限定し、値は姓名辞書の完全分割（姓+名）でのみ報告する
	// （「株式会社〇〇」（以下「事業者」という。）等の法人名は辞書ゲートで落ちる）。
	personNameDefinedAsOperatorRe = regexp.MustCompile(
		`「([` + kanji + `]{2,8}(?:[ ][` + kanji + `]{1,8})?)」[ ]?[(（]以下[ ]?「(?:事業者|当該事業者|被処分者|処分対象者|同人)」`,
	)
	// personNameRepNameSpacedRe は建設業者監督処分簿（国の様式で都道府県が公表）の表組み
	// 「代表者氏名     <姓> <名>」のように、コロンのない「代表者氏名」「代表者の氏名」「代表者名」
	// ラベルの後に空白で続く氏名を拾う（person-name-role-label）。高知県の監督処分簿 PDF で
	// 全ルールモードが取りこぼす見逃しを実測した。汎用の「氏名」ラベルはコロン必須のまま
	// （#48）とし、法人代表者を示す複合ラベルに限って空白区切りを許容する。値は姓名辞書の
	// 完全分割（姓+名）でのみ報告する。
	personNameRepNameSpacedRe = regexp.MustCompile(
		`代表者(?:の?氏名|名)[ ]+` + personNameSpacedValue,
	)
	// personNameKessanHeaderRe は決算短信・適時開示の表紙の「代表者 (役職名) 代表取締役社長 (氏名) <姓> <名>」
	// 「問合せ先責任者 (役職名) 常務取締役 (氏名) <姓> <名> (TEL) …」のように、括弧書きの「(役職名)」の後の
	// 「(氏名)」に続く氏名を拾う（person-name-role-label）。東証の決算短信の様式で、上場企業の文書では
	// ほぼ毎回この形で載るが、括弧書きのラベルにはコロンがないため全ルールモードが取りこぼす見逃しを
	// 実測した（2026-10-30 14:00、新規 1950 文書のうち 76 文書・152 行）。「(役職名)」を同じ行に要求して
	// 記入様式の単独の「(氏名)」とは区別し、値の後に 2 個以上の空白・行末・開き括弧（「(TEL)」）を要求する。
	// 空白で 2 語に分かれた値は姓だけ辞書で確かめる（validFullSplitOrSpacedSurnameGiven）。
	// 表紙の PDF 抽出では姓と名の間が均等割付で大きく空き（「（氏名）<姓>           <名>」）、
	// 1 字の姓（「岸 泰造」）もあるため、値は personNameSpacedValue より広く取り、
	// 後ろに「TEL」「ＴＥＬ」が 1 個の空白で続く形も許す。
	personNameKessanHeaderRe = regexp.MustCompile(
		`[(（]役職名[)）][^(（]{0,60}?[(（]氏名[)）][ ]*` +
			`([` + kanji + `]{1,8}(?:[ ]{1,40}[` + kanji + `]{1,8})?)` +
			`(?:[ ]{2,}|[ ]*$|[ ]*[(（]|[ ]+(?:TEL|ＴＥＬ|Tel|電話))`,
	)
	// personNameBanOrderRe は特定商取引法に基づく行政処分の公表文書の「<姓><名>に対する業務禁止命令」
	// の氏名を拾う（person-name-role-label）。業務禁止命令（特商法第 8 条の 2 等）は法人の役員等の
	// 個人を名宛人とする処分であり、この位置の値は自然人の氏名になる。愛媛県の処分公表で
	// 全ルールモードが取りこぼす見逃しを実測した。法人名（業務停止命令の名宛人）は
	// 姓名辞書の完全分割を通らないため報告しない。直前は漢字以外（行頭・読点・括弧等）に限る。
	personNameBanOrderRe = regexp.MustCompile(
		`(?:^|[^` + kanji + `])` +
			`([` + kanji + `]{2,8}(?:[ ][` + kanji + `]{1,8})?)` +
			`[ ]?に対する業務禁止命令`,
	)
	// lecturer* は personNameLecturerLabelRe / personNameLecturerLabel2Re の部品（講師等の
	// ラベル、敬称、値の後の区切り）。
	lecturerLabel     = `(?:講師|講演者|審査員|コーディネーター|ファシリテーター|オブザーバー|パネリスト)[ ]?[：:／/][ ]*`
	lecturerHonorific = `[ ]*(?:氏|先生|さん|様)?`
	lecturerEnd       = `(?:[ ]*[(（〔［【]|[ ]*[・、,]|[ ]*$|[ ]{2,})`
	lecturerValue     = `([` + kanji + `]{2,8}?(?:[ ]{1,3}[` + kanji + `]{1,8}?)?)`
	// personNameLecturerLabelRe は催し・講座の案内の「講師：<姓><名>先生」「講師／<姓><名>氏〔<所属>〕」
	// 「講師：<姓> <名>氏（<会社名>）」のように、講師・審査員等のラベルの直後に続く氏名を拾う
	// （person-name-role-label）。自治体の広報・イベント案内で、敬称の付かない形や「先生」付きの
	// 形を全ルールモードが取りこぼし、敬称付きも高再現率モードでしか拾えない見逃しを実測した
	// （2026-10-30 06:00、10 件超）。値は最短一致にして敬称（氏 は漢字）を取り込まず、直後に
	// 括弧・中黒・読点・行末・2 個以上の空白のいずれかを要求する。団体名・所属名
	// （〇〇クラブ・教育委員会主事 等）は姓名辞書の完全分割（姓+名）を通らないため報告しない。
	// 2 人目（「講師：<姓><名>先生・<姓><名>先生」）は personNameLecturerLabel2Re で拾う。
	personNameLecturerLabelRe = regexp.MustCompile(
		lecturerLabel + lecturerValue + lecturerHonorific + lecturerEnd,
	)
	personNameLecturerLabel2Re = regexp.MustCompile(
		lecturerLabel + `[` + kanji + `]{2,8}?(?:[ ]{1,3}[` + kanji + `]{1,8}?)?` + lecturerHonorific + `[ ]*[・、,][ ]*` +
			lecturerValue + lecturerHonorific + lecturerEnd,
	)
	// personNameShiAffiliationRe は「<姓> <名> 氏 （<所属>）」「<姓><名>氏〔<肩書>〕」のように、
	// 敬称「氏」の直後に所属・肩書の括弧が続く講演者・委員紹介の氏名を拾う
	// （person-name-role-label）。自治体のシンポジウム・会議の案内で、既定のルールモードが
	// 取りこぼす（敬称アンカーの高再現率モードでしか拾えない）見逃しを実測した
	// （2026-10-30 06:00）。「氏 + 所属の括弧」は人物紹介の定型で、氏族名（<姓>氏）や
	// 一般語とは区別できる。直前は行頭・漢字と空白以外の文字・2 個以上の空白に限り
	// （字間スペース付きの「<姓> <名> 氏」の途中から拾わないため）、値は姓名辞書の
	// 完全分割（姓+名）でのみ報告する。2026-10-30 10:00 に、PDF の均等割付で姓と名の間が 5 個の
	// 空白になり、名が辞書にない「<姓>     <名>   氏（<所属>）」の見逃しを実測したため、姓と名の
	// 間の空白を 6 個まで許し、空白で 2 語に分かれた値は姓だけ辞書で確かめる
	// （validFullSplitOrSpacedSurnameGiven）。
	personNameShiAffiliationRe = regexp.MustCompile(
		`(?:^|[^` + kanji + ` ][ ]*|[ ]{2,})` +
			`([` + kanji + `]{1,4}[ ]{0,6}[` + kanji + `]{1,4}?)[ ]*氏[ ]*[(（〔［]`,
	)
	// personNameKosekiTodokeRe は広報紙の「戸籍の窓口」欄「死亡届（<姓> <名>さん）」
	// 「出生届（<姓> <名>くん）」「婚姻届（<姓> <名>さん・<姓> <名>さん）」の氏名を拾う
	// （person-name-role-label）。届出の種類 + 括弧 + 空白区切りの姓名 + 敬称は届出人・
	// 届出の本人を指す定型で、既定のルールモードが取りこぼす見逃しを町の広報 PDF で実測した
	// （2026-10-30 06:00、同一資料で 15 件超）。出生届の子の名はカタカナ・ひらがなも
	// 混じるため名側は辞書を要求せず、先頭語が姓名辞書の姓であることを要求する
	// （validSpacedSurnameGiven）。死亡届の本人は故人だが、届出の公表欄では届出人
	// （遺族）と同じ姓・住所区と結び付くため、生存する遺族を識別しうる情報として扱う。
	// 婚姻届の 2 人目は personNameKosekiTodoke2Re で拾う。
	kosekiTodokeValue        = `([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + katakana + hiragana + `]{1,4}?)[ ]*(?:さん|くん|ちゃん|様)`
	personNameKosekiTodokeRe = regexp.MustCompile(
		`(?:出生|死亡|婚姻)届[(（][ ]*` + kosekiTodokeValue,
	)
	personNameKosekiTodoke2Re = regexp.MustCompile(
		`婚姻届[(（][ ]*[` + kanji + `]{1,4}[ ]{1,3}[` + kanji + katakana + hiragana + `]{1,4}?[ ]*(?:さん|くん|ちゃん|様)[ ]*[・、][ ]*` +
			kosekiTodokeValue,
	)
	// personNameTitleHonorificWideRe は宛名・発信者欄の「<市町村>長    <姓>      <名>   様」のように、
	// pdftotext -layout の均等割付で姓と名の間が 5〜12 個の空白になり、行末が敬称「様」「殿」で
	// 終わる表記を拾う（person-name-role-label）。personNameTitleLineEndRe は空白 4 個までのため、
	// 村・町の入札公告・通知文の宛名を全ルールモードが取りこぼす見逃しを実測した
	// （2026-10-30 06:00）。行末の敬称を必須にすることで、表の列が離れて並ぶ行とは区別する。
	personNameTitleHonorificWideRe = regexp.MustCompile(
		`(?:市長|町長|村長|区長|知事|教育長|議長|理事長|会長|社長|学長|院長|所長|局長)[ ]+` +
			`([` + kanji + `]{1,4}[ ]{5,12}[` + kanji + `]{1,4})[ ]*(?:様|殿)[ ]*$`,
	)
	// personNameCommitteeListRe は会議録・議事要旨の出席者欄「出席委員 <姓><名>会長、<姓><名>委員、…」
	// のように、姓名の直後に会議内の役職（会長・副会長・委員長・副委員長・委員・議長・副議長）が
	// 続き読点で区切って並ぶ氏名を拾う（person-name-role-label）。町の審議会の議事要旨で、
	// 全モードが取りこぼす見逃しを実測した（2026-10-30 08:00）。値は直前が行頭・読点・
	// コロン・山括弧・空白のいずれかで、直後の役職のあとに読点か行末が来ること
	// （rejectCommitteeListTail）と、姓名辞書の完全分割（姓+名）を要求する。姓だけの
	// 「<姓>委員、」や「人権擁護委員、」「民生委員、」のような制度名は完全分割を通らない。
	personNameCommitteeListRe = regexp.MustCompile(
		`(?:^|[、,，：:＞>]|[ ])[ ]*([` + kanji + `]{3,8}?)(?:副委員長|委員長|副会長|会長|副議長|議長|委員)`,
	)
	// personNameLecturerSpaceRe は「（１）講師 <姓> <名>さん」「講師   <姓> <名>氏」のように、講師等の
	// ラベルと氏名の間がコロンでなく空白で、氏名の後に敬称が付く形を拾う（person-name-role-label）。
	// personNameLecturerLabelRe はコロン・スラッシュ区切りしか見ないため、市の報道資料で
	// 取りこぼしていた（2026-10-30 08:00 実測）。空白区切りは「講師 派遣事業」のような
	// 一般語とも並ぶため、敬称を必須にする。
	personNameLecturerSpaceRe = regexp.MustCompile(
		`(?:講師|講演者|審査員|パネリスト)[ ]+` + lecturerValue + `[ ]*(?:氏|先生|さん|様)`,
	)
	// personNameLecturerSpaceParenRe は「・講師 <姓> <名>（<所属><職名>）」のように、講師等のラベルと
	// 空白区切りの姓名の後に、敬称でなく所属・職名の括弧が続く講座案内の形を拾う
	// （person-name-role-label）。personNameLecturerSpaceRe は敬称を必須にしているため、
	// 県の博物館の講座一覧 PDF で敬称のない職員講師 6 人を全モードが取りこぼしていた
	// （2026-10-30 16:00 実測）。名の直後の敬称（氏・様など）は値に含めない。一般語と区別するため、値は姓と名の間に空白がある 2 語に限り、
	// 姓は辞書、名は職名でない 1〜3 文字であること（validFullSplitOrSpacedSurnameGiven）を要求する。
	personNameLecturerSpaceParenRe = regexp.MustCompile(
		`(?:講師|講演者|審査員|パネリスト)[ ]+([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + `]{1,4}?)[ ]*(?:氏|様|さん|先生)?[ ]*[(（]`,
	)
	// personNameDirectorCreditRe は出演作品の一覧の「「<作品名>」監督　<姓><名>」「「<作品名>」 監督：<姓><名>」
	// のように、作品名の閉じかぎ括弧の後の「監督」に続く氏名を拾う（person-name-role-label）。
	// 芸能事務所の所属タレントの経歴ページで全モードが取りこぼす見逃しを実測した
	// （2026-10-30 16:00、1 文書で 7 人）。閉じかぎ括弧を必須にして「監督官庁」「監督 指導」
	// のような一般語と区別し、値の後は括弧・中黒・読点・注記の ※・行末・2 個以上の空白に限り、
	// 姓名辞書の完全分割（姓+名）を要求する。
	personNameDirectorCreditRe = regexp.MustCompile(
		`[」』][ ]*(?:総監督|監督)[ ]*[：:]?[ ]*([` + kanji + `]{2,8}?(?:[ ][` + kanji + `]{1,8}?)?)(?:[ ]*[(（・、,※]|[ ]*$|[ ]{2,})`,
	)
	// personNameSenseiLineRe は講座・教室の講師一覧で「<姓> <名> 先生」だけが 1 行に並ぶ形を拾う
	// （person-name-role-label）。ラベルがないため全モードが取りこぼす見逃しを、博物館の
	// 講座案内で実測した（2026-10-30 16:00、5 人）。行頭から始まる空白区切りの 2 語で、
	// 直後に「先生」と、中黒・読点・行末・2 個以上の空白が続くことを要求し、姓は辞書、名は
	// 職名でないこと（validSpacedSurnameGiven）を確かめる。名はひらがなを含む形（<姓> <ひらがな>子）も許す。
	personNameSenseiLineRe = regexp.MustCompile(
		`^[ ]*([` + kanji + `]{1,4}[ ]{1,3}[` + kanji + hiragana + `]{1,4})[ ]*先生[ ]*(?:[・、]|$|[ ]{2,})`,
	)
	// personNameTantoSpaceRe は学校・自治体の様式の「担当者 <姓> <名>」「担当者 教頭 <姓> <名>」の
	// ように、担当者ラベルと姓名の間が空白だけで、値の後に 2 個以上の空白か行末が来る形を拾う
	// （person-name-role-label）。pdftotext -layout で表の欄がコロンなしに並ぶ形を全モードが
	// 取りこぼしていた（2026-10-30 08:00 実測）。値は空白区切りの姓名で、姓名辞書の完全分割を要求する。
	personNameTantoSpaceRe = regexp.MustCompile(
		`担当者[ ]+(?:(?:教頭|校長|副校長|主任|主査|主事|係長|課長|主幹|副主幹|課長補佐)[ ]+)?` +
			`([` + kanji + `]{1,4}[ ][` + kanji + `]{1,4})(?:[ ]{2,}|[ ]*$)`,
	)
	// personNameTantoWideRe は「担当：<姓>       <名>」「担当者名：<姓>         <名>」のように、担当欄の
	// 姓と名の間が pdftotext -layout の均等割付で 2〜10 個の空白になる表記を拾う
	// （person-name-role-label）。既存の担当ラベルは空白 1 個までしか名を取り込まず、姓だけを Low で
	// 報告していた（2026-10-30 10:00 に町の報道資料・イベント案内で実測）。値の後は 2 個以上の
	// 空白か行末を要求し、姓は辞書、名は 1〜3 文字で職名でないこと（validSpacedSurnameGiven）を要求する。
	personNameTantoWideRe = regexp.MustCompile(
		`(?:担当者名|担当者|担当)[ ]*[:：][ ]*([` + kanji + `]{1,4}[ ]{2,10}[` + kanji + `]{1,3})(?:[ ]{2,}|[ ]*$)`,
	)
	// personNameExecTitleWideRe は入札結果の「<社名> 代表取締役     <姓>       <名>」のように、代表者の
	// 役職名の後で姓と名の間が 5〜8 個の空白になり行が終わる表記を拾う（person-name-role-label）。
	// personNameExecTitleRe は姓名の間の空白を 3 個までしか許さないため、町の入札結果で全モードが
	// 取りこぼしていた（2026-10-30 10:00 実測）。表の列と区別するため、行末で終わる 2 語に限る。
	personNameExecTitleWideRe = regexp.MustCompile(
		`(?:代表取締役社長|代表取締役|代表理事|代表社員|取締役社長|理事長|組合長|社長)[ ]+` +
			`([` + kanji + `]{1,4}[ ]{4,8}[` + kanji + `]{1,3})[ ]*$`,
	)
	// personNameHonorificAfterTitleRe は「<町名>町長<姓><名>様」「（委員長<姓><名>氏）」のように、職名と
	// 氏名が地続きで敬称が付く形の、職名を除いた氏名を拾う（person-name-high-recall）。無空白の敬称
	// パターンは職名まで値に含めるため rejectHonorificTitlePrefix で棄却し、ここで拾い直す。
	personNameHonorificAfterTitleRe = regexp.MustCompile(
		`(?:委員長|理事長|市長|町長|村長|区長|副会長|会長|社長|校長|園長|議長|館長|知事)([` + kanji + `]{2,6})(?:様|さん|氏|殿)`,
	)
)

// validFullSplitOrSpacedSurnameGiven は、姓名辞書の完全分割（姓+名）か、空白で 2 語に分かれた
// 「<姓> <名>」（validSpacedSurnameGiven）のどちらかが成立する値を許可する。「<姓>   <名>   氏（<所属>）」
// のように敬称と所属の括弧という強い構造がある形で、辞書にない名（2026-10-30 10:00 に実測）を拾うために使う。
// validKessanSpacedPair は決算短信の表紙の「(氏名)」欄の値が、辞書照合なしでも氏名とみなせる
// 形（空白で区切った漢字 1〜4 字の 2 語で、プレースホルダや記入説明でない）かを返す。
// 様式自体が氏名欄であることを示すため、辞書にない珍しい姓（2026-10-30 14:00 に実測）も Low で拾う。
func validKessanSpacedPair(v string) bool {
	f := strings.Fields(v)
	if len(f) != 2 || !notPlaceholderName(v) || !notFormWordValue(v) {
		return false
	}
	for _, w := range f {
		if n := len([]rune(w)); n < 1 || n > 4 {
			return false
		}
	}
	return true
}

func validFullSplitOrSpacedSurnameGiven(v string) bool {
	return validPersonNameFullSplit(v) || validSpacedSurnameGiven(v)
}

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
// personNameFormWordPrefixes / personNameFormWordParts は、申込・届出の案内文の
// 「氏名（ふりがな）」「氏名（団体名）」「氏名（法人にあっては…）」のように、氏名ラベルの
// 括弧内が記入方法の説明である値。辞書に一致しない値を Low で拾う強ラベルの片割れが、
// 自治体・国の案内ページでこれを氏名として報告する偽陽性を実測した。
var personNameFormWordPrefixes = []string{
	"ふりがな", "フリガナ", "カタカナ", "ひらがな", "漢字", "団体名", "所属", "法人", "及び", "又は",
	"複数", "代表者", "ことば", "読み", "よみ", "記入", "楷書", "社名",
	// 「氏名（敬称略）」（名簿の見出し）と「氏名(名称及び代表者職氏名)」（届出様式の記入説明）。
	"敬称略", "名称",
	// 空欄の記入様式「氏名：　　　電話番号：」で、値の位置に次の項目ラベルが来る形
	// （2026-10-30 06:00 に実測した Low の偽陽性）。
	"電話", "住所", "生年月日", "連絡先", "年齢", "性別",
	// 作品募集の応募欄「氏名（ペンネーム可）」と、半角カナの「お名前(ﾌﾘｶﾞﾅ)」（2026-10-30 18:00 に
	// 出版社・神社のサイトで実測した Low の偽陽性。どちらも記入方法の指示で氏名ではない）。
	"ペンネーム", "ﾌﾘｶﾞﾅ", "フリカ\u3099ナ", "ﾌﾘｶﾅ", "ｶﾀｶﾅ", "ｶﾅ", "ﾖﾐ",
}

// personNameBracketFormHints は「お名前（かな）」「氏名（カナ）」のように、氏名ラベル直後の
// 括弧内に置かれる記入方法の指示語。「かな」は名としても姓名辞書に載るため、Medium の
// 辞書照合を通ってしまう偽陽性を申込フォームの案内で実測した（2026-10-30 04:00）。
var personNameBracketFormHints = map[string]bool{
	"かな": true, "カナ": true, "よみ": true, "ヨミ": true, "ふりがな": true, "フリガナ": true,
	"読み": true, "敬称略": true,
	// 「氏名（法人の場合は名称及び代表者氏名）」が行の途中で改行され「氏名（法人」で
	// 行が終わる記入説明。「法人」が姓名辞書に一致して Medium で報告される偽陽性を
	// 実測した（2026-10-30 06:00）。
	"法人": true,
	// 申請書様式の「氏名（自署）」（本人が自筆で書く欄の指示）。「自署」を氏名として low で報告する
	// 偽陽性を大学の申請様式で実測した（2026-10-30 14:00）。
	"自署": true,
	// 申込フォームの「お名前（フルネーム、フリガナ）」（2026-10-30 16:00 に実測した low の偽陽性）。
	"フルネーム": true,
	// 半角カナの「お名前(ﾌﾘｶﾞﾅ)」（2026-10-30 18:00 に神社のお守り郵送案内で実測した low の偽陽性）。
	// 半角カナは正規化で「フリカ」+ 結合濁点（U+3099）+「ナ」になるため、その形も入れる。
	"ﾌﾘｶﾞﾅ": true, "フリカ\u3099ナ": true, "ﾌﾘｶﾅ": true, "ｶﾅ": true, "ﾖﾐ": true, "ペンネーム可": true,
}

// rejectBracketedFormHint は、氏名ラベルの値が括弧で囲まれた記入方法の指示語
// （personNameBracketFormHints）である場合に棄却する。括弧で囲まれていない
// 値は、ひらがなの人名の可能性があるため棄却しない。
func rejectBracketedFormHint(line string, start, end int) bool {
	if !personNameBracketFormHints[strings.TrimSpace(line[start:end])] {
		return true
	}
	before := strings.TrimRight(line[:start], " ")
	after := strings.TrimLeft(line[end:], " ")
	open := strings.HasSuffix(before, "(") || strings.HasSuffix(before, "（")
	// 「（法人名、代表者名）」「（法人の場合は…）」のように「法人」で始まる括弧書きは、
	// 閉じ括弧の位置によらず記入説明とみなす（PDF の改行で次行と連結された形を含む）。
	// 「（フルネーム、フリガナ）」のように読点で次の指示語が続く形も括弧書きの指示とみなす。
	closed := strings.HasPrefix(after, ")") || strings.HasPrefix(after, "）") || after == "" ||
		strings.HasPrefix(after, "、") || strings.HasPrefix(after, ",") ||
		strings.TrimSpace(line[start:end]) == "法人"
	return !(open && closed)
}

var personNameFormWordParts = []string{
	"場合", "記入", "にあっては", "担当", "証明", "整備局", "・氏名", "・職",
}

// notFormWordValue は氏名候補 v が記入方法の説明（personNameFormWordPrefixes /
// personNameFormWordParts）でないことを返す。辞書に一致しない値を Low で拾う
// パターン専用（辞書一致の Medium には影響しない）。
func notFormWordValue(v string) bool {
	v = strings.TrimSpace(v)
	for _, s := range personNameFormWordPrefixes {
		if strings.HasPrefix(v, s) {
			return false
		}
	}
	for _, s := range personNameFormWordParts {
		if strings.Contains(v, s) {
			return false
		}
	}
	return true
}

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
	// 「株式会社<社名>様」（寄附の御礼・導入事例）のように法人格が前に付く組織名も棄却する
	// （2026-10-30 04:00 に自治体の寄附受納ページで実測した偽陽性）。
	for _, s := range []string{"株式会社", "有限会社", "合同会社", "合資会社", "合名会社"} {
		if strings.HasPrefix(v, s) {
			return false
		}
	}
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

// validStrictFullNameExtended は高再現率用カタカナ名（org 版）まで許す
// validStrictFullName。person-name-structured / CSV 列文脈のように
// high-recall 有効時だけ走る経路から使う。
func validStrictFullNameExtended(v string) bool {
	v = strings.TrimSpace(v)
	_, given, ok := dict.SplitFullNameExtended(v)
	return ok && len([]rune(given)) >= 2
}

// validPersonNameFullSplit は姓+名の分割（dict.FullNameSplit）が成立する
// 場合のみ許可する。担当ラベル（person-name-role-label）の Medium パターンと、
// 空白入りの敬称アンカー（person-name-high-recall）で使う。
// 単独の姓一致（SurnameOnly）は validPersonNameSurnameOnly 側の Low パターンで
// 別途扱うため、ここには含めない（渋谷・大和・本田のような地名・企業名と同形の
// 姓が Medium に一律昇格するのを避ける）。
func validPersonNameFullSplit(v string) bool {
	return dict.MatchPersonName(strings.TrimSpace(v)) == dict.FullNameSplit
}

// validPersonNameSurnameOnly は単独の姓一致（dict.SurnameOnly）の場合のみ許可
// する。担当ラベル（person-name-role-label）の Low パターン用。
// validPersonNameSurnameOrFull は姓のみ、または姓+名の完全分割が成立する値を許可する。
func validPersonNameSurnameOrFull(v string) bool {
	m := dict.MatchPersonName(strings.TrimSpace(v))
	return m == dict.SurnameOnly || m == dict.FullNameSplit
}

// spacedGivenStopwords は「<職名> <姓> <語>」の 2 語目に来うる、名ではない語。
var spacedGivenStopwords = map[string]bool{
	"担当": true, "宛": true, "様": true, "殿": true, "氏": true, "外": true, "他": true,
	"以下": true, "ほか": true, "代理": true, "事務": true, "所長": true, "課長": true,
	"電話": true, "内線": true, "直通": true, "代表": true, "携帯": true,
	// 担当欄の「<姓>   主査」のように姓の後に職名だけが続く形（2026-10-30 10:00 の担当欄パターン追加時）。
	"係長": true, "主査": true, "主事": true, "主任": true, "主幹": true, "部長": true, "室長": true,
	"班長": true, "補佐": true, "係": true, "課": true, "班": true, "室": true,
}

// validSpacedSurnameGiven は空白で 2 語に分かれた「<姓> <名>」を検証する。先頭語が
// 姓名辞書の姓（単独の姓、または姓+名の分割が成立する語）で、2 語目が 1〜3 文字の
// 名らしい語（職名・一般語の stopword でない）なら許可する。名の辞書は収録数が
// 限られる（亮太郎・洋和 等が未収録）ため、名側は辞書を要求しない。代わりに
// 呼び出し側の正規表現で、読み括弧や職名 + 行末といった人名の構造を要求する。
func validSpacedSurnameGiven(v string) bool {
	f := strings.Fields(strings.TrimSpace(v))
	if len(f) != 2 {
		return false
	}
	if n := len([]rune(f[1])); n < 1 || n > 3 || spacedGivenStopwords[f[1]] {
		return false
	}
	return dict.IsSurname(f[0])
}

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

// phonePatternGroup は jp-phone-number のパターンを「そのパターンにマッチする
// どの文字列にも必ず含まれるリテラル」ごとに分けた 1 グループ。literals が空でない
// 場合、行がそのいずれも含まなければ internal/detect はグループ内の正規表現走査を
// まるごと省略できる（Rule.PrefilterLiterals）。
type phonePatternGroup struct {
	// literals はグループ内の全パターンについて「マッチ文字列に必ず 1 つは含まれる」
	// リテラル集合（OR 条件）。空なら常に正規表現を走査する。
	literals []string
	// patterns はこのグループのパターン（分割前の定義順を保つ）。
	patterns []Pattern
}

// phoneRules は jp-phone-number ルールを、必須リテラルごとに分割した複数の Rule
// エントリとして返す。
//
// なぜ分割するのか（性能）: 電話番号の各パターンは境界ガード
// （dgNoDigitBeforeNoAlnumHyphenAfter の `(?:^|[^0-9])` …）で始まる。Go の regexp は
// プログラム先頭が単一ルーンのリテラルでないと strings.Index による位置スキップ
// （regexp.prefix）を使えず、行の全バイト位置からバックトラッカー（tryBacktrack）を
// 起動する。実測（88 バイトの ASCII 数字行、1 パターンあたり
// FindStringSubmatchIndex 1 回）では:
//
//	(?:^|[^0-9])(zzz)                     … 3.9µs  ← 走査足場だけでこの値
//	(?:^|[^0-9])(0\d{1,4}-\d{1,4}-\d{3,4})… 4.0µs  ← 本体の寄与は 0.1µs 未満
//	(0\d{9})                              … 0.09µs ← 先頭リテラルがあると 40 倍速い
//
// つまりコストはパターン本体の複雑さ（可変長量指定子の連結や桁数の組合せ）ではなく
// 「正規表現を起動した回数」でほぼ決まる。境界ガードは検出挙動（マッチ集合と、
// キャプチャ外ルーン数から決まる internal/detect の patternBoundContext 加点）に
// 直結するため外せない。したがって高速化は正規表現の書き換えでは得られず、
// 起動そのものを省くことで得る。
//
// なぜ検出挙動が変わらないのか:
//
//  1. 正規表現は 1 文字も変えていない（分割前と同一のソース・同一の Base・
//     ValidateLine・RequireContext・NegativeContextMode）。
//  2. パターンの評価順序も分割前と同じ（グループは定義順の連続した区間で、
//     エントリも元の位置にまとめて挿入する）。同一ルール ID・同一スパン・同信頼度で
//     重なる候補の採用は先着順（internal/detect の better/resolveOverlaps は
//     同点時に RuleID でしか比較しない）ため、順序保存は等価性の前提になる。
//  3. literals は各パターンの構文から導いた必要条件で、リテラルを 1 つも含まない行は
//     そのパターンが構造的にマッチし得ない（下の各グループのコメント参照）。
//     TestPhoneScanEquivalence が生成ケース・乱数ケースで「リテラル判定を挟んでも
//     結果が変わらない」ことを固定する。
func phoneRules() []Rule {
	// base は全エントリが共有するメタデータ（Patterns / PrefilterLiterals 以外）。
	base := Rule{
		ID:          "jp-phone-number",
		Description: "電話番号（携帯・固定・IP・国際表記）",
		Prefilter:   PrefilterDigit,
		Context:     []string{"電話", "携帯", "連絡先", "tel", "phone", "fax", "mobile", "denwa"},
		// 桁ベースの区切りなし固定電話パターンは業務 ID・型番等と衝突しやすいため、
		// 金額・数量・連番 ID 文脈で棄却する。区切りあり携帯・区切りなし携帯・
		// 区切りあり固定・国際表記の 4 パターンは、汎用の負文脈クラス（金額・
		// カウンタ・汎用窓語）まで適用すると既存の検出挙動を落としかねないため
		// NegativeContextAdjacentLabelOnly に限定し、採番ラベル（型番・SKU 等）が
		// 値に直接隣接する場合だけ棄却する（既知FP: 「電話機SKU: 090-...」
		// 「電話API version: 03-...」。それ以外の検出挙動は維持する）。
		NegativeContext:      digitRuleNegativeContext,
		RequireContextWindow: digitRuleRequireContextWindow,
		Validate:             validPhone,
		// PhoneKind はフリーダイヤル等のサービス番号(0120/0800/0570/0990/0180)・
		// IP電話(050)・携帯(060/070/080/090)・国際表記・固定電話を判別し、
		// Reason.Kind に記録する（内訳は internal/rule/phone_kind.go）。
		// [rules] exclude_kinds で下位種別ごとに除外できる（既定は全種別検出）。
		Kind: PhoneKind,
	}

	groups := []phonePatternGroup{
		{
			// 区切りあり携帯・IP 電話（060/070/080/090/050）。3 文字目の "0" の直後は
			// 必ずハイフンなので "0-" が必須リテラルになる。
			literals: []string{"0-"},
			patterns: []Pattern{
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0[5-9]0-\d{4}-\d{4}`), Base: High, NegativeContextMode: NegativeContextAdjacentLabelOnly},
			},
		},
		{
			// 空白・ドット区切り携帯・IP 電話。3 文字目の "0" の直後は必ず
			// 半角スペースかドットなので "0 " または "0." が必須リテラルになる。
			literals: []string{"0 ", "0."},
			patterns: []Pattern{
				// ValidateLine の区切り集合から半角スペースを外し、ドットだけを見る。
				// この幅 1 ガードが本来狙っているのはバージョン文字列風の長いドット
				// 連結で、実際に回帰テストで固定されているのもドット形だけである
				// （TestNumericSeparatorVariantsRejectLongTokenPrefixes）。一方
				// スペースを含めると、箇条書き番号・表のセル番号のような 1 桁の
				// 数字が値の直前に来ただけで棄却されてしまう（1-3-4-4 という数字
				// グルーピングは現実の番号体系に無く、長いトークンの部分一致である
				// 可能性は低い。TestSpaceSeparatedPhoneAllowsSingleDigitPrefix）。
				// 以下のドット区切り固定電話・混在区切り固定電話も同じ理由で
				// スペースを外す。
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0[5-9]0[ .]\d{4}[ .]\d{4}`), Base: Medium,
					ValidateLine: rejectSeparatedDigitGroup(".", 1)},
			},
		},
		{
			// スラッシュ区切り携帯・IP 電話。3 文字目の "0" の直後は必ずスラッシュ。
			literals: []string{"0/"},
			patterns: []Pattern{
				// スラッシュは URL パス区切りとしても一般的で桁形状だけでは判別
				// できないため（"https://.../090/1234/5678"「api/v2/090/1234/5678」等）、
				// 他の区切りあり携帯パターンと異なり RequireContext を必須にして
				// 構造的に FP を避ける。
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0[5-9]0/\d{4}/\d{4}`), Base: Medium, RequireContext: true,
					ValidateLine: rejectSeparatedDigitGroup("/", 1)},
			},
		},
		{
			// 区切りなし携帯・IP 電話。区切り文字を持たないため強い必須リテラルが
			// 無い（"0" だけでは事前判定の意味がほとんど無い）。代わりに
			// internal/detect の patternGate が「連続 11 桁」を要求するため、
			// 数字の短い行はリテラル判定なしでも正規表現に到達しない。
			patterns: []Pattern{
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0[5-9]0\d{8}`), Base: Medium, NegativeContextMode: NegativeContextAdjacentLabelOnly},
			},
		},
		{
			// 区切りあり固定電話（市外局番 2〜5 桁）。末尾は 3〜4 桁を許容し、
			// フリーダイヤル・ナビダイヤル等の末尾 3 桁表記も拾う。区切りは
			// ハイフン 2 個で固定なので "-" が必須リテラル。
			literals: []string{"-"},
			patterns: []Pattern{
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{1,4}-\d{1,4}-\d{3,4}`), Base: Medium, NegativeContextMode: NegativeContextAdjacentLabelOnly},
			},
		},
		{
			// ドット区切り固定電話（携帯のドット区切りパターン、上の
			// 空白・ドット区切り携帯・IP 電話に倣う）。区切りはドット 2 個で固定
			// なので "." が必須リテラル。validPhone は 10 桁でハイフン・空白の
			// いずれも含まない場合、区切りなし固定電話と同じ市外局番辞書
			// （dict.ValidAreaCode）照合に落ちる（strings.ContainsAny による
			// "-"/" " 判定にドットは該当しないため）。そのため、このパターン自体には
			// 市外局番の実在性検証を追加しなくても、ドット区切り表記は自動的に
			// 市外局番の実在性検証がかかる。
			literals: []string{"."},
			patterns: []Pattern{
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{1,4}\.\d{1,4}\.\d{3,4}`), Base: Medium,
					ValidateLine: rejectSeparatedDigitGroup(".", 1)},
			},
		},
		{
			// 混在区切り固定電話（ドット+ハイフン、ハイフン+ドット）。どちらの
			// 並びでもハイフンを 1 個必ず含むため "-" が必須リテラル（ドットも必須
			// だが、OR 条件のリテラル集合は 1 つに絞るほど強く効くため、コード行で
			// より出現しにくいハイフン側を選ぶ）。上のドット単独区切りパターンに
			// 倣い RequireContext なし・Base Medium とする。ただし、上のコメントに
			// ある「ドット単独区切りは自動的に市外局番辞書照合がかかる」仕組みには
			// 乗らない: validPhone は strings.ContainsAny(m, "- ") でハイフン・空白の
			// 有無だけを見て経路を分けるため、この混在形は必ずハイフンを含み、
			// 区切りあり表記と同じ緩い判定（2 桁目が 0 でないことのみ）の経路になる
			// （dict.ValidAreaCode は通らない）。桁構造自体が既に情報量の高い
			// シグナルであるため、他の区切りあり電話パターンと同水準の検証で許容する。
			literals: []string{"-"},
			patterns: []Pattern{
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{1,4}\.\d{1,4}-\d{3,4}`), Base: Medium,
					ValidateLine: rejectSeparatedDigitGroup(".-", 1)},
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{1,4}-\d{1,4}\.\d{3,4}`), Base: Medium,
					ValidateLine: rejectSeparatedDigitGroup(".-", 1)},
			},
		},
		{
			// 括弧市外局番（市外局番の直後に市内局番を括弧書き）。開き括弧が必須。
			literals: []string{"("},
			patterns: []Pattern{
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{1,4}\(\d{1,4}\)\d{4}`), Base: Medium},
			},
		},
		{
			// 括弧市外局番（市外局番全体を括弧で囲む表記）。値は必ず "(0" で始まる。
			literals: []string{"(0"},
			patterns: []Pattern{
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`\(0\d{1,4}\)\s?\d{1,4}-?\d{4}`), Base: Medium},
			},
		},
		{
			// 区切りなし固定電話（10 桁）。裸の \d{10} は型番・伝票番号等との
			// 衝突が非常に多く単独では出せないため、コンテキストキーワード必須
			// （RequireContext）にした上で validPhone が市外局番辞書
			// （dict.ValidAreaCode）で先頭一致の実在性を検証する。区切り文字を
			// 持たないため、上の区切りなし携帯と同じ理由でリテラル事前判定は置かず、
			// patternGate の「連続 10 桁」要求に任せる。
			patterns: []Pattern{
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`0\d{9}`), Base: Medium, RequireContext: true},
			},
		},
		{
			// 国際表記 +81。値は必ず "+81" で始まる。
			literals: []string{"+81"},
			patterns: []Pattern{
				{Re: dgNoDigitBeforeNoAlnumHyphenAfter(`\+81[- ]?\d{1,4}[- ]?\d{1,4}[- ]?\d{3,4}`), Base: High, NegativeContextMode: NegativeContextAdjacentLabelOnly},
			},
		},
	}

	rules := make([]Rule, 0, len(groups))
	for _, g := range groups {
		r := base
		r.PrefilterLiterals = g.literals
		r.Patterns = g.patterns
		rules = append(rules, r)
	}
	return rules
}

// myNumberContext は jp-my-number のコンテキスト語。
var myNumberContext = []string{"マイナンバー", "個人番号", "mynumber", "my number", "my_number"}

// Builtin は組み込みルール一覧を返す。
func Builtin() []Rule {
	rules := []Rule{
		{
			ID:              "jp-my-number",
			Description:     "マイナンバー（個人番号）",
			Prefilter:       PrefilterDigit,
			Context:         myNumberContext,
			NegativeContext: digitRuleUnitAdjacentNegativeContext,
			Validate:        validMyNumber,
			Patterns: []Pattern{
				// rejectDaiGoNumber は古物商許可番号「第<12 桁>号」等の許可・登録番号の棄却
				// （2026-10-30 14:00 に企業サイトの古物商許可番号で偽陽性を実測した）。
				{Re: dgNoAlnumHyphen(`\d{12}`), Base: Medium,
					ValidateLine: allValidateLine(rejectNumericTokenPart, rejectHexDumpGroup, rejectDaiGoNumber)},
				// 前後にハイフンが続く場合はクレジットカード等の
				// 4-4-4-4 グループの一部とみなして除外する。
				{Re: dgNoAlnumHyphen(`\d{4}-\d{4}-\d{4}`), Base: Medium},
				// 空白区切り（4-4-4 / 6-6）。stripSeparators は元々半角スペースを
				// 除去するため Validate 側の変更は不要。
				// rejectNumericTokenPart・rejectHexDumpGroup・rejectLogTimestamp66 は
				// OSS コーパスで実測した偽陽性（小数部・識別子の一部・16 進ダンプ・
				// ログのタイムスタンプ）の棄却（digit_token_guard.go）。
				{Re: dgNoAlnumHyphen(`\d{4} \d{4} \d{4}`), Base: Medium,
					ValidateLine: allValidateLine(rejectSeparatedDigitGroup(" ", 4), rejectNumericTokenPart, rejectHexDumpGroup)},
				{Re: dgNoAlnumHyphen(`\d{6} \d{6}`), Base: Medium,
					ValidateLine: allValidateLine(rejectSeparatedDigitGroup(" ", 6), rejectNumericTokenPart, rejectHexDumpGroup,
						rejectLogTimestamp66(myNumberContext))},
				// ドット区切り（6-6）。「値 = 123456.000007」のような小数リテラルと
				// 区別できないため、上の空白区切りと異なり RequireContext を必須に
				// する（以下のスラッシュ・括弧区切りも同じ理由で必須にする）。Base は
				// 新表記ゆれとして Medium に据え置く。
				{Re: dgNoAlnumHyphen(`\d{6}\.\d{6}`), Base: Medium, RequireContext: true, RequireContextWindow: digitRuleRequireContextWindow,
					ValidateLine: rejectSeparatedDigitGroup(".", 6)},
				// スラッシュ区切り（6-6）。stripSeparators にスラッシュを追加済み
				// なので、区切りを除いた 12 桁でそのまま検査用数字が検証される。
				{Re: dgNoAlnumHyphen(`\d{6}/\d{6}`), Base: Medium, RequireContext: true, RequireContextWindow: digitRuleRequireContextWindow,
					ValidateLine: rejectSeparatedDigitGroup("/", 6)},
				// 括弧区切り（前半 6 桁を丸括弧書き）。dgNoAlnumHyphen の境界ガードが
				// 開き括弧の直前の英数字（"func(123456)000007" のような関数呼び出し
				// 風の表記）を除外するため、数式・関数呼び出しとの衝突は構造的に
				// 避けられる。
				{Re: dgNoAlnumHyphen(`\(\d{6}\)\d{6}`), Base: Medium, RequireContext: true, RequireContextWindow: digitRuleRequireContextWindow},
			},
		},
	}
	// jp-phone-number は「マッチに必ず含まれるリテラル」ごとに複数エントリへ
	// 分割する（理由と等価性の根拠は phoneRules のコメント）。同一 ID の複数
	// エントリは jp-address と同じ扱いで両立する。ルール間の相対順序を変えない
	// よう、元の定義位置（jp-my-number の直後）にそのまま挿入する。
	rules = append(rules, phoneRules()...)
	rules = append(rules, []Rule{
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
				// dgNoAlnumHyphen で英数字・ハイフン連結トークンの内部を除外する
				// （型番やリビジョン番号のような、英数字とハイフンで連結された長い
				// トークンから 3-4 桁部分だけを郵便番号として切り出さないため）。
				{Re: dgNoAlnumHyphen(`\d{3}-\d{4}`), Base: Medium, RequireContext: true},
				// ハイフンなし裸 7 桁。桁数のみでは業務 ID 等と衝突しやすいため
				// コンテキストを必須とし、Validate（dict.ValidPostalCode）が
				// 7 桁完全一致でビットセットに対して実在性を検証するため、
				// パターン固有の追加検証は不要。
				{Re: dg(`\d{7}`), Base: Medium, RequireContext: true},
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
			// 都道府県なしラベル付き住所（jp-address 第 3 エントリ）。既定プロファイル
			// 唯一の住所 FN（例:「住所: 渋谷区神南1-2-3」）を解消する。jp-pii-detector:ignore
			// 都道府県プレフィクス必須の上記 2 エントリでは拾えず、high-recall 限定の
			// jp-address-high-recall でしか拾えなかった。jp-address-high-recall を参考にしつつ
			// ラベル必須化・市区町村辞書ゲートで既定プロファイルでも安全に使えるよう
			// 厳しくする（設計の詳細は addressLabeledPrefix 等のコメント参照）。
			//
			// twin パターン（マーカー付き番地形・ダッシュ番地形の両方に High/Medium
			// の 2 枚組）が必須である理由: high-recall プロファイルでは同じ入力に
			// jp-address-high-recall の High twin も発火しうる。resolveOverlaps の
			// 優先順位は (1)Confidence → (2)内部スコア（高再現率ルールは
			// finalizeFindingScore で -20 の prior）の順であるため、この新エントリも
			// High まで昇格できる twin にしておけば、High 同士の比較で prior の無い
			// jp-address 側が常に勝ち、low/medium/high-recall の 3 プロファイル全部で
			// ルール帰属が安定する。この新エントリが Medium 止まりだと、high-recall
			// プロファイルでの帰属が jp-address-high-recall に化けてしまい評価が壊れる
			// （corpusv2 側の対応する合成ポジティブは、この第 3 エントリと重複しない
			// ラベルなし形へ変更済み。internal/corpusv2/corpusv2.go 参照）。
			ID:                "jp-address",
			Description:       "住所（都道府県〜番地）",
			Prefilter:         PrefilterDigit,
			PrefilterLiterals: []string{"住所", "所在地", "自宅", "居住", "address"},
			Context:           []string{"住所", "所在地", "自宅", "address", "居住"},
			Validate:          addressLabeledMunicipalityValid,
			Patterns: []Pattern{
				// マーカー付き番地（丁目/番/号）。High 側は市区町村マッチ直後の
				// ギャップが ABR 町字マスター由来の実在町字名で始まる場合だけ
				// Pattern.Validate を通過する（jp-address-high-recall と同じ
				// 町字辞書昇格 twin）。
				{Re: addressLabeledMarkedRe, Base: High, Validate: dict.MunicipalityThenTownMatch},
				{Re: addressLabeledMarkedRe, Base: Medium},
				// マーカーなしダッシュ連結。High/Medium 双方に notCalendarDateBanchi
				// （ISO 日付誤検出の棄却）を適用し、High 側だけはさらに
				// dict.MunicipalityThenTownMatch も満たす場合に限る
				// （notCalendarDateBanchiAndRealTown、jp-address-high-recall と
				// 同じ AND 合成。理由は同関数のコメント参照）。
				{Re: addressLabeledDashRe, Base: High, Validate: notCalendarDateBanchiAndRealTown},
				{Re: addressLabeledDashRe, Base: Medium, Validate: notCalendarDateBanchi},
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
				// 同一正規表現の 2 枚組（twin）: 市区町村マッチ直後のギャップが
				// ABR 町字マスター由来の実在町字名で始まれば High、そうでなければ
				// 従来どおり Medium のまま拾う（resolveOverlaps が同一スパンで
				// 信頼度の高い High を残す）。町字辞書は昇格専用のエビデンスで
				// あり、不一致は棄却ではなく Medium への据え置きにしかならない
				// ため recall には影響しない（dict.MunicipalityThenTownMatch の
				// コメント参照）。
				{Re: addressHighRecallMarkedRe, Base: High, Validate: dict.MunicipalityThenTownMatch, ValidateLine: rejectAddressNonAddressNumber},
				{Re: addressHighRecallMarkedRe, Base: Medium, ValidateLine: rejectAddressNonAddressNumber},
				// マーカーなしダッシュ連結にも同じ twin 方式を適用する。High 側の
				// Validate は notCalendarDateBanchiAndRealTown（notCalendarDateBanchi と
				// dict.MunicipalityThenTownMatch の AND 合成）を使い、ISO 日付棄却が
				// High 側でも失われないようにする（経緯・理由は
				// addressHighRecallDashRe・notCalendarDateBanchiAndRealTown 各コメント参照）。
				{Re: addressHighRecallDashRe, Base: High, Validate: notCalendarDateBanchiAndRealTown},
				{Re: addressHighRecallDashRe, Base: Medium, Validate: notCalendarDateBanchi},
			},
		},
		{
			// 漢数字番地・都道府県なし（神南一丁目十九番十一号 等。高再現率）。
			// 既定 jp-address が漢数字用に同一 ID の第 2 エントリを持つのと同じ
			// 手法で、ASCII 数字を含まない行にもマッチさせるため PrefilterDigit
			// ではなく PrefilterCJK + 市区町村リテラルで別途プリフィルタする。
			// ダッシュ形は持たない（漢数字表記では実質使われないため。banchiKanji
			// のコメント参照）。
			ID:                "jp-address-high-recall",
			Description:       "住所（都道府県なし・高再現率）",
			Prefilter:         PrefilterCJK,
			PrefilterLiterals: []string{"市", "区", "町", "村"},
			Context:           []string{"住所", "所在地", "勤務地", "勤務先", "自宅", "address"},
			Validate:          dict.MunicipalitySuffixMatch,
			Patterns: []Pattern{
				// マーカー付き twin と同じ手法（上記コメント参照）。
				{Re: addressHighRecallKanjiRe, Base: High, Validate: dict.MunicipalityThenTownMatch, ValidateLine: rejectAddressNonAddressNumber},
				{Re: addressHighRecallKanjiRe, Base: Medium, ValidateLine: rejectAddressNonAddressNumber},
			},
		},
		{
			ID:          "email-address",
			Description: "メールアドレス",
			Prefilter:   PrefilterAt,
			Validate:    validEmail,
			Patterns: []Pattern{
				// Unicode Letter/Number を含む右境界ガードを捕捉グループの外に置き、
				// user@gmail.com_suffix / user@gmail.com+suffix のように直後が
				// 英数字・_ % + - : で続く（メールアドレスの一部ではない）部分一致を
				// 棄却する。Unicode 文字も境界にしないため、EAI/confusable 候補の
				// ASCII 接尾部だけを通常メールとして報告しない。`:` は
				// git@github.com:owner/repo.git のような
				// scp 形式の SSH URL をメールとして切り出さないために含める。
				// `.` は除外集合に含めないため、文末ピリオド
				// （…は user@example.com.）は従来どおり検出できる。
				//
				// ValidateLine は URL のユーザー情報（"http://gopher@test.com"、
				// "ssh://git@github.com/user/repo"）を棄却する（OSS コーパスでの実測。
				// digit_token_guard.go の rejectURLUserinfo 参照）。
				{Re: emailASCIIRe, Base: High, ValidateLine: rejectURLUserinfo},
			},
		},
		{
			// EAI（国際化メールアドレス）は高再現率モードでのみ有効。
			// 日本語を含む候補と IANA TLD 実在確認に限定し、まず安全側から導入する。
			ID:          "email-address-eai",
			Description: "メールアドレス（EAI・高再現率）",
			Prefilter:   PrefilterAt,
			Validate:    validEAIEmail,
			Patterns: []Pattern{
				{Re: emailEAIRe, Base: High},
			},
		},
		{
			// Unicode confusable は ASCII 中心のメール候補だけを高再現率モードで
			// 検査する。全行の汎用正規化には加えず、位置保存不変条件を維持する。
			ID:          "email-address-confusable",
			Description: "メールアドレス（Unicode confusable・高再現率）",
			Prefilter:   PrefilterAt,
			Validate:    validConfusableEmail,
			Patterns: []Pattern{
				{Re: emailConfusableRe, Base: High},
			},
		},
		{
			ID:              "credit-card",
			Description:     "クレジットカード番号（Luhn + ブランドプレフィックス + 公知テストPAN除外）",
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
				// ValidateLine は OSS コーパスで実測した偽陽性（小数部・識別子の
				// 一部・16 進ダンプ）の棄却（digit_token_guard.go）。
				{Re: dgNoSlashAlnumHyphen(`\d(?:[- ]?\d){12,18}`), Base: High,
					ValidateLine: allValidateLine(rejectNumericTokenPart, rejectHexDumpGroup)},
				{Re: dgNoAlnumHyphen(`\d(?:[- ]?\d){0,5}[- ]\d(?:[- ]?\d){6,17}`), Base: High,
					ValidateLine: allValidateLine(rejectNumericTokenPart, rejectHexDumpGroup)},
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
				// ドット区切り（4-4-4）。このルールは Base High だが、新表記ゆれ形は
				// Base Medium に据え置き、High帯キャリブレーション（validate だけで
				// 精度が出る場合に限り High とする方針）を守る。ValidateLine は
				// 自身の内部グループと同じ幅（4 桁）の隣接ドット区切りグループが
				// あれば、より長い数字列の一部とみなして棄却する
				// （my-number の 4-4-4 空白区切りパターンと同じ手法）。
				{Re: dg(`\d{4}\.\d{4}\.\d{4}`), Base: Medium, RequireContext: true,
					ValidateLine: rejectSeparatedDigitGroup(".", 4)},
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
				// ドット区切り（4-6）。既存のハイフン・空白区切りは書式自体の
				// 情報量が高く Base High だが、ドット区切りは小数点のようにも
				// 見えるため新表記ゆれとして Base Medium に据え置く。
				// stripSeparators は既にドットを除去するため validPensionNumber の
				// AllSame 判定はそのまま効く。
				{Re: dg(`\d{4}\.\d{6}`), Base: Medium, RequireContext: true,
					ValidateLine: rejectSeparatedDigitGroup(".", 1)},
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
				// 空白・スラッシュ区切り（3+4）。normalize.Line が全角スラッシュ
				// 「／」を半角へ畳むため、この 1 パターンで両表記に対応する。
				// validBankAccount は区切り文字を含む生のマッチ文字列に対して
				// AllSame を判定するため、区切りを挟むと全桁同一ダミー
				// （"口座番号 000 0000" 等）を取りこぼす。区切りを除いてから
				// 同じ判定を行う Pattern.Validate を追加する
				// （validPensionNumber 等と同じ手法）。
				{Re: dg(`\d{3}[ /]\d{4}`), Base: Medium, RequireContext: true,
					Validate:     func(m string) bool { return !checksum.AllSame(stripSeparators(m)) },
					ValidateLine: rejectSeparatedDigitGroup(" /", 3, 4)},
			},
		},
		{
			ID:          "jp-yucho-account",
			Description: "ゆうちょ銀行 記号番号",
			Prefilter:   PrefilterDigit,
			// 「通帳」「貯金」はゆうちょの公式用語（通帳記号・通帳番号・貯金
			// 記号）由来。負文脈の採番ラベル接尾辞ヒューリスティック
			// （internal/detect/negative_context.go の hasNumberingSuffixBefore）は
			// 「〜番号」ラベルを抑制対象とみなすため、これらが Context に
			// 無いと「通帳番号: [番号]」のような正当なラベル付きの値が保護規則
			// （ラベル近傍に自ルールの正文脈語があれば抑制しない）から漏れて
			// 誤って棄却される。値の形状（記号 1XXX0）と検査数字の検証が既に
			// 厳しいため、語を広げても FP リスクは小さい。
			Context: []string{"ゆうちょ", "郵便貯金", "記号", "日本郵政", "郵便局", "通帳", "貯金", "yucho", "japan post", "japan post bank"},
			// 銀行名候補の専用経路は「ゆうちょ銀行」表記だけを文脈として使う。
			// 任意の銀行名は通常の銀行口座ルール（jp-bank-account）側の文脈で扱う。
			ContextPatterns: []ContextPattern{
				{Re: bankNameCandidateRe, Validate: isYuchoBankName, ValidateSuffixes: true, Literals: bankNameSuffixes},
			},
			NegativeContext:      digitRuleNegativeContext,
			RequireContextWindow: digitRuleRequireContextWindow,
			Patterns: []Pattern{
				// 記号（5 桁、先頭 "1"・末尾 "0"）＋番号（7〜8 桁、末尾は必ず
				// "1"）をハイフンで相関させた表記。通帳の再発行時は記号と番号の
				// 間に 1 桁の再発行区分が挟まる（「記号-1桁-番号」。ゆうちょ銀行
				// 公式変換サービスが「記号と番号の間の 1 桁の数字は入力しない」と
				// 案内する、振込等で使用しない桁）ため、`\d-` を任意で許容する。
				// 記号 4 桁目は、ゆうちょ銀行公式変換サービスの公開 JavaScript に
				// ある検査式で検証する（checksum.YuchoAccount の出典コメントを
				// 参照。再発行区分は parseYuchoDashForm が読み飛ばし、検査数字の
				// 対象にならない）。
				{Re: dgNoAlnumHyphen(`1\d{3}0-(?:\d-)?\d{6,7}1`), Base: High, RequireContext: true, Validate: validYuchoAccount},
				// ハイフンの代わりに半角スペース 1 つで記号・番号を並べた表記
				// （「記号番号 [記号5桁] [番号]」のような転記形。全角スペースは
				// normalize.Line が半角へ畳む）。jp-bank-account の 3+4 桁スペース
				// 区切り対応と同じ区切り表記ゆれの吸収で、形状・検査数字は
				// ハイフン形と同一基準で検証する（数字だけを抽出して判定する
				// validYuchoLabeledAccount をそのまま使う）。
				{Re: dgNoAlnumHyphen(`1\d{3}0 \d{6,7}1`), Base: High, RequireContext: true, Validate: validYuchoLabeledAccount},
				// 記号・番号のラベルが同一行で別々に書かれる形式（"記号 11111
				// 番号 11111111" 相当の並び。ラベル直結・コロン・スペース区切り
				// いずれも許容）。JSON/YAML の同一行ペア（"記号"・"番号" キーが
				// 引用符で囲まれ、カンマ・読点で区切られる形）にも対応するため、
				// ラベル・値を囲む引用符・鉤括弧と値間の区切り（カンマ・読点）を
				// 任意で許容する（引用符等はグループ 1 に含まれうるが、
				// validYuchoLabeledAccount は数字だけを抽出して判定する）。
				// 同一行のラベル形式は対応済み。別行形式も
				// ScanContent の専用ペア走査で対応済み（internal/detect/yucho_pair.go
				// の scanCrossLineYuchoPairs。rule.CrossLineYuchoSymbolRe /
				// CrossLineYuchoNumberRe / ValidCrossLineYuchoPair を使用。diff 走査は
				// scanCrossLineYuchoPairsDiff が対応）。捕捉値（グループ1）は記号側の
				// 数字先頭から番号側の数字末尾まで（間の「番号」ラベルを含む）とし、
				// ラベル語「記号」自体はグループ外に置く。間に非数字のラベルを挟む
				// ため dg ヘルパーはグループを二重にしてしまい使えず、境界ガード
				// （前後が数字でないこと）を自前で書く。このコメント自体が
				// dogfooding で自己検出されないよう、上の例は全桁同一のダミー値
				// （Validate で棄却される形）だけを書く。
				{Re: regexp.MustCompile(
					`(?:^|[^0-9])記号["']?\s*[:=]?\s*["'「]?(1\d{3}0["'」]?\s*[,、:=]?\s*["'「]?番号["']?\s*[:=]?\s*["'「]?\d{6,7}1)(?:[^0-9]|$)`,
				), Base: High, RequireContext: true, Validate: validYuchoLabeledAccount},
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
			// 全パターンがラベル（前置の birthdateLabel、または後置の「生まれ」）を
			// 必須とするため、そのラベル語を 1 つも含まない行は正規表現走査ごと
			// スキップできる。境界ガードや文字クラスで始まる数字系ルールの正規表現は、
			// Go regexp の先頭リテラル最適化（regexp.prefix）が効かず行の全位置から
			// バックトラッカーが走るため、この事前判定が数字を含むコード行の
			// ホットパスで効く（phoneRules のコメントに実測値）。
			//
			// リテラルが必要条件である根拠（TestBirthdatePrefilterLiteralsAreMandatory）:
			// birthdateLabel の選択肢は 生年月日 / 誕生日 / birth date / birthdate /
			// birthday / date_of_birth / date of birth / dob で、英語側はすべて
			// "birth" か "dob" を部分文字列として含む（大小文字は containsAnyLiteral が
			// 行側を小文字化して吸収する）。後置ラベルのパターンは「生まれ」を必須とする。
			PrefilterLiterals: []string{"生年月日", "誕生日", "生まれ", "birth", "dob"},
			// 形式（西暦・和暦・区切りなし8桁）だけでなく、実在する暦日かを検証する。
			// 2023-99-99 や 2023-02-29（閏年でない）などを棄却する。
			Validate: validBirthdate,
			Patterns: []Pattern{
				// 区切りあり形式。西暦 4 桁、または和暦（元号の漢字表記 or
				// 明治/大正/昭和/平成/令和を表す単字アルファベット略記 M/T/S/H/R）＋
				// 年（1-2 桁の数字、または改元年を表す「元」）。
				{Re: regexp.MustCompile(
					birthdateLabel + birthdateLabelSep +
						`((?:(?:19|20)\d{2}|(?:明治|大正|昭和|平成|令和|[MTSHRmtshr])(?:元|\d{1,2}))[年/.-]\d{1,2}[月/.-]\d{1,2}日?)`,
				), Base: Medium},
				// ラベル直結・区切りなしの 8 桁連結（YYYYMMDD）。DB エクスポート等で
				// 最頻出の表記。月日のレンジをパターン側で絞り込み、ラベルへの
				// 直結を必須とすることで、処理日・有効期限など無関係な 8 桁列や、
				// ラベルなしの裸 8 桁を拾わない。
				{Re: regexp.MustCompile(
					birthdateLabel + birthdateLabelSep +
						`((?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))(?:[^0-9]|$)`,
				), Base: Medium},
				// 後置ラベル「生まれ」（値→ラベル順で前置ラベルが無いケース。
				// 実測 FN「1985年1月2日生まれ」相当）。jp-pii-detector:ignore
				// 上の区切りあり値パターン（第 1 パターン）の捕捉本体をそのまま
				// 流用し、前方に数字境界ガード（(?:^|[^0-9])）、後方に「生まれ」を
				// 必須とする。区切りなし8桁の後置ラベル形は実測未確認のため対象外。
				{Re: regexp.MustCompile(
					`(?:^|[^0-9])((?:(?:19|20)\d{2}|(?:明治|大正|昭和|平成|令和|[MTSHRmtshr])(?:元|\d{1,2}))[年/.-]\d{1,2}[月/.-]\d{1,2}日?)生まれ`,
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
				// 空白区切り8桁（4+4）。8桁連結時と同じ RequireContext・窓
				// （ルール既定の 40 ルーン）を使う。validHealthInsurance は区切り
				// 文字を含む生のマッチ文字列に対して AllSame を判定するため、
				// 空白を挟むと全桁同一ダミー（"保険者番号 0000 0000" 等）を
				// 取りこぼす。区切りを除いてから同じ判定を行う Pattern.Validate を
				// 追加する。
				{Re: dg(`\d{4} \d{4}`), Base: Medium, RequireContext: true,
					Validate:     func(m string) bool { return !checksum.AllSame(stripSeparators(m)) },
					ValidateLine: rejectSeparatedDigitGroup(" ", 4)},
				// 国民健康保険の保険者番号は 6 桁。日常的な数字との衝突が大きい
				// ため、既存の広い文脈語（「保険証」「被保険者」等）だけでは
				// 発火させず、正規表現自体にも強ラベル「保険者番号」と通常の
				// 区切りだけを埋め込む。「被保険者番号」は別の番号なので、直前の
				// 「被」から始まる部分一致を除外する。RequireContextWindow も 12
				// ルーンへ狭め、長い説明を挟んだ受付 ID・金額等を拾わない。
				// 検査用数字は厚生省通知（昭和49年9月20日 保険発第104号）の
				// M10W21 算式を validHealthInsurance で検証する。
				{Re: regexp.MustCompile(
					`(?:^|[^被])保険者番号[[:space:]　]*[:：=]?[[:space:]　]*(\d{6})(?:[^0-9A-Za-z-]|$)`,
				), Base: Medium, RequireContext: true, RequireContextWindow: healthInsurance6DigitContextWindow},
				// 帳票等の「値→ラベル」順と、値行の次にラベル行が来る表記も
				// 同じ強ラベル・狭い窓で扱う。
				{Re: regexp.MustCompile(
					`(?:^|[^0-9A-Za-z-])(\d{6})[[:space:]　]*[:：=]?[[:space:]　]*保険者番号(?:[^0-9]|$)`,
				), Base: Medium, RequireContext: true, RequireContextWindow: healthInsurance6DigitContextWindow},
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
				// 区切りあり（4桁-6桁-1桁）は当初、書式自体が固有の形状のため
				// コンテキストなしで High としていたが、実測でリビジョン表記
				// （「リビジョン 2024-123456-7 をデプロイ」）・業務ロット番号
				// （「部品ロット 8907-654321-3」）と衝突することが確認されたため、
				// 他の桁ベースパターンと同様にコンテキスト必須（RequireContext）へ
				// 変更した。
				{Re: dg(`\d{4}-\d{6}-\d`), Base: High, RequireContext: true},
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
			//
			// 裏取り調査の結果（2026-07-12 時点）: 算式は住民基本台帳法施行規則
			// （平成11年自治省令第35号）第1条第2号が「総務大臣が定める算式」として
			// 平成14年総務省告示第436号へ委任する。国立国会図書館「日本法令索引」は
			// 告示の題名・公布日・現行有効を確認できるが、本文リンクを「該当する情報は
			// ありません」としている。e-Gov・官報発行サイトの無料公開範囲・総務省公開
			// 資料でも原文に到達できなかったため、官報原本を確認するまで形状＋文脈のみを
			// 維持する（出典 URL は docs/detection-methods.md 4.1 節）。
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
			// 登録番号は国税庁の適格請求書発行事業者公表サイトで公開される情報のため
			// kind=public-business を付与する（PublicBusinessKind、identifier_kind.go）。
			// ノイズになる場合は [rules] exclude_kinds = ["public-business"] で除外可能。
			Kind: PublicBusinessKind,
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
				{Re: personNameStrongLabelRe, Base: Medium, Validate: dict.IsPersonName, ValidateLine: rejectBracketedFormHint},
				{Re: personNameStrongLabelRe, Base: Low, Validate: notFormWordValue, ValidateLine: rejectBracketedFormHint},
				// 弱いラベル: 姓側（姓・名字・苗字・last_name）。validSurnameField が
				// 姓名辞書で検証済み（単独要素は 2 文字以上の姓、または姓+名に
				// 分割できる氏名のみ許可）のため、Base は Medium。
				{Re: regexp.MustCompile(
					personNameBoundary +
						`(?:姓|名字|苗字|(?i:last_?name))` +
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
						`(?:姓|名字|苗字|(?i:last_?name))` +
						personNameSep +
						personNameValueShortFallback,
				), Base: Medium, Validate: validSurnameField},
				// 弱いラベル: 名側（名・first_name）。validGivenField が姓名辞書で
				// 検証済み（単独要素は 2 文字以上の名、または姓+名に分割できる
				// 氏名のみ許可。1 文字名（学・実 等）と姓（名: 田中）は棄却）
				// のため、Base は Medium。
				{Re: regexp.MustCompile(
					personNameBoundary +
						`(?:名|(?i:first_?name))` +
						personNameSep +
						`(` + personNameValueShort + `)`,
				), Base: Medium, Validate: validGivenField},
				// 名側の見逃し修正フォールバック（姓側と同様）。
				{Re: regexp.MustCompile(
					personNameBoundary +
						`(?:名|(?i:first_?name))` +
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
			// 担当者・宛名・連絡先ラベルは既定で有効にする（高再現率オプトイン
			// 不要）。日本語の業務文書では「担当:」「宛名:」は「氏名:」と同等の
			// 頻度で使われるアンカーであり、既定で取りこぼすと初見の利用者が
			// 「氏名が検出されない」と受け取るため。敬称アンカー
			// （person-name-high-recall）と分離したのは、敬称の側が「現行仕様」
			// 「非一様」「実在氏名」のように日常語の内部と衝突して既定に置けない
			// のに対し、こちらは姓名辞書ゲートだけで実測の誤検出を抑えられる
			// ため（判定根拠が違うので信頼度プロファイルも別になる）。
			ID:                "person-name-role-label",
			Description:       "氏名（担当者・宛名ラベル付き）",
			Prefilter:         PrefilterCJK,
			PrefilterLiterals: []string{"会長", "委員", "議長", "担当", "宛名", "連絡先", "代表", "代 表", "取締役", "監査役", "弁護士", "弁理士", "司法書士", "行政書士", "税理士", "公認会計士", "社会保険労務士", "裁判官", "長 ", "申立人", "請求人", "原告", "被告", "控訴人", "上告人", "総代", "こと", "個人", "業者", "業 者", "業  者", "内線", "（以下「", "(以下「", "官 ", "業務禁止", "(", "（", "長 ", "官", "責任者", "担当役", "知事", "教授", "講師", "長：", "長:", "頭取：", "CEO", "ＣＥＯ", "番", "長 :", "講演者", "審査員", "コーディネーター", "ファシリテーター", "オブザーバー", "パネリスト", "氏", "届", "監督", "先生"},
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
				// 代表者ラベル（行政処分・登記・特定商取引法表示で法人代表者を示す）。
				// 法人の役員の氏名も生存する個人を識別できる情報であり個人情報に当たる。
				// 「代表者：代表取締役 姓 名」のように役職名を挟む表記と、PDF 抽出で
				// 生じる「代 表 者」の字間スペースを許容する。値の検証は担当者ラベルと
				// 同じ姓名辞書ゲート（姓+名は Medium、単独の姓は Low）。
				{Re: personNameRepLabelRe, Base: Medium, Validate: validPersonNameFullSplit},
				{Re: personNameRepLabelRe, Base: Low, Validate: validPersonNameSurnameOnly},
				// 士業・裁判官の肩書 + 空白 + 氏名（判決書の当事者欄・登記の申請代理人欄）。
				// 弁護士・裁判官等の氏名も生存する個人を識別でき個人情報に当たる。
				// コロンのない表記のため、単独の姓（Low）は報告せず姓+名の完全分割のみ
				// Medium で報告する（「弁護士 費用」等の一般語は辞書ゲートで落ちる）。
				{Re: personNameProfessionTitleRe, Base: Medium, Validate: validPersonNameFullSplit},
				// 問合せ先欄の「役職 + 姓 + Tel」。役職と電話ラベルで挟まれた位置は担当者名で
				// あることがほぼ確実なため、姓のみの一致も Medium で報告する（地名と同形の姓
				// でもこの位置では人名として読む）。
				{Re: personNameContactTitleRe, Base: Medium, Validate: validPersonNameSurnameOrFull},
				{Re: personNameContactTitlePhoneRe, Base: Medium, Validate: validPersonNameSurnameOrFull},
				// 読み括弧付きの「<姓> <名>（<せい> <めい>）」、コロンなしの「担当 <姓>（<よみ>）」、
				// 職名 + 空白区切りの姓名で終わる行。いずれも人名の構造（読み・職名 + 行末）を
				// 要求したうえで姓名辞書の姓で検証する。
				{Re: personNameWithReadingRe, Base: Medium, Validate: validSpacedSurnameGiven},
				{Re: personNameTantoReadingRe, Base: Medium, Validate: validPersonNameSurnameOrFull},
				{Re: personNameTitleLineEndRe, Base: Medium, Validate: validSpacedSurnameGiven},
				{Re: personNameTantoDeptSlashRe, Base: Medium, Validate: validPersonNameSurnameOrFull},
				{Re: personNameTantoDeptSlash2Re, Base: Medium, Validate: validPersonNameSurnameOrFull},
				{Re: personNameTantoListRe[0], Base: Medium, Validate: validPersonNameSurnameOrFull},
				{Re: personNameTantoListRe[1], Base: Medium, Validate: validPersonNameSurnameOrFull},
				{Re: personNameTantoListRe[2], Base: Medium, Validate: validPersonNameSurnameOrFull},
				{Re: personNameTantoListRe[3], Base: Medium, Validate: validPersonNameSurnameOrFull},
				{Re: personNameOrgHeadColonRe, Base: Medium, Validate: validFullSplitOrSpacedSurnameGiven},
				{Re: personNameOrgHeadColonIkaRe, Base: Medium, Validate: validPersonNameFullSplit},
				// 会議録の出席者表の議席番号 + 姓名（2026-10-30 12:00 に実測した見逃し）。
				{Re: personNameSeatNumberRe, Base: Medium, Validate: validSpacedSurnameGiven},
				// 代表権のある役職名 + 空白/「である」/括弧 + 氏名（行政処分の公表文書の本文）。
				// 「代表者：」ラベルを伴わないため、姓+名の完全分割のみ Medium で報告する。
				{Re: personNameExecTitleRe, Base: Medium, Validate: validPersonNameFullSplit},
				{Re: personNameExecTitleAndRe, Base: Medium, Validate: validPersonNameFullSplit},
				// 当事者ラベル（審査申立人・原告 等）+ 空白 + 氏名と「（総代）氏名」。
				// 「原告 主張」「被告 会社」等の一般語は姓名辞書ゲートで落ちる。
				{Re: personNamePartyLabelRe, Base: Medium, Validate: validPersonNameFullSplit},
				// 個人事業主の「<屋号>こと<姓><名>」と、「<姓><名>（個人）」の括弧書き。
				{Re: personNameYagoKotoRe, Base: Medium, Validate: validPersonNameFullSplit},
				{Re: personNameKojinSuffixRe, Base: Medium, Validate: validPersonNameFullSplit},
				// 処分対象欄「事業者：<姓> <名>」と「「<姓><名>」（以下「事業者」という。）」。
				{Re: personNameBusinessOperatorLabelRe, Base: Medium, Validate: validPersonNameFullSplit},
				{Re: personNameDefinedAsOperatorRe, Base: Medium, Validate: validPersonNameFullSplit},
				// 監督処分簿の「代表者氏名  <姓> <名>」（コロンなし）と「<姓><名>に対する業務禁止命令」。
				{Re: personNameRepNameSpacedRe, Base: Medium, Validate: validPersonNameFullSplit},
				// 決算短信・適時開示の表紙の「(役職名) <役職> (氏名) <姓> <名>」（2026-10-30 14:00 に実測した見逃し）。
				{Re: personNameKessanHeaderRe, Base: Medium, Validate: validFullSplitOrSpacedSurnameGiven},
				// 同じ表紙で、姓が辞書にない（珍しい姓の）空白区切りの 2 語は Low で報告する。
				{Re: personNameKessanHeaderRe, Base: Low, Validate: validKessanSpacedPair},
				{Re: personNameBanOrderRe, Base: Medium, Validate: validPersonNameFullSplit},
				// 講師・審査員等のラベル + 氏名、「<姓><名>氏（<所属>）」、戸籍の届出欄、
				// 宛名欄の均等割付の姓名 + 様（いずれも 2026-10-30 06:00 に実測した見逃し）。
				{Re: personNameLecturerLabelRe, Base: Medium, Validate: validPersonNameFullSplit},
				{Re: personNameLecturerLabel2Re, Base: Medium, Validate: validPersonNameFullSplit},
				{Re: personNameShiAffiliationRe, Base: Medium, Validate: validFullSplitOrSpacedSurnameGiven},
				{Re: personNameKosekiTodokeRe, Base: Medium, Validate: validSpacedSurnameGiven},
				{Re: personNameKosekiTodoke2Re, Base: Medium, Validate: validSpacedSurnameGiven},
				{Re: personNameTitleHonorificWideRe, Base: Medium, Validate: validSpacedSurnameGiven},
				// 会議録の出席者欄「<姓><名>会長、<姓><名>委員、」、空白区切りの「講師 <姓> <名>さん」、
				// 様式の「担当者 <姓> <名>」（いずれも 2026-10-30 08:00 に実測した見逃し）。
				{Re: personNameCommitteeListRe, Base: Medium, Validate: validPersonNameFullSplit, ValidateLine: rejectCommitteeListTail},
				{Re: personNameLecturerSpaceRe, Base: Medium, Validate: validPersonNameFullSplit},
				{Re: personNameTantoSpaceRe, Base: Medium, Validate: validPersonNameFullSplit},
				// 担当欄・代表者欄で姓と名の間が広く空いた表記（2026-10-30 10:00 に実測した見逃し）。
				{Re: personNameTantoWideRe, Base: Medium, Validate: validSpacedSurnameGiven},
				{Re: personNameExecTitleWideRe, Base: Medium, Validate: validSpacedSurnameGiven},
				// 敬称のない「講師 <姓> <名>（<所属>）」、作品一覧の「「<作品名>」監督 <姓名>」、
				// 講師一覧の「<姓> <名> 先生」の行（いずれも 2026-10-30 16:00 に実測した見逃し）。
				{Re: personNameLecturerSpaceParenRe, Base: Medium, Validate: validFullSplitOrSpacedSurnameGiven},
				{Re: personNameDirectorCreditRe, Base: Medium, Validate: validPersonNameFullSplit},
				{Re: personNameSenseiLineRe, Base: Medium, Validate: validSpacedSurnameGiven},
			},
		},
		{
			ID:                "person-name-high-recall",
			Description:       "氏名（敬称アンカー付き・高再現率）",
			Prefilter:         PrefilterCJK,
			PrefilterLiterals: []string{"様", "さん", "氏", "殿"},
			Validate:          notPlaceholderName,
			Patterns: []Pattern{
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
				), Base: Medium, Validate: honorificPersonNameValid,
					// 「新品同様」「構文仕様」のような一般語の「様」と、
					// 「初見さん」「常連さん」「社員皆さん」のような一般語 + 敬称を棄却する。
					ValidateLine: allValidateLine(rejectYouCompound, rejectHonorificCommonNoun, rejectShimeiCompound, rejectHonorificWordCompound, rejectHistoricalUjiName, rejectGradePrefix, rejectShrineHall, rejectHonorificTitlePrefix)},
				// 「<町名>町長<姓><名>様」のように職名に地続きの氏名。上の無空白パターンは職名まで値に
				// 含めるため rejectHonorificTitlePrefix で棄却し、ここで職名を除いた範囲を拾い直す
				// （2026-10-30 10:00 に実測した範囲の誤り）。
				{Re: personNameHonorificAfterTitleRe, Base: Medium, Validate: honorificPersonNameValid,
					ValidateLine: allValidateLine(rejectKaishaChoPrefix, rejectYouCompound, rejectHonorificCommonNoun, rejectShimeiCompound, rejectHonorificWordCompound, rejectHistoricalUjiName)},
				// 「6年生<姓><名>さん」「2年<姓><名>さん」のように学年の直後に続く氏名。上の無空白
				// パターンは「年生<姓><名>」まで値に含めてしまうため rejectGradePrefix で棄却し、
				// ここで学年を除いた範囲を拾い直す（2026-10-30 08:00 に実測した範囲の誤り）。検証は
				// 上の無空白パターンと同じ honorificPersonNameValid（辞書にない子どもの名も残す）。
				{Re: regexp.MustCompile(
					`[0-9]年生?([` + kanji + `]{3,8})(?:さん|くん|ちゃん|様|氏)`,
				), Base: Medium, Validate: honorificPersonNameValid,
					// 学年の後の値も上の無空白パターンと同じ一般語・団体名の棄却を通す。
					ValidateLine: allValidateLine(rejectYouCompound, rejectHonorificCommonNoun, rejectShimeiCompound, rejectHonorificWordCompound, rejectHistoricalUjiName)},
				// 敬称の直前に空白が入る形（「鈴木一郎 様」）と、姓名の間に空白が
				// 入る形（「山田 太郎様」）。上の無空白パターンは値と敬称が地続きの
				// ときしか一致しないため、フォーム・宛名書きで一般的なこの表記を
				// 取りこぼしていた。
				//
				// 空白入りは「対応 様」「現行 仕様」のようなテンプレート断片・
				// 分かち書きとも衝突しうるため、辞書未収録値を通す
				// honorificPersonNameValid（notRoleWord フォールバック）は使わず、
				// 姓+名の分割が成立する値だけを許可する（validPersonNameFullSplit）。
				// 無空白パターンより検証を厳しくするのは、区切りが増えるぶん
				// 「たまたま敬称の前に置かれた 2 文字漢字」の可能性が上がるため。
				{Re: regexp.MustCompile(
					`(?:^|[^` + kanji + hiragana + katakana + `])` +
						`([` + kanji + `]{1,8}[ ][` + kanji + `]{1,8})[ ]?(?:様|さん|氏|殿)`,
				), Base: Medium, Validate: validPersonNameFullSplit},
				{Re: regexp.MustCompile(
					`(?:^|[^` + kanji + hiragana + katakana + `])` +
						`([` + kanji + `]{2,8})[ ](?:様|さん|氏|殿)`,
				), Base: Medium, Validate: validPersonNameFullSplit},
				// 敬称アンカー（ひらがな・カタカナの氏名 + 様/さん/氏/殿）。この
				// 文字種には notRoleWord のような語尾 denylist が効かないほど
				// 日常語との衝突が多いため、辞書一致必須の allowlist 方式
				// （dict.IsPersonNameExtended）で検証する。既定の opti 辞書に加え、
				// org 版カタカナ名はこの高再現率経路だけで許可する。辞書収録済みのひらがな名
				// （例: さくら）は敬称付きでも検出され、日常語（例: たくさん・
				// みなさん）は辞書不在で棄却される。
				{Re: regexp.MustCompile(
					`(?:^|[^` + kanji + hiragana + katakana + `])` +
						`([` + hiragana + katakana + `]{2,8})(?:様|さん|氏|殿)`,
				), Base: Medium, Validate: dict.IsPersonNameExtended,
					// 「サンタさん」のような一般語 + 敬称を棄却する（honorificCommonNouns）。
					ValidateLine: rejectHonorificCommonNoun},
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
			ID:          "person-name-roster",
			Description: "氏名（名簿ファイル・オプトイン）",
			Prefilter:   PrefilterCJK,
			// このルールも単一行パターンを持たない。ラベルも敬称も無く氏名だけが
			// 改行区切りで並ぶファイル（名簿・宛名リスト）を、
			// detect.scanNameRosterFile がファイル全体の統計（行全体が氏名の形を
			// していて、かつ ValidRosterName を通る行の割合）から判定する。
			// 行単位の手がかりが一切無いため、既定でも --high-recall でも無効で、
			// 専用の opt-in（[rules] name_roster / --name-roster）でのみ有効になる
			// （NameRosterRuleIDs）。
		},
		{
			ID:          "person-name-romaji",
			Description: "氏名（ローマ字表記・高再現率）",
			// 値が ASCII 文字（[A-Za-z]）のみのため PrefilterCJK は使えない
			// （person-name ルールは CJK 前提でこの行を素通りする）。代わりに
			// PrefilterLiterals の "name" だけでホットパスを絞る。
			Prefilter:         PrefilterNone,
			PrefilterLiterals: []string{"name"},
			// 姓辞書・名辞書の共起（語順不問）を必須にする。長音省略ヘボン式
			// （Ito/Saito）と OH 表記（Itoh/Ohno）は辞書読み込み時の機械派生で
			// 併録済み（internal/dict の loadRomaji 参照）。マクロン付き表記
			// （Itô/Itō 等）や、辞書外の英単語（Ken/Kai/Mori 等）との衝突は
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
				// 大文字表記（NAME: / Name:）も person-name の同ラベルと同様に拾う。
				{Re: regexp.MustCompile(
					personNameBareNameBoundary +
						`(?i:name)` +
						personNameSep +
						`(` + romajiNameValue + `)` + romajiNameEndBoundary,
				), Base: Medium},
			},
		},
	}...)
	// 数字列ルールに共通の周辺文脈ガード（小数・16 進トークン・URL の ID・
	// Firebase アプリ ID）を合成する（numeric_context_guard.go）。
	return withNumericContextGuard(rules)
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
// 「ゆうちょ記号5桁-番号7桁」（再発行区分 1 桁が挟まる「記号-1桁-番号」、および
// 半角スペース区切りの「記号 番号」を含む）の番号部分だけを拾う隣接汚染を防ぐ。
// ゆうちょ形式全体は jp-yucho-account が専用の文脈と境界で判定する。
// スペース区切りはハイフンより偶発的な隣接（独立した別番号が並ぶだけ）が
// 起きやすいため、記号の完全な形状（先頭 "1"・末尾 "0"）と番号末尾 "1" まで
// 要求して、正当な 7 桁口座番号の巻き添え棄却を避ける。
func rejectYuchoAccountSuffix(line string, start, end int) bool {
	// yuchoSymbolBefore は line[sepIdx] の区切り文字の直前 5 バイトが
	// ゆうちょ記号の候補（数字 5 桁・先頭 "1"。requireTrailingZero なら
	// さらに末尾 "0"）かを返す。
	yuchoSymbolBefore := func(sepIdx int, requireTrailingZero bool) bool {
		if sepIdx < 5 {
			return false
		}
		symbol := line[sepIdx-5 : sepIdx]
		if symbol[0] != '1' || (requireTrailingZero && symbol[4] != '0') {
			return false
		}
		for i := 1; i < len(symbol); i++ {
			if symbol[i] < '0' || symbol[i] > '9' {
				return false
			}
		}
		return true
	}
	if start < 1 {
		return true
	}
	switch line[start-1] {
	case '-':
		// 記号-番号（従来形）。
		if yuchoSymbolBefore(start-1, false) {
			return false
		}
		// 記号-再発行区分1桁-番号（parseYuchoDashForm と同じ読み飛ばし）。
		if start >= 3 && line[start-3] == '-' && line[start-2] >= '0' && line[start-2] <= '9' &&
			yuchoSymbolBefore(start-3, false) {
			return false
		}
	case ' ':
		// 記号 番号（スペース区切り形）。
		if end > start && line[end-1] == '1' && yuchoSymbolBefore(start-1, true) {
			return false
		}
	}
	return true
}

// validHealthInsurance は健康保険の 8 桁番号では全桁同一ダミー値だけを棄却し、
// 国民健康保険の 6 桁保険者番号ではさらに M10W21 の検証番号を確認する。算式は
// 厚生省保険局国民健康保険課長通知「診療報酬明細書等に記載される保険者番号の
// 設定について」（昭和49年9月20日 保険発第104号）を一次資料とする。
func validHealthInsurance(m string) bool {
	if checksum.AllSame(m) {
		return false
	}
	return len(m) != 6 || checksum.Modulus10Weight21(m)
}

// validPassport は旅券（パスポート）番号（英字 2 + 数字 7）の末尾 7 桁が
// 全桁同一の明らかなダミー値（0000000 等）を棄却する。ICAO Doc 9303 Part 4
// 4.2.2.2 は旅券番号を発行国が定める最大 9 文字としており、日本の冊子記号の
// 発行範囲（先頭 T/M 等）は規定しない。外務省の公開資料にもその割当規則はない
// ため、標本から推測した先頭文字制限は導入しない（2026-07 再調査）。
// https://www.icao.int/publications/Documents/9303_p4_cons_en.pdf
// https://www.mofa.go.jp/mofaj/ca/pss/page23_003544.html
func validPassport(m string) bool {
	if len(m) < 7 {
		return false
	}
	return !checksum.AllSame(m[len(m)-7:])
}

// validResidenceCard は在留カード番号（英 2 + 数 8 + 英 2）のうち、数字 8 桁が
// 全桁同一のダミー値を棄却する。出入国在留管理庁「第2世代在留カード等仕様書」
// Ver 1.1（3.3.4.3、2026-04）は、番号を JIS X 0201 の「英字＋数字」12 バイト、
// 詳細を「年度/発行組織/年齢区分/その他」とだけ公開し、検査式も I/O 除外も
// 規定していない。したがって、未公開の割当・検査式を推測して棄却しない。
// https://www.moj.go.jp/isa/content/001460711.pdf
func validResidenceCard(m string) bool {
	if len(m) != 12 {
		return false
	}
	return !checksum.AllSame(m[2:10])
}

func validPhone(m string) bool {
	d := stripSeparators(strings.TrimPrefix(m, "+"))
	if checksum.AllSame(d) {
		return false
	}
	// 昇順・降順の連番のみ（0123456789 等）はプレースホルダとして棄却する。
	// 市外局番辞書の完全化（総務省一次データ 387 件）で 0123（恵庭・千歳）の
	// ような連番プレフィックスも実在局番として一致するようになり、辞書照合
	// だけではこの種のダミー値を弾けなくなったため、マイナンバー・運転免許と
	// 同じ棄却基準に揃える。実在の加入者番号が偶然完全な連番になるケースは
	// 棄却されるが、プレースホルダとの区別は値からは付かないため許容する。
	if checksum.IsZeroPaddedSequential(d) {
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
		// 実在性を検証する。区切りあり表記にはこの辞書を必須にしない
		// （区切りあり表記は形状自体の情報量が高く、市外局番の新設・統合など
		// 辞書の鮮度リスクで FN を出さないため）。
		_, ok := dict.ValidAreaCode(d)
		return ok
	case 11:
		return d[1] >= '5' && d[1] <= '9' && d[2] == '0'
	}
	return false
}

// parseYuchoDashForm はゆうちょ銀行の記号（5 桁・先頭 "1"・末尾 "0"）・番号
// （7〜8 桁・末尾 1）がハイフンで相関した表記（jp-yucho-account 第 1 パターンの
// 捕捉値、例「1XXX0-XXXXXXX1」）を記号・番号へ分解する。通帳の再発行時は記号と
// 番号の間に 1 桁の再発行区分が挟まる（「1XXX0-X-XXXXXXX1」。ゆうちょ銀行公式
// 変換サービスが「記号と番号の間の 1 桁の数字は入力しない」と案内する、振込等で
// 使用しない桁）ため、「数字 1 桁＋ハイフン」を任意で読み飛ばす。桁数・先頭/末尾
// だけを見る形状検証で、検査数字・全桁同一の判定は行わない（呼び出し側が
// yuchoAccountChecksumOK で行う。再発行区分は検査数字の対象にならない）。
//
// 記号 5 桁目 = 0 を要求するのは、あくまで「振込可能な口座」（通常貯金・通常貯蓄
// 貯金・振替）に限った制約であって、ゆうちょの記号一般の性質ではない。この制約は
// 国税庁が配布する納付書記載要領
// （https://www.nta.go.jp/taxes/nozei/nofu/pdf/24100030_5.pdf）と、ゆうちょ銀行
// 公式変換サービスの公開 JavaScript が入力チェック（validate()）で記号の末尾 0 を
// 要求することで裏付けられる。ただし後者はあくまで「このツールの対象外」を弾く
// 入力サニティガードであり、変換ロジック本体（checkdigit）は 5 桁目を読んでいない。
//
// 二次情報では、記号 5 桁目は全体としては 0 以外（3・4・7 等）も取り、先頭 1 かつ
// 5 桁目 ≠0 の甲種団体貯金、先頭 2〜5 の定額・定期・財形といった記号体系が実在
// する。本実装はこれらの商品に未対応であり、既知の検出漏れである。誤って「実在
// しない形状」と決めつけて無効判定へ倒すと、本物の PII を取りこぼすうえに
// internal/corpusv2 が評価コーパスの陽性を陰性へ読み替えてしまうため、未対応の
// 記号体系はここでパース不能（YuchoChecksumUnparseable = 判定不能）に留め、
// コーパスの帰属を勝手に変えないようにしている。
func parseYuchoDashForm(m string) (symbol, number string, ok bool) {
	symbol, number, ok = strings.Cut(m, "-")
	if !ok {
		return "", "", false
	}
	if len(number) >= 2 && number[0] >= '0' && number[0] <= '9' && number[1] == '-' {
		number = number[2:]
	}
	if len(symbol) != 5 || symbol[0] != '1' || symbol[4] != '0' ||
		(len(number) != 7 && len(number) != 8) || number[len(number)-1] != '1' {
		return "", "", false
	}
	return symbol, number, true
}

// parseYuchoLabeledForm はゆうちょ銀行の記号・番号ラベルが同一行で別々に
// 書かれた表記（jp-yucho-account 第 2 パターンの捕捉値、例:「記号 11111
// 番号 11111111」相当の並びから前置ラベル「記号」を除いた部分。dogfooding
// での自己検出を避けるため全桁同一のダミー値で例示する）を記号・番号へ
// 分解する。捕捉値にはラベル文字「番号」や区切り文字（空白・コロン等）が
// 混じるため、まず数字だけを抽出し、先頭 5 桁を記号・残りを番号とみなした上で
// parseYuchoDashForm と同じ形状検証（桁数・先頭/末尾）を行う。記号 5 桁目 = 0 を
// 要求する根拠と、それが「振込可能な口座」限定の制約であること（未対応の記号体系は
// 判定不能に留めること）は parseYuchoDashForm のコメントを参照。
func parseYuchoLabeledForm(m string) (symbol, number string, ok bool) {
	digits := make([]byte, 0, len(m))
	for i := 0; i < len(m); i++ {
		if m[i] >= '0' && m[i] <= '9' {
			digits = append(digits, m[i])
		}
	}
	if len(digits) != 12 && len(digits) != 13 {
		return "", "", false
	}
	symbol, number = string(digits[:5]), string(digits[5:])
	if symbol[0] != '1' || symbol[4] != '0' || number[len(number)-1] != '1' {
		return "", "", false
	}
	return symbol, number, true
}

// yuchoAccountChecksumOK は形状検証済み（parseYuchoDashForm /
// parseYuchoLabeledForm 通過済み）の記号・番号について、全桁同一の
// ダミー値でないことと、checksum.YuchoAccount（記号 4 桁目の公式検査数字。
// ゆうちょ銀行公式変換サービスの公開 JavaScript による）を満たすことを返す。
//
// ここでは形状（記号 5 桁目 = 0 等）を再検査しない。5 桁目 = 0 は「振込可能な
// 口座」限定の制約にすぎず、記号 5 桁目 ≠0 の商品（甲種団体貯金・財形等）も実在
// するため、それを「実在しない形状」として無効（Invalid）へ倒すのは誤りである
// （公式変換サービスの JS が validate() で末尾 0 を要求するのは、変換対象外の
// 入力を弾くサニティガードであって実在性の否定ではない）。未対応の記号体系は
// 形状検証側でパース不能（＝判定不能）に留める。詳細は parseYuchoDashForm の
// コメントを参照。
func yuchoAccountChecksumOK(symbol, number string) bool {
	return !checksum.AllSame(symbol) && !checksum.AllSame(number) && checksum.YuchoAccount(symbol, number)
}

// validYuchoAccount はゆうちょ銀行の記号・番号がハイフンで相関した表記
// （parseYuchoDashForm）かを検証し、形状が正しければ検査数字・全桁同一を
// yuchoAccountChecksumOK で判定する。
func validYuchoAccount(m string) bool {
	symbol, number, ok := parseYuchoDashForm(m)
	return ok && yuchoAccountChecksumOK(symbol, number)
}

// validYuchoLabeledAccount はゆうちょ銀行の記号・番号ラベルが同一行で別々に
// 書かれた表記（parseYuchoLabeledForm）かを検証し、形状が正しければ検査数字・
// 全桁同一を yuchoAccountChecksumOK で判定する。
func validYuchoLabeledAccount(m string) bool {
	symbol, number, ok := parseYuchoLabeledForm(m)
	return ok && yuchoAccountChecksumOK(symbol, number)
}

// YuchoChecksumStatus は、ある候補文字列がゆうちょ銀行の記号・番号としてパース
// できたか、パースできた場合に公式検査数字（checksum.YuchoAccount）を満たすかを
// 表す。ゼロ値は YuchoChecksumUnparseable（パース不能）にしてあり、判定を
// 忘れた呼び出し側が誤って「成立」「不成立」のどちらかに倒れないようにしている。
//
// internal/corpusv2 が非公開評価コーパスの陽性ケースを移行する際、「値そのものが
// 客観的に検査数字を満たさない」ケースだけを狙い撃ちし、想定外の表記（パース
// 不能）は判定不能として一切変更しないために、bool 1 つではなくこの 3 値を使う
// （bool 1 つだと「パース不能」と「検査数字不成立」を区別できず、想定外の表記を
// 誤って「不成立」扱いしてしまう）。
type YuchoChecksumStatus int

const (
	// YuchoChecksumUnparseable は、ハイフン形（parseYuchoDashForm）・ラベル形
	// （parseYuchoLabeledForm）のどちらの形状にも一致しなかったことを表す。
	// 呼び出し側はこれを「判定不能」として扱い、何も変更しないこと。
	//
	// 本実装が形状として受け付ける記号 5 桁目 = 0 は「振込可能な口座」（通常貯金・
	// 通常貯蓄貯金・振替）限定の制約であり、記号 5 桁目 ≠0 の甲種団体貯金や先頭
	// 2〜5 の定額・定期・財形といった記号体系も実在する（二次情報）。これらは本実装
	// が未対応なだけで実在しないわけではないため、Invalid（客観的に無効）ではなく
	// この Unparseable に落ちる。呼び出し側は「無効」と読み替えてはならない。
	YuchoChecksumUnparseable YuchoChecksumStatus = iota
	// YuchoChecksumValid は記号・番号として解釈でき、かつ公式検査数字（4桁目）を
	// 満たすことを表す。
	YuchoChecksumValid
	// YuchoChecksumInvalid は記号・番号として解釈できたが、公式検査数字を
	// 満たさない（全桁同一の明らかなダミー値を含む）ことを表す。形状が未対応な
	// だけの値はここに含めない（YuchoChecksumUnparseable のコメントを参照）。
	YuchoChecksumInvalid
)

func (s YuchoChecksumStatus) String() string {
	switch s {
	case YuchoChecksumValid:
		return "valid"
	case YuchoChecksumInvalid:
		return "invalid"
	}
	return "unparseable"
}

// YuchoValueChecksumStatus は、jp-yucho-account が検出したスパン文字列
// （呼び出し側で normalize.Line 済みであること）を、validYuchoAccount /
// validYuchoLabeledAccount と同じパース規則（ハイフン形→ラベル形の順に試す）で
// 記号・番号へ分解し、公式検査数字の成立可否を返す。jp-yucho-account の
// Validate が使う判定ロジックの唯一の情報源で、ここでは再実装しない
// （parseYuchoDashForm / parseYuchoLabeledForm / yuchoAccountChecksumOK を
// そのまま共有する）。
func YuchoValueChecksumStatus(value string) YuchoChecksumStatus {
	symbol, number, ok := parseYuchoDashForm(value)
	if !ok {
		symbol, number, ok = parseYuchoLabeledForm(value)
	}
	if !ok {
		return YuchoChecksumUnparseable
	}
	if yuchoAccountChecksumOK(symbol, number) {
		return YuchoChecksumValid
	}
	return YuchoChecksumInvalid
}

// birthdateRe は jp-birthdate の区切りあり捕捉値（西暦 4 桁 or 和暦元号＋年・月・日）
// を分解する。グループ: 1=西暦年 / 2=元号（漢字 or 単字アルファベット略記）/
// 3=和暦年（数字、または改元年を表す「元」）/ 4=月 / 5=日。区切りはルールの
// 正規表現と同じ（年→月は [年/.-]、月→日は [月/.-]、末尾 日?）。
var birthdateRe = regexp.MustCompile(
	`^(?:((?:19|20)\d{2})|(明治|大正|昭和|平成|令和|[MTSHRmtshr])(元|\d{1,2}))[年/.-](\d{1,2})[月/.-](\d{1,2})日?$`)

// birthdateDigitsRe は jp-birthdate の「ラベル直結・区切りなし8桁」捕捉値
// （YYYYMMDD）を分解する。月日のレンジは検出側の正規表現で既に絞り込み済み
// なので、ここでは西暦年/月/日への分解のみを行う。グループ: 1=西暦年 / 2=月 / 3=日。
var birthdateDigitsRe = regexp.MustCompile(`^((?:19|20)\d{2})(\d{2})(\d{2})$`)

// birthdateEraAbbrev は運転免許証・保険証等の転記で一般的な元号の単字
// アルファベット略記を正式名称へ変換する。キーは大文字で、参照側が
// strings.ToUpper してから引くことで小文字表記（s63.1.2 等）にも対応する
// （漢字の元号名は ToUpper で変化しないため、同じ経路を通しても影響しない）。
var birthdateEraAbbrev = map[string]string{
	"M": "明治",
	"T": "大正",
	"S": "昭和",
	"H": "平成",
	"R": "令和",
}

// warekiEraInfo は元号 1 つの換算基準と有効期間。
type warekiEraInfo struct {
	// startYear は元年に対応する西暦年。西暦 = startYear + 和暦年 - 1 で換算する。
	startYear int
	// maxYear はその元号で取りうる最大の和暦年（令和は終期がないため、
	// 正規表現側の上限である 2 桁いっぱいまで許容する）。
	maxYear int
	// firstDay / lastDay は改元日・元号最終日（西暦）。年の上限だけでは弾けない
	// 実在しない日付（昭和64年3月1日 = 昭和は1989年1月7日まで、平成31年5月1日 =
	// 平成は2019年4月30日まで 等）を棄却するために使う。ゼロ値は「その側の境界を
	// 検証しない」ことを表す。
	firstDay, lastDay time.Time
}

// contains は西暦日付 t が元号の有効期間内かを返す（ゼロ値の境界は検証しない）。
func (e warekiEraInfo) contains(t time.Time) bool {
	if !e.firstDay.IsZero() && t.Before(e.firstDay) {
		return false
	}
	return e.lastDay.IsZero() || !t.After(e.lastDay)
}

// warekiEra は元号の換算基準と有効期間を返す。改元年を元年（1 年）とする。
// 改元日は前元号の最終日と同日になることがある（明治45年7月30日＝大正元年7月30日、
// 大正15年12月25日＝昭和元年12月25日）ため、その日はどちらの元号でも有効とする。
//
// 明治の firstDay だけはゼロ値（開始側を検証しない）にする。明治1〜5年は太陰太陽暦
// （改暦は明治5年12月3日＝1873年1月1日）で、startYear からの単純な年換算が西暦日付と
// 一致しないため、開始境界を課すとかえって実在する表記を落とす。終了側（明治45年
// 7月30日）は改暦後で西暦と一対一に対応するため検証できる。
func warekiEra(era string) (warekiEraInfo, bool) {
	switch era {
	case "明治": // 〜1912年7月30日（明治45年7月30日まで）
		return warekiEraInfo{startYear: 1868, maxYear: 45,
			lastDay: gregorianDate(1912, 7, 30)}, true
	case "大正": // 1912年7月30日〜1926年12月25日
		return warekiEraInfo{startYear: 1912, maxYear: 15,
			firstDay: gregorianDate(1912, 7, 30), lastDay: gregorianDate(1926, 12, 25)}, true
	case "昭和": // 1926年12月25日〜1989年1月7日
		return warekiEraInfo{startYear: 1926, maxYear: 64,
			firstDay: gregorianDate(1926, 12, 25), lastDay: gregorianDate(1989, 1, 7)}, true
	case "平成": // 1989年1月8日〜2019年4月30日
		return warekiEraInfo{startYear: 1989, maxYear: 31,
			firstDay: gregorianDate(1989, 1, 8), lastDay: gregorianDate(2019, 4, 30)}, true
	case "令和": // 2019年5月1日〜（終期なし）
		return warekiEraInfo{startYear: 2019, maxYear: 99,
			firstDay: gregorianDate(2019, 5, 1)}, true
	}
	return warekiEraInfo{}, false
}

// gregorianDate は西暦の年月日を UTC の time.Time にする（元号境界の比較用）。
func gregorianDate(year, month, day int) time.Time {
	return time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
}

// validBirthdate は捕捉した生年月日が実在する暦日かを検証する。形式上は
// 成立しても暦として無効な値（2023-99-99 / 2023-02-29 / 昭和65年… 等）を棄却する。
// 和暦は年の上限（昭和65年）だけでなく元号の有効期間（昭和64年3月1日・平成31年
// 5月1日のように、年としては成立するが改元をまたいで実在しない日付）も検証する
// （warekiEraInfo.contains）。未来日や年齢の妥当性までは判定しない（信頼度では
// なく検出可否のみを扱うため）。まず区切りなし8桁（YYYYMMDD）として解釈を試み、
// ダメなら区切りあり形式（西暦 or 和暦、単字アルファベット略記・元年を含む）と
// して解釈する。
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
	month, _ := strconv.Atoi(sub[4])
	day, _ := strconv.Atoi(sub[5])
	if sub[1] != "" {
		year, _ := strconv.Atoi(sub[1])
		return validCalendarDate(year, month, day)
	}
	// 単字アルファベット略記は大小文字を問わない（正規表現側が両方許容する）。
	// 漢字の元号名は ToUpper で変化しないため、同じ経路を通してよい。
	era := sub[2]
	if full, ok := birthdateEraAbbrev[strings.ToUpper(era)]; ok {
		era = full
	}
	eraYear := 1
	if sub[3] != "元" {
		eraYear, _ = strconv.Atoi(sub[3])
	}
	info, ok := warekiEra(era)
	if !ok || eraYear < 1 || eraYear > info.maxYear {
		return false
	}
	year := info.startYear + eraYear - 1
	if !validCalendarDate(year, month, day) {
		return false
	}
	return info.contains(gregorianDate(year, month, day))
}

// validCalendarDate は西暦の年月日が実在する日付かを time.Date の
// ラウンドトリップで検証する（閏年・月ごとの日数を含む）。
func validCalendarDate(year, month, day int) bool {
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return false
	}
	t := gregorianDate(year, month, day)
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

// notCalendarDateBanchiAndRealTown は notCalendarDateBanchi（ISO 日付誤検出の
// 棄却）と dict.MunicipalityThenTownMatch（市区町村直後が ABR 町字マスター由来の
// 実在町字名で始まるかの昇格専用チェック）の両方を満たす場合だけ true を返す
// 合成 Validate。jp-address-high-recall のマーカーなしダッシュ連結
// （banchiDash）用 High 側 twin 専用（addressHighRecallDashRe のコメント参照）。
//
// dict.MunicipalityThenTownMatch 単体を High 側の Pattern.Validate にすると、
// 市区町村の直後がたまたま実在町字名で始まり、かつ番地部分が ISO 日付形
// （2025-07-02 等）のケースで、notCalendarDateBanchi による日付棄却が High 側
// だけ効かなくなってしまう（Medium 側は変わらず notCalendarDateBanchi 単体で
// 棄却されるため、その場合 Medium にも昇格せず完全に非検出になり、ISO 日付が
// 誤って住所として報告されることはない＝リグレッションにはならないが、
// 「両方満たす場合だけ True」という twin の設計原則からは外れる）。ここで
// 明示的に AND 合成することで、日付棄却の意図を High 側でも保つ。
func notCalendarDateBanchiAndRealTown(v string) bool {
	return notCalendarDateBanchi(v) && dict.MunicipalityThenTownMatch(v)
}

// emailDummySubstringWords / emailDummyTokenWords はメールのダミー値でよく使われる
// ローカル部・ドメイン第 1 ラベルの語（denylist で棄却）。照合の厳しさを語の
// 弁別力で 2 段に分ける。
//
//   - emailDummySubstringWords は部分一致で棄却する。いずれも実在の人名・企業名に
//     偶然現れることがまず無い弁別力の高い語なので、dummyuser のような合成形
//     （ダミー語 + 一般語）まで広く抑制できる部分一致が有効に働く。
//   - emailDummyTokenWords は 3 文字と短く、実在の語の一部として頻出するため
//     （barry / barbara / barclays / foodservice 等）、部分一致だと実在アドレスを
//     巻き添えで落としてしまう。こちらはトークン一致に留める。
var (
	emailDummySubstringWords = []string{"hoge", "fuga", "dummy", "hogehoge", "sample"}
	emailDummyTokenWords     = []string{"foo", "bar"}
	// emailPlaceholderDomainLabels は、ドキュメント・テストで「任意のドメイン」の
	// 意味で使われるドメイン（domain.com・test.com・somewhere.org 等）の第 1 ラベル。
	// ラベル 2 つのドメイン（<label>.<TLD>）のときだけ棄却する。OSS コーパスで
	// 実測した、例示用アドレスの偽陽性の上位（docs/development.md 参照）。
	emailPlaceholderDomainLabels = []string{"domain", "yourdomain", "mydomain", "somewhere", "test"}
)

// emailNonPersonalDomains は、個人ではなくプロトコルの拡張名・機械アカウントに
// 使われるドメイン。ドメインそのものか、そのサブドメインのときに棄却する。
//   - openssh.com / libssh.org: SSH の暗号・拡張名（"chacha20-poly1305@openssh.com"、
//     "curve25519-sha256@libssh.org"）。RFC 4251 の命名規則で、設定ファイル・
//     ライブラリに頻出する。
//   - gserviceaccount.com: Google Cloud のサービスアカウント
//     （"*.iam.gserviceaccount.com"、"*@developer.gserviceaccount.com"）。
//     個人ではなくワークロードの ID（秘密情報の検出は対象外）。
var emailNonPersonalDomains = []string{"openssh.com", "libssh.org", "gserviceaccount.com"}

// emailNonPersonalLocals は、個人を指さない送信専用・システムのローカル部
// （完全一致、大文字小文字は区別しない）。
var emailNonPersonalLocals = []string{
	"noreply", "no-reply", "no_reply", "donotreply", "do-not-reply", "do_not_reply", "mailer-daemon",
}

// nonPersonalEmail は、local@domain（domain は小文字）が個人を指さない
// プロトコル名・機械アカウント・送信専用アドレスであるかを返す。
func nonPersonalEmail(local, domain string) bool {
	for _, d := range emailNonPersonalDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return slices.Contains(emailNonPersonalLocals, strings.ToLower(local))
}

// containsEmailDummyWord は s（ローカル部またはドメイン第 1 ラベル）がダミー語を
// 含むかを返す。emailDummySubstringWords は部分一致、emailDummyTokenWords は
// トークン一致（s を区切り文字 . _ % + - で分割し、各トークンの前後に付いた連番を
// 取り除いてから完全一致）で判定する。
func containsEmailDummyWord(s string) bool {
	s = strings.ToLower(s)
	for _, w := range emailDummySubstringWords {
		if strings.Contains(s, w) {
			return true
		}
	}
	for _, token := range strings.FieldsFunc(s, isEmailLocalSeparator) {
		if slices.Contains(emailDummyTokenWords, strings.Trim(token, "0123456789")) {
			return true
		}
	}
	return false
}

// isEmailLocalSeparator はローカル部・ドメインラベル内のトークン区切り文字かを返す
// （emailASCIIRe が許容する記号のうち、語を区切りうるもの）。
func isEmailLocalSeparator(r rune) bool {
	switch r {
	case '.', '_', '%', '+', '-':
		return true
	}
	return false
}

// validEmail は予約済みドメイン（RFC 2606/6761）・ダミー値でよく使われる
// ローカル部/ドメイン語等を除外する。長さ上限（アドレス全体 254 文字・ローカル部
// 64 文字・ドメインラベル 63 文字。RFC 5321 4.5.3.1 / RFC 1035 2.3.4）も検証し、
// EAI 版（validEAIEmail）と判定基準を揃える。ASCII 版だけ上限が無いと、長大な
// 英数字列にたまたま "@" が挟まったトークンをメールアドレスとして報告しうる。
func validEmail(m string) bool {
	if len(m) > 254 {
		return false
	}
	at := strings.LastIndexByte(m, '@')
	if at <= 0 || at == len(m)-1 {
		return false
	}
	local := m[:at]
	if len(local) > 64 || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") ||
		strings.Contains(local, "..") {
		return false
	}
	if !containsASCIIAlnum(local) {
		return false
	}
	domain := strings.ToLower(m[at+1:])
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 ||
			strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	if containsEmailDummyWord(local) || containsEmailDummyWord(labels[0]) {
		return false
	}
	if len(labels) == 2 && slices.Contains(emailPlaceholderDomainLabels, labels[0]) {
		return false
	}
	if nonPersonalEmail(local, domain) {
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
