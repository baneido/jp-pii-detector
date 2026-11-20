package rule

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/dict"
)

// 2026-11-20 の公開文書の走査（6,129 件）で、既定モードのルールが取りこぼしていた氏名の形
// （person-name-role-label）と、同じ確認で見つけた誤検出の棄却。人を指す語のある無作為 421 行に
// 人手で付けた正解（姓+名 50 人）のうち、既定モードが拾えたのは 34 人だった。

// listRoleWords は名簿の見出しになる役職（「｛評議員｝ <氏名>、<氏名>、…」の括弧の中）。
const listRoleWords = `評議員|理事|監事|委員|役員|顧問|幹事|会員|参与|相談役|世話人|審査員|選考委員|運営委員|実行委員`

// prefectureAlternation は「<氏名><都道府県>知事」の都道府県名。正規表現の中で都道府県名を列挙して、
// 氏名の末尾の字が都道府県名の一部として食われないようにする。
const prefectureAlternation = `北海道|青森県|岩手県|宮城県|秋田県|山形県|福島県|茨城県|栃木県|群馬県|埼玉県|千葉県|東京都|神奈川県|` +
	`新潟県|富山県|石川県|福井県|山梨県|長野県|岐阜県|静岡県|愛知県|三重県|滋賀県|京都府|大阪府|兵庫県|奈良県|和歌山県|` +
	`鳥取県|島根県|岡山県|広島県|山口県|徳島県|香川県|愛媛県|高知県|福岡県|佐賀県|長崎県|熊本県|大分県|宮崎県|鹿児島県|沖縄県`

var (
	// personNameBracketRoleListRe は「｛評議員｝ <氏名>、<氏名>、<氏名>、」のように、括弧に入れた役職の
	// 見出しに読点区切りの氏名が続く行の、氏名 1 つ分（財団の役員名簿で実測）。行の形は
	// requireBracketRoleListLine が確かめ、値は姓名辞書の完全分割を要求する。
	personNameBracketRoleListRe = regexp.MustCompile(`([` + kanji + `]{3,6})(?:[、，,][ ]?|[ ]*$)`)
	bracketRoleListLineRe       = regexp.MustCompile(
		`^[ ]*[｛{〔\[［【（(](?:` + listRoleWords + `)[｝}〕\]］】）)][ ]*((?:[` + kanji + `]{2,6}[、，,][ ]?){2,}(?:[` + kanji + `]{2,6})?)[ ]*$`,
	)
	// personNameDirectorParenRe は「理事 <氏名>（<社名>代表取締役社長）」のように、法人の役員の職名・空白・
	// 氏名の後に括弧（本務・読みがな）が続く形（団体の役員名簿で実測）。
	personNameDirectorParenRe = regexp.MustCompile(
		`(?:^|[ ])(?:代表理事|専務理事|常務理事|常任理事|副理事長|理事|監事|評議員|幹事|顧問|参与)[ ]+([` + kanji + `]{3,6})[（(]`,
	)
	// personNamePrefectureGovernorRe は「<県庁>では<氏名><県名>知事、」のように、氏名に都道府県名 + 知事が
	// 直結する形（省庁・団体の表敬訪問の記事で実測）。
	personNamePrefectureGovernorRe = regexp.MustCompile(
		`(?:^|[^` + kanji + `]|[のはがにでとをもへや、])([` + kanji + `]{3,6}?)(?:` + prefectureAlternation + `)知事`,
	)
	// personNameMunicipalMayorN は「<市役所>では<氏名><市名>市長を」のように、氏名に市区町村名 + 首長の職名が
	// 直結する形を、氏名の字数（3〜6 字）ごとに分けたもの。市区町村名は正規表現に列挙できないので、
	// 氏名の字数を固定して、続く自治体名を requireMunicipalityBeforeMayor が辞書で確かめる。
	personNameMunicipalMayor3Re = municipalMayorRe(3)
	personNameMunicipalMayor4Re = municipalMayorRe(4)
	personNameMunicipalMayor5Re = municipalMayorRe(5)
	personNameMunicipalMayor6Re = municipalMayorRe(6)
	// personNameAppointedAsRe は「<法人>理事長に<姓> <名>（<号>）が就任」のように、職名 + に + 氏名 + が就任
	// （大学・法人の就任のお知らせで実測）。
	personNameAppointedAsRe = regexp.MustCompile(
		`(?:理事長|会長|社長|学長|総長|校長|院長|館長|所長|頭取|代表理事|代表取締役|センター長|学部長|研究科長|教育長|副市長|副知事)に[ ]?` +
			`([` + kanji + `]{1,4}[ ][` + kanji + `]{1,4}|[` + kanji + `]{3,6})(?:氏)?(?:[（(][^（）()]{1,16}[）)])?が(?:就任|選任|着任|選出)`,
	)
	// personNameTitleEllipsisRe は「<大学> 特任准教授 <姓> <名>...」のように、職名・空白・空白区切りの氏名の
	// 後が省略記号で切れている形（新着情報の一覧の抜粋で実測）。
	personNameTitleEllipsisRe = regexp.MustCompile(
		`(?:` + personTitleWords + `)[ ]+([` + kanji + `]{1,4}[ ][` + kanji + `]{1,4})[ ]?(?:\.\.\.|…|‥)`,
	)
	// personNameEventShiLineEndRe は「<学科> 特別レクチャー <氏名>氏」のように、催しの名前・空白・氏名 + 氏で
	// 行が終わる形（大学の催しの案内で実測）。催しの語を必須にし、値は姓名辞書の完全分割を要求する。
	personNameEventShiLineEndRe = regexp.MustCompile(
		`(?:レクチャー|セミナー|講演会|講演|講座|シンポジウム|フォーラム|トークショー|トーク|対談|講話|研修会|研修|ワークショップ|公開講義|講義|授業)` +
			`[ ]*[：:]?[ ]+([` + kanji + `]{3,6})氏[ ]*(?:$|[（(])`,
	)
)

func municipalMayorRe(n int) *regexp.Regexp {
	return regexp.MustCompile(
		`(?:^|[^` + kanji + `]|[のはがにでとをもへや、])([` + kanji + `]{` + string(rune('0'+n)) + `})[` + kanji + `ケヶ]{1,6}?[市町村区]長`,
	)
}

// requireBracketRoleListLine は personNameBracketRoleListRe の値が、「｛<役職>｝ <氏名>、<氏名>、…」の形の行の
// 読点区切りの並びの中にあるときだけ通す。並びの中の値の半分以上が姓名辞書で完全分割できない行
// （地名・団体名の並び）は通さない。
func requireBracketRoleListLine(line string, start, end int) bool {
	if !strings.ContainsAny(line, "｝}〕]］】）)") {
		return false
	}
	m := bracketRoleListLineRe.FindStringSubmatchIndex(line)
	if m == nil || start < m[2] || end > m[3] {
		return false
	}
	names, total := 0, 0
	for _, tok := range strings.FieldsFunc(line[m[2]:m[3]], func(r rune) bool { return r == '、' || r == '，' || r == ',' || r == ' ' }) {
		total++
		if validPersonNameFullSplit(tok) {
			names++
		}
	}
	return total >= 3 && names*2 >= total
}

// requireMunicipalityBeforeMayor は personNameMunicipalMayorNRe の値の直後から首長の職名（市長・町長・
// 村長・区長）の「長」の前までが、実在の市区町村名であるときだけ通す。
func requireMunicipalityBeforeMayor(line string, start, end int) bool {
	rest := line[end:]
	i := strings.Index(rest, "長")
	if i <= 0 || utf8.RuneCountInString(rest[:i]) > 7 {
		return false
	}
	place := rest[:i]
	if !dict.IsMunicipalityOrPrefecture(place) {
		return false
	}
	// 「<姓>副<市名>市長」のような形は氏名の範囲が決まらないので通さない。
	return !strings.HasSuffix(line[start:end], "副")
}

// rejectUnderscoreJoinedDigits は桁数だけが手がかりの番号（基礎年金番号・介護保険の被保険者番号）の値が、
// 下線で別の数字とつながった識別子の一部である場合に棄却する（2026-11-20 にオープンデータのカタログ CSV で
// 実測した偽陽性。データセットの ID「<自治体コード>_<10 桁>」の 10 桁が、同じ行のデータセット名
// 「介護保険サービス提供事業者一覧」を手がかりに報告されていた。2026-11-19 に直した URL の中の形の、
// URL を伴わない列）。
func rejectUnderscoreJoinedDigits(line string, start, end int) bool {
	if start >= 2 && line[start-1] == '_' && isASCIIDigit(line[start-2]) {
		return false
	}
	if end+1 < len(line) && line[end] == '_' && isASCIIDigit(line[end+1]) {
		return false
	}
	return true
}

// rejectPermitNumberDaiGo は jp-drivers-license の 12 桁が「第<12 桁>号」の形で、行に許可・届出の語が
// ある場合に棄却する（2026-11-20 に企業の会社概要「古物営業許可 <県>公安委員会 第<12 桁>号」で実測した
// 偽陽性。前の行の「宅建免許番号」が手がかりになっていた）。古物商の許可番号は事業者の番号で、
// 個人の運転免許証番号ではない。運転免許証番号は「第…号」と書かない。
func rejectPermitNumberDaiGo(line string, start, end int) bool {
	if !strings.HasSuffix(line[:start], "第") || !strings.HasPrefix(line[end:], "号") {
		return true
	}
	for _, w := range []string{"古物", "許可", "届出", "登録", "認可"} {
		if strings.Contains(line, w) {
			return false
		}
	}
	return true
}

// rejectHonorificFishShoshiShop は高再現率の敬称パターンで、敬称と同じ字を含む一般語を敬称付きの氏名と
// みなさない（2026-11-20 に市場の統計 CSV・団体の基本方針・学校給食の献立・町の沿革で実測した
// 高再現率モードの偽陽性。いずれも特定の個人を指さない）。
//   - 「丸干さんま」: 「さんま」は魚の名前（「<姓>さんまで」のような助詞の続きは通す）
//   - 「先輩諸氏」「会員諸氏」: 「諸氏」は複数の人への敬称
//   - 「八百屋さん」「魚屋さん」: 店
//   - 「4月<氏名>氏」: 値が数字の直後の「月」「日」「年」から始まる形は、日付の字を取り込んだ範囲の誤り
func rejectHonorificFishShoshiShop(line string, start, end int) bool {
	v := line[start:end]
	rest := line[end:]
	if after, ok := strings.CutPrefix(rest, "さんま"); ok {
		r, _ := utf8.DecodeRuneInString(after)
		if after == "" || !strings.ContainsRune("でたずすだっ", r) {
			return false
		}
	}
	if strings.HasPrefix(rest, "氏") && strings.HasSuffix(v, "諸") {
		return false
	}
	if strings.HasPrefix(rest, "さん") {
		switch v {
		case "八百屋", "魚屋", "肉屋", "本屋", "床屋", "薬屋", "豆腐屋", "電器屋", "電気屋", "靴屋", "畳屋", "植木屋", "問屋", "質屋", "菓子屋", "駄菓子屋", "洋服屋", "文具屋", "金物屋", "建具屋", "写真屋", "不動産屋":
			return false
		}
	}
	if start >= 1 && isASCIIDigit(line[start-1]) {
		for _, p := range []string{"月", "日", "年"} {
			if strings.HasPrefix(v, p) {
				return false
			}
		}
	}
	return true
}

// notPlaceholderEAILocal は email-address-eai の値のローカル部が伏せ字（〇〇〇・○○・＊＊）だけの
// 場合に棄却する（2026-11-20 に大学のメールアドレス変更の案内「〇〇〇@<ドメイン>」で実測した
// 高再現率モードの偽陽性。書式の例で、特定の個人のアドレスではない）。
func notPlaceholderEAILocal(v string) bool {
	local, _, ok := strings.Cut(v, "@")
	if !ok || local == "" {
		return true
	}
	for _, r := range local {
		if !strings.ContainsRune("〇○◯●＊*×xX△□■", r) {
			return true
		}
	}
	return false
}
