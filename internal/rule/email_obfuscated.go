package rule

import (
	"regexp"
	"strings"
)

// 迷惑メール対策で「@」を「*」「＊」に置き換えて載せるアドレス（「E-mail: <ローカル部>*<ドメイン>
// （*を@に置き換えてください）」）。2026-11-28 に公開文書 1,401 件の人手確認で、大学・官公庁の
// 問い合わせ先に多い表記として、全モードの見逃しを実測した。「*」は箇条書き・注記・伏せ字にも
// 使うので、同じ行に「*を@に」「＊を＠に」のような置き換えの指示がある行に限る。値の検証は
// validEmail が「*」を「@」に戻して通常のアドレスと同じく行う（TLD の実在・ダミー語の棄却など）。
var (
	emailStarObfuscatedRe = regexp.MustCompile(`(?:^|[^\p{L}\p{N}._%+*＊-]|\p{Hiragana}|メール|アドレス|宛先|連絡先)([A-Za-z0-9._%+-]+[*＊][A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})(?:[^\p{L}\p{N}_%+:*＊-]|[\p{Han}\p{Hiragana}\p{Katakana}]|$)`)
	// emailStarInstructionRe は置き換えの指示「*を@に」「「＊」を「＠」に」「* は @ に」。
	emailStarInstructionRe = regexp.MustCompile(`[*＊][」』"”]?[ 　]*[をは][ 　]*[「『"“]?[@＠]`)
)

// requireStarInstruction は、行に「*」を「@」に置き換える指示があるときだけ候補を通す。
func requireStarInstruction(line string, _, _ int) bool {
	return emailStarInstructionRe.MatchString(line)
}

// unobfuscateStarEmail は「@」を含まず「*」「＊」をちょうど 1 つ含む値の「*」を「@」に戻す。
// 通常のアドレスのパターンは「*」を捕捉しないので、それ以外の値はそのまま返す。
func unobfuscateStarEmail(m string) string {
	if strings.Contains(m, "@") {
		return m
	}
	n := strings.Count(m, "*") + strings.Count(m, "＊")
	if n != 1 {
		return m
	}
	m = strings.Replace(m, "＊", "@", 1)
	return strings.Replace(m, "*", "@", 1)
}
