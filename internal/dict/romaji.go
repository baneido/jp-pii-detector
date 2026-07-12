package dict

import (
	"embed"
	"strings"
)

// romaji_surnames.txt / romaji_given_names.txt は、ローマ字（ヘボン式）表記の
// 氏名検出ルール person-name-romaji（internal/rule、高再現率・既定オフ）専用の
// 辞書。全文走査での氏名検出には使わない。出典・生成方法は各ファイルの
// ヘッダーコメントと internal/dict/gen-names を参照。
//
//go:embed romaji_surnames.txt romaji_given_names.txt
var romajiFS embed.FS

var (
	romajiSurnames   = loadRomaji(romajiFS, "romaji_surnames.txt")
	romajiGivenNames = loadRomaji(romajiFS, "romaji_given_names.txt")
)

// loadRomaji は loadNameSet で読み込んだワープロ式ローマ字表記
// （タロウ→tarou、サイトウ→saitou のように長音符を "u" 綴りでそのまま表す
// 慣習的表記）の集合に、読み込み時点で長音省略ヘボン式の派生形を機械生成して
// 併録する。パスポート・クレジットカード・メール署名などで標準となるのは
// 長音省略ヘボン式（Taro / Saito / Ito / Yuki）であり、ワープロ式のみの辞書では
// person-name-romaji ルールがこれらに一致しない問題への対処。
//
// 生成する派生形は 2 種類（詳細は romajiDropLongVowel / romajiOhForm）:
//  1. 長音省略形: "ou"→"o"、"oo"→"o"、"uu"→"u"（tarou→taro、saitou→saito、
//     oono→ono、yuuki→yuki）。
//  2. OH 表記: "ou"/"oo" の直後が子音または語末の場合に限り "oh"
//     （oono→ohno、satou→satoh、itou→itoh）。
//
// "ii"・"ei" はヘボン式でも省略せずそのまま綴るため変換対象に含めない
// （上記いずれの置換パターンにも該当しないので、対応する呼び出し元でも
// 何もせず素通りする）。
//
// 元のワープロ式表記も必ず残す。追加先は map（集合）なので、派生形が元の
// 表記や他エントリの派生形と重複しても自然に 1 件へ潰れる。この派生は
// 姓・名どちらの辞書にも同じロジックで適用する。txt ファイル自体（生成元
// CSV との対応）は変更しない。
//
// 派生により ono・ito のような英単語と紛らわしい短い表記も辞書に加わり、
// 偶発的な衝突が増えうる。しかし person-name-romaji ルールは「name ラベル +
// 姓・名辞書の共起（英単語 2 語）」を要求する RequireContext ルールであり、
// かつ高再現率モード限定（既定オフ）でしか有効化されないため、誤検知面への
// 影響は限定的と判断する。
func loadRomaji(fsys embed.FS, name string) map[string]bool {
	base := loadNameSet(fsys, name)
	out := make(map[string]bool, len(base))
	for entry := range base {
		out[entry] = true
		if dropped := romajiDropLongVowel(entry); dropped != entry {
			out[dropped] = true
		}
		if oh, ok := romajiOhForm(entry); ok {
			out[oh] = true
		}
	}
	return out
}

// romajiDropLongVowel は entry 中の "ou"→"o"、"oo"→"o"、"uu"→"u" を全出現
// 置換した長音省略形を返す（該当箇所がなければ entry をそのまま返す）。
// 先頭から走査し、置換した箇所は 2 ルーン分まとめて消費するため、1 語に
// 複数箇所含む場合（koutarou）も段階置換の組合せを考えず一括で全置換した
// 1 形（kotaro）になる。"ii"・"ei" はここでの置換パターンに含まれないため、
// ヘボン式の慣習どおり素通りする（例: keiichi はそのまま keiichi のまま
// 変化しない）。
func romajiDropLongVowel(entry string) string {
	rs := []rune(entry)
	var b strings.Builder
	b.Grow(len(entry))
	for i := 0; i < len(rs); i++ {
		if i+1 < len(rs) {
			switch {
			case rs[i] == 'o' && rs[i+1] == 'u':
				b.WriteRune('o')
				i++
				continue
			case rs[i] == 'o' && rs[i+1] == 'o':
				b.WriteRune('o')
				i++
				continue
			case rs[i] == 'u' && rs[i+1] == 'u':
				b.WriteRune('u')
				i++
				continue
			}
		}
		b.WriteRune(rs[i])
	}
	return b.String()
}

// romajiOhForm は entry 中の "ou"/"oo" を、直後の文字が子音または語末の場合に
// 限り "oh" へ置換した表記（実務でよく見る大野→Ohno、佐藤→Satoh、伊藤→Itoh
// のような表記）を返す。該当箇所が一つもなければ ok=false。
//
// 直後が母音の場合は変換しない（例えば "ou" の直後に母音が続く語をそのまま
// "oh" にすると誤読形になるため）。"uu" はこの表記の対象外（"uh" という
// 表記は実務で使われないため、romajiDropLongVowel の長音省略のみで扱う）。
func romajiOhForm(entry string) (string, bool) {
	rs := []rune(entry)
	var b strings.Builder
	b.Grow(len(entry))
	changed := false
	for i := 0; i < len(rs); i++ {
		if i+1 < len(rs) && rs[i] == 'o' && (rs[i+1] == 'u' || rs[i+1] == 'o') {
			nextIsVowel := i+2 < len(rs) && isRomajiVowel(rs[i+2])
			if !nextIsVowel {
				b.WriteString("oh")
				i++
				changed = true
				continue
			}
		}
		b.WriteRune(rs[i])
	}
	if !changed {
		return "", false
	}
	return b.String(), true
}

// isRomajiVowel は r がローマ字表記の母音（a/e/i/o/u）かを返す。
// romajiOhForm が "ou"/"oo" の直後の文字が母音かどうかを判定するために使う。
func isRomajiVowel(r rune) bool {
	switch r {
	case 'a', 'e', 'i', 'o', 'u':
		return true
	}
	return false
}

// IsRomajiSurname は s（小文字化済みのローマ字表記を想定）が収録済みの姓の
// ローマ字表記かを返す。呼び出し側で strings.ToLower 済みの値を渡すこと。
func IsRomajiSurname(s string) bool { return romajiSurnames[s] }

// IsRomajiGivenName は s（小文字化済みのローマ字表記を想定）が収録済みの名の
// ローマ字表記かを返す。呼び出し側で strings.ToLower 済みの値を渡すこと。
func IsRomajiGivenName(s string) bool { return romajiGivenNames[s] }
