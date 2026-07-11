package dict

import "embed"

// romaji_surnames.txt / romaji_given_names.txt は、ローマ字（ヘボン式）表記の
// 氏名検出ルール person-name-romaji（internal/rule、高再現率・既定オフ）専用の
// 辞書。全文走査での氏名検出には使わない。出典・生成方法は各ファイルの
// ヘッダーコメントと internal/dict/gen-names を参照。
//
//go:embed romaji_surnames.txt romaji_given_names.txt
var romajiFS embed.FS

var (
	romajiSurnames   = loadNameSet(romajiFS, "romaji_surnames.txt")
	romajiGivenNames = loadNameSet(romajiFS, "romaji_given_names.txt")
)

// IsRomajiSurname は s（小文字化済みのローマ字表記を想定）が収録済みの姓の
// ローマ字表記かを返す。呼び出し側で strings.ToLower 済みの値を渡すこと。
func IsRomajiSurname(s string) bool { return romajiSurnames[s] }

// IsRomajiGivenName は s（小文字化済みのローマ字表記を想定）が収録済みの名の
// ローマ字表記かを返す。呼び出し側で strings.ToLower 済みの値を渡すこと。
func IsRomajiGivenName(s string) bool { return romajiGivenNames[s] }
