package rule

import "strings"

// phoneServicePrefixes はフリーダイヤル・ナビダイヤル・ダイヤルQ2・テレドームなど、
// 個人に紐づかないサービス系番号の先頭4桁（国内形）。
var phoneServicePrefixes = []string{"0120", "0800", "0570", "0990", "0180"}

// phoneMobilePrefixes は携帯電話・FMC の先頭3桁（国内形）。060 は本来 FMC
// （固定電話網の番号を携帯端末で着信する仕組み）だが、jp-phone-number ルールの
// 説明「電話番号（携帯・固定・IP・国際表記）」に合わせ、090/080/070 と同じ
// mobile 側に分類する。
var phoneMobilePrefixes = []string{"060", "070", "080", "090"}

// PhoneKind は jp-phone-number ルールが検出したマッチ文字列（正規化済み・区切り
// 含む。Rule.Validate（validPhone）を通過済みの値を前提とする）を用途別の
// 下位種別に分類する。判定は "+81"/"81" 始まりの表記を、国番号を除き先頭に "0" を
// 補った国内形（例: +81-90-XXXX-XXXX は 090-XXXX-XXXX として）へ読み替えてから行う。
//
// 戻り値:
//   - "service":       先頭 0120/0800/0570/0990/0180
//     （フリーダイヤル・ナビダイヤル・ダイヤルQ2・テレドーム）
//   - "ip":             先頭 050（IP電話）
//   - "mobile":         先頭 060/070/080/090（携帯電話。060 の扱いは
//     phoneMobilePrefixes のコメント参照）
//   - "international":  元のマッチが "+81" で始まり、国内形に読み替えても
//     上記のいずれにも該当しない場合（例: +81 表記の固定電話）
//   - "fixed":          それ以外（区切りあり/なしの固定電話。"+81" を伴わない
//     裸の "81" 始まりで上記に該当しない場合も含む）
//
// この分類自体は検出可否・信頼度には影響しない（Finding.Reason.Kind への記録の
// み）。[rules] exclude_kinds（internal/config）による種別ごとの除外判定は
// internal/detect が行う。
func PhoneKind(m string) string {
	digits := stripSeparators(m)
	intl := strings.HasPrefix(m, "+81")
	domestic := toDomesticPhoneDigits(digits)

	switch {
	case hasAnyDigitPrefix(domestic, phoneServicePrefixes):
		return "service"
	case strings.HasPrefix(domestic, "050"):
		return "ip"
	case hasAnyDigitPrefix(domestic, phoneMobilePrefixes):
		return "mobile"
	case intl:
		return "international"
	default:
		return "fixed"
	}
}

// toDomesticPhoneDigits は "+81"/"81" で始まる数字列を、国番号を外して先頭に
// "0" を補った国内形に読み替える。いずれの接頭辞も無ければそのまま返す。
func toDomesticPhoneDigits(digits string) string {
	switch {
	case strings.HasPrefix(digits, "+81"):
		return "0" + digits[len("+81"):]
	case strings.HasPrefix(digits, "81"):
		return "0" + digits[len("81"):]
	default:
		return digits
	}
}

// hasAnyDigitPrefix は s が prefixes のいずれかで始まるかを返す。
func hasAnyDigitPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
