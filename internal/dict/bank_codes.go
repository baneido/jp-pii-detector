package dict

// bankCodes は、銀行名辞書にも収録している主要行の金融機関コードを手作業で
// 収録した代表サブセット。全銀協等の外部マスタを取り込んだものではない。
// 元データのライセンス・帰属を確認できない大規模データを同梱しないため、
// 網羅性より適合率を優先する。追加時の制約は docs/development.md を参照。
var bankCodes = map[string]bool{
	"0001": true, // みずほ銀行
	"0005": true, // 三菱UFJ銀行
	"0009": true, // 三井住友銀行
	"0010": true, // りそな銀行
	"0017": true, // 埼玉りそな銀行
	"0033": true, // PayPay銀行
	"9900": true, // ゆうちょ銀行
}

// ValidBankCode は code が収録済みの実在金融機関コード（4 桁）かを返す。
// この辞書は代表サブセットであり、false はコードが実在しないことを意味しない。
func ValidBankCode(code string) bool { return bankCodes[code] }
