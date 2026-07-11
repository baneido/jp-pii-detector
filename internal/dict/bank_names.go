package dict

import (
	"embed"
	"strings"
)

// bank_names.txt は著名な金融機関名（本体＋業態サフィックスを含む完全名）を
// 収録した「代表サブセット」辞書。全国銀行協会（Zengin）加盟金融機関の
// 公式マスタ（約 1,100 件）ではなく、手作業で収録した一部にとどまる。
// 収録経緯・既知の限界は bank_names.txt のヘッダコメントと
// docs/development.md を参照。
//
//go:embed bank_names.txt
var bankNamesFS embed.FS

var bankNames = loadBankNameSet("bank_names.txt")

func loadBankNameSet(name string) map[string]bool {
	data, err := bankNamesFS.ReadFile(name)
	if err != nil {
		panic(err)
	}
	out := map[string]bool{}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = true
	}
	return out
}

// IsBankName は s（本体＋業態サフィックスを含む完全な名称。例: "三菱UFJ銀行"）が
// 収録済みの実在銀行・信用金庫・労働金庫名かを返す。
//
// この辞書は代表サブセットであり、収録外の実在金融機関は false になりうる
// （適合率優先の existence-check であり、網羅的な allowlist ではない）。
func IsBankName(s string) bool { return bankNames[s] }
