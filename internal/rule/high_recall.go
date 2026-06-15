package rule

// highRecallRuleIDs は高再現率モードでのみ有効にするルール ID 一覧。
// config パッケージが既定値を組み立てる際に参照する。
var highRecallRuleIDs = []string{
	"jp-address-high-recall",
	"person-name-high-recall",
}

// HighRecallRuleIDs は高再現率モード対象ルール ID の一覧を返す。
func HighRecallRuleIDs() []string {
	return append([]string(nil), highRecallRuleIDs...)
}
