package rule

// highRecallRuleIDs は高再現率モードでのみ有効にするルール ID 一覧。
// config パッケージが既定値を組み立てる際に参照する。
var highRecallRuleIDs = []string{
	"email-address-confusable",
	"email-address-eai",
	"jp-address-high-recall",
	"person-name-high-recall",
	"person-name-structured",
	"person-name-romaji",
}

// HighRecallRuleIDs は高再現率モード対象ルール ID の一覧を返す。
func HighRecallRuleIDs() []string {
	return append([]string(nil), highRecallRuleIDs...)
}

// nameRosterRuleIDs は「名簿ファイル判定」専用のオプトイン対象ルール ID。
// 高再現率（highRecallRuleIDs）とは独立した opt-in 軸にしているのは、判定の
// 根拠が質的に違うため。高再現率ルールが「行内のラベル・敬称という手がかりを
// 緩める」のに対し、こちらは手がかりが 1 つも無い羅列に対してファイル全体の
// 統計（姓名辞書に一致する行の割合）だけで判断する。--high-recall を選んだ
// 利用者が自動的にこの判定まで受け取ることのないよう、別フラグに分ける。
var nameRosterRuleIDs = []string{
	"person-name-roster",
}

// NameRosterRuleIDs は名簿ファイル判定の対象ルール ID の一覧を返す。
func NameRosterRuleIDs() []string {
	return append([]string(nil), nameRosterRuleIDs...)
}
