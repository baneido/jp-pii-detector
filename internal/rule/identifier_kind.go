package rule

// PublicBusinessKind は jp-invoice-number（適格請求書発行事業者登録番号）が検出した
// マッチ文字列を下位種別に分類する Rule.Kind 実装。登録番号は法人番号と同一の採番体系
// （T + 検査用数字を含む 13 桁）で、国税庁の適格請求書発行事業者公表サイトにより誰でも
// 検索・閲覧できる公開情報のため、常に "public-business" を返す定数分類にしている
// （docs/development.md の jp-invoice-number 節参照）。引数 match は現状使っていないが、
// 将来「法人番号由来か個人事業主由来か」など登録番号の内訳を判別できるようになった場合に
// 備え、PhoneKind 等と同じ func(match string) string シグネチャに揃えている。
//
// [rules] exclude_kinds（internal/config）はルールを問わず一致する種別名をすべて除外する
// ため、kind の語彙は他ルールと衝突しない名前を選ぶ必要がある。"public-business" は
// jp-phone-number の PhoneKind が返す下位種別（service/ip/mobile/fixed/international、
// internal/rule/phone_kind.go）のいずれとも一致しない。
func PublicBusinessKind(match string) string {
	return "public-business"
}
