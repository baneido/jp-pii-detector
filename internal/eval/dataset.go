package eval

// Dataset はルールごとの陽性・陰性ケースを集めたラベル付き評価データセット。
// すべて架空のダミー値（マイナンバー・カード番号は検査用数字が通る合成値）。
//
// 各ケースの Want には、その行で検出されるべきルール ID を列挙する
// （陰性ケースは空）。評価は行×ルール単位の集合で行うため、同一行に
// 同じルールの PII が複数あっても 1 件として扱う（複数件の取りこぼし
// 防止は internal/detect のテストで担保する）。陰性には「似て非なる値」
// （桁数違い・検査用数字不一致・コンテキスト欠如・別種の数字列）を多く含め、
// 適合率が甘くならないようにしている。
var Dataset = []Case{
	// ---- jp-my-number ----
	{"マイナンバー: 1234-5678-9018", []string{"jp-my-number"}},
	{"個人番号：１２３４５６７８９０１８", []string{"jp-my-number"}},
	{"my_number=987654321093", []string{"jp-my-number"}},
	{"value = 123456789018", []string{"jp-my-number"}},
	{"個人番号 525246130014", []string{"jp-my-number"}},
	{"value = 123456789012", nil},       // 検査用数字不一致
	{"id = 9123456789018", nil},         // 13 桁（境界）
	{"group: 1234-5678-9012-3456", nil}, // 4-4-4-4 グループ
	{"seq 111111111111", nil},           // 全桁同一

	// ---- jp-phone-number ----
	{"TEL: 090-1234-5678", []string{"jp-phone-number"}},
	{"携帯 09012345678", []string{"jp-phone-number"}},
	{"本社: 03-1234-5678", []string{"jp-phone-number"}},
	{"int'l: +81-90-1234-5678", []string{"jp-phone-number"}},
	{"IP: 050-1234-5678", []string{"jp-phone-number"}},
	{"電話番号：０９０ー１２３４ー５６７８", []string{"jp-phone-number"}},
	{"連絡先 080-1111-2222,090-3333-4444", []string{"jp-phone-number"}},
	{"phone 0123-456-78", nil}, // 桁数不正
	{"00-1234-5678", nil},      // 第 2 桁が 0
	{"build 1-2-3456", nil},    // 電話ではない

	// ---- jp-postal-code ----
	{"〒150-0043", []string{"jp-postal-code"}},
	{"郵便番号: 530-0001", []string{"jp-postal-code"}},
	{"〒530-0001 大阪府大阪市北区梅田3丁目", []string{"jp-postal-code", "jp-address"}},
	{"version 150-0043", nil}, // コンテキストなし
	{"範囲 100-200", nil},       // 桁数不一致

	// ---- jp-address ----
	{"東京都渋谷区道玄坂2-10-7", []string{"jp-address"}},
	{"住所: 大阪府大阪市北区梅田3丁目1番3号", []string{"jp-address"}},
	{"神奈川県横浜市中区本町1-2-3", []string{"jp-address"}},
	{"東京都渋谷区では雨が降った", nil}, // 番地なし
	{"本日は晴天なり", nil},

	// ---- email-address ----
	{"contact: taro.yamada@gmail.com", []string{"email-address"}},
	{"taro＠gmail.com", []string{"email-address"}},
	{"user.name+tag@sub.company.co.jp", []string{"email-address"}},
	{"admin@baneido.com", []string{"email-address"}},
	{"user@example.com", nil},         // 予約ドメイン
	{"user@foo.test", nil},            // 予約 TLD
	{"follow @handle on social", nil}, // @ だがメールではない

	// ---- credit-card ----
	{"card: 4111-1111-1111-1111", []string{"credit-card"}},
	{"JCB 3530111333300000", []string{"credit-card"}},
	{"mc: 5555 5555 5555 4444", []string{"credit-card"}},
	{"amex 378282246310005", []string{"credit-card"}},
	{"4111-1111-1111-1112", nil},    // Luhn 不正
	{"order 1234567890123456", nil}, // ブランド不正
	{"sn 41111111", nil},            // 桁数不足

	// ---- jp-drivers-license（コンテキスト必須）----
	{"免許証番号: 305012345678", []string{"jp-drivers-license"}},
	{"driver_license: 123456789012", []string{"jp-drivers-license"}},
	{"id: 305012345678", nil}, // コンテキストなし
	{"免許の更新に行く", nil},         // 番号なし

	// ---- jp-passport（コンテキスト必須）----
	{"パスポート番号: TK1234567", []string{"jp-passport"}},
	{"passport: AB1234567", []string{"jp-passport"}},
	{"TK1234567", nil},         // コンテキストなし
	{"コード AB1234567 を入力", nil}, // パスポート文脈なし

	// ---- jp-pension-number（コンテキスト必須）----
	{"基礎年金番号: 1234-567890", []string{"jp-pension-number"}},
	{"年金番号 1234567890", []string{"jp-pension-number"}},
	{"1234-567890", nil}, // コンテキストなし

	// ---- jp-residence-card（コンテキスト必須）----
	{"在留カード番号 AB12345678CD", []string{"jp-residence-card"}},
	{"zairyu: CD87654321EF", []string{"jp-residence-card"}},
	{"AB12345678CD", nil}, // コンテキストなし

	// ---- jp-bank-account（コンテキスト必須）----
	{"口座番号: 1234567", []string{"jp-bank-account"}},
	{"普通預金 7654321", []string{"jp-bank-account"}},
	{"1234567", nil},      // コンテキストなし
	{"注文番号 1234567", nil}, // 口座文脈なし

	// ---- jp-health-insurance（コンテキスト必須）----
	{"保険者番号: 12345678", []string{"jp-health-insurance"}},
	{"被保険者 87654321", []string{"jp-health-insurance"}},
	{"12345678", nil},       // コンテキストなし
	{"ビルド番号 12345678", nil}, // 保険文脈なし

	// ---- person-name（ラベル付き・low）----
	{"氏名: 山田 太郎", []string{"person-name"}},
	{"フリガナ＝ヤマダ　タロウ", []string{"person-name"}},
	{"名前: 鈴木花子", []string{"person-name"}},
	{"氏名は重要な情報です", nil}, // ラベルだが値なし

	// ---- jp-birthdate（ラベル付き）----
	{"生年月日: 1990年1月23日", []string{"jp-birthdate"}},
	{"生年月日：平成2年1月23日", []string{"jp-birthdate"}},
	{"誕生日: 2000/12/31", []string{"jp-birthdate"}},
	{"更新日: 2024年1月1日", nil}, // 生年月日ラベルなし

	// ---- 実運用での限界を表す難ケース（○/△ ルールの精度を現実に近づける）----
	// ラベル付き氏名は一般名詞・定型句も拾ってしまう（適合率の限界）。
	{"氏名: 未定", nil},
	{"氏名: 該当なし", nil},
	// コンテキスト必須ルールは、同じ語の近くにある別種の数字を誤検出しうる。
	{"口座開設は1234567円から可能", nil},       // 金額（口座コンテキスト下）
	{"免許の更新手数料 123456789012 円", nil}, // 金額（免許コンテキスト下）
	{"年金の受給額 1234567890 円", nil},     // 金額（年金コンテキスト下）
	{"被保険者数は12345678人", nil},         // 人数（保険コンテキスト下）
	// 静的パターンの構造上の取りこぼし（再現率の限界）。
	{"口座番号: 123456", []string{"jp-bank-account"}}, // 6 桁口座は 7 桁前提で未検出
	{"勤務地: 渋谷区道玄坂2-10-7", []string{"jp-address"}}, // 都道府県なしの住所は未検出

	// ---- 全ルール共通の陰性（適合率のストレス）----
	{"commit 1a2b3c4d5e6f7890", nil},
	{"timestamp: 20260611123456789", nil},
	{"price: 1980 yen, qty 12", nil},
	{"semver v1.2.3 build 4567", nil},
	{"color #FF00AA size 1024x768", nil},
}
