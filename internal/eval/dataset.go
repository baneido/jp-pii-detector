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
	{"マイナンバー: 1234-5678-9018", []string{"jp-my-number"}, []Span{
		{RuleID: "jp-my-number", Start: 8, End: 22, Tags: []string{"easy"}},
	}},
	{"個人番号：１２３４５６７８９０１８", []string{"jp-my-number"}, nil},
	{"my_number=987654321093", []string{"jp-my-number"}, nil},
	{"value = 123456789018", []string{"jp-my-number"}, nil},
	{"個人番号 525246130014", []string{"jp-my-number"}, nil},
	{"value = 123456789012", nil, nil},       // 検査用数字不一致
	{"id = 9123456789018", nil, nil},         // 13 桁（境界）
	{"group: 1234-5678-9012-3456", nil, nil}, // 4-4-4-4 グループ
	{"seq 111111111111", nil, nil},           // 全桁同一

	// ---- jp-phone-number ----
	{"TEL: 090-1234-5678", []string{"jp-phone-number"}, nil},
	{"携帯 09012345678", []string{"jp-phone-number"}, nil},
	{"本社: 03-1234-5678", []string{"jp-phone-number"}, nil},
	{"int'l: +81-90-1234-5678", []string{"jp-phone-number"}, nil},
	{"IP: 050-1234-5678", []string{"jp-phone-number"}, nil},
	{"電話番号：０９０ー１２３４ー５６７８", []string{"jp-phone-number"}, nil},
	{"連絡先 080-1111-2222,090-3333-4444", []string{"jp-phone-number"}, []Span{
		{RuleID: "jp-phone-number", Start: 4, End: 17, Tags: []string{"hard"}},
		{RuleID: "jp-phone-number", Start: 18, End: 31, Tags: []string{"hard"}},
	}},
	{"phone 0123-456-78", nil, nil}, // 桁数不正
	{"00-1234-5678", nil, nil},      // 第 2 桁が 0
	{"build 1-2-3456", nil, nil},    // 電話ではない

	// ---- jp-postal-code ----
	{"〒150-0043", []string{"jp-postal-code"}, nil},
	{"郵便番号: 530-0001", []string{"jp-postal-code"}, nil},
	{"〒530-0001 大阪府大阪市北区梅田3丁目", []string{"jp-postal-code", "jp-address"}, nil},
	{"version 150-0043", nil, nil}, // コンテキストなし
	{"範囲 100-200", nil, nil},       // 桁数不一致
	{"郵便番号: 000-0000", nil, nil},   // 実在しない地域コード

	// ---- jp-address ----
	{"東京都渋谷区道玄坂2-10-7", []string{"jp-address"}, nil},
	{"住所: 大阪府大阪市北区梅田3丁目1番3号", []string{"jp-address"}, nil},
	{"神奈川県横浜市中区本町1-2-3", []string{"jp-address"}, nil},
	{"東京都渋谷区では雨が降った", nil, nil}, // 番地なし
	{"本日は晴天なり", nil, nil},

	// ---- email-address ----
	{"contact: taro.yamada@gmail.com", []string{"email-address"}, []Span{
		{RuleID: "email-address", Start: 9, End: 30, Tags: []string{"easy"}},
	}},
	{"taro＠gmail.com", []string{"email-address"}, nil},
	{"user.name+tag@sub.company.co.jp", []string{"email-address"}, nil},
	{"admin@baneido.com", []string{"email-address"}, nil},
	{"user@example.com", nil, nil},         // 予約ドメイン
	{"user@foo.test", nil, nil},            // 予約 TLD
	{"user@service.notatld", nil, nil},     // IANA に存在しない TLD
	{"follow @handle on social", nil, nil}, // @ だがメールではない

	// ---- credit-card ----
	{"card: 4111-1111-1111-1111", []string{"credit-card"}, []Span{
		{RuleID: "credit-card", Start: 6, End: 25, Tags: []string{"easy"}},
	}},
	{"JCB 3530111333300000", []string{"credit-card"}, nil},
	{"mc: 5555 5555 5555 4444", []string{"credit-card"}, nil},
	{"amex 378282246310005", []string{"credit-card"}, nil},
	{"4111-1111-1111-1112", nil, nil},    // Luhn 不正
	{"order 1234567890123456", nil, nil}, // ブランド不正
	{"sn 41111111", nil, nil},            // 桁数不足

	// ---- jp-drivers-license（コンテキスト必須）----
	{"免許証番号: 305012345678", []string{"jp-drivers-license"}, nil},
	{"driver_license: 123456789012", []string{"jp-drivers-license"}, nil},
	{"id: 305012345678", nil, nil},           // コンテキストなし
	{"sublicense no 305012345678", nil, nil}, // ASCII 文脈語が単語の一部
	{"免許の更新に行く", nil, nil},                   // 番号なし

	// ---- jp-passport（コンテキスト必須）----
	{"パスポート番号: TK1234567", []string{"jp-passport"}, []Span{
		{RuleID: "jp-passport", Start: 9, End: 18, Tags: []string{"easy"}},
	}},
	{"passport: AB1234567", []string{"jp-passport"}, nil},
	{"TK1234567", nil, nil},         // コンテキストなし
	{"コード AB1234567 を入力", nil, nil}, // パスポート文脈なし

	// ---- jp-pension-number（コンテキスト必須）----
	{"基礎年金番号: 1234-567890", []string{"jp-pension-number"}, nil},
	{"年金番号 1234567890", []string{"jp-pension-number"}, nil},
	{"1234-567890", nil, nil}, // コンテキストなし

	// ---- jp-residence-card（コンテキスト必須）----
	{"在留カード番号 AB12345678CD", []string{"jp-residence-card"}, nil},
	{"zairyu: CD87654321EF", []string{"jp-residence-card"}, nil},
	{"AB12345678CD", nil, nil}, // コンテキストなし

	// ---- jp-bank-account（コンテキスト必須）----
	{"口座番号: 1234567", []string{"jp-bank-account"}, nil},
	{"普通預金 7654321", []string{"jp-bank-account"}, nil},
	{"1234567", nil, nil}, // コンテキストなし
	{"口座番号は別紙に記載しています。" +
		"ああああああああああああああああああああああああああああああ" +
		"1234567", nil, nil}, // 口座文脈が遠い
	{"注文番号 1234567", nil, nil}, // 口座文脈なし

	// ---- jp-health-insurance（コンテキスト必須）----
	{"保険者番号: 12345678", []string{"jp-health-insurance"}, nil},
	{"被保険者 87654321", []string{"jp-health-insurance"}, nil},
	{"12345678", nil, nil},       // コンテキストなし
	{"ビルド番号 12345678", nil, nil}, // 保険文脈なし

	// ---- person-name（ラベル付き・low）----
	{"氏名: 山田 太郎", []string{"person-name"}, nil},
	{"フリガナ＝ヤマダ　タロウ", []string{"person-name"}, nil},
	{"名前: 鈴木花子", []string{"person-name"}, nil},
	{"氏名は重要な情報です", nil, nil}, // ラベルだが値なし

	// ---- jp-birthdate（ラベル付き）----
	{"生年月日: 1990年1月23日", []string{"jp-birthdate"}, nil},
	{"生年月日：平成2年1月23日", []string{"jp-birthdate"}, nil},
	{"誕生日: 2000/12/31", []string{"jp-birthdate"}, nil},
	{"更新日: 2024年1月1日", nil, nil}, // 生年月日ラベルなし

	// ---- 実運用での限界を表す難ケース（○/△ ルールの精度を現実に近づける）----
	// ラベル付き氏名は一般名詞・定型句も拾ってしまう（適合率の限界）。
	{"氏名: 未定", nil, nil},
	{"氏名: 該当なし", nil, nil},
	// コンテキスト必須ルールは、同じ語の近くにある別種の数字を誤検出しうる。
	{"口座開設は1234567円から可能", nil, nil},       // 金額（口座コンテキスト下）
	{"免許の更新手数料 123456789012 円", nil, nil}, // 金額（免許コンテキスト下）
	{"年金の受給額 1234567890 円", nil, nil},     // 金額（年金コンテキスト下）
	{"被保険者数は12345678人", nil, nil},         // 人数（保険コンテキスト下）
	// 静的パターンの構造上の取りこぼし（再現率の限界）。
	{"口座番号: 123456", []string{"jp-bank-account"}, []Span{
		{RuleID: "jp-bank-account", Start: 6, End: 12, Tags: []string{"hard"}},
	}}, // 6 桁口座は 7 桁前提で未検出
	{"勤務地: 渋谷区道玄坂2-10-7", []string{"jp-address"}, []Span{
		{RuleID: "jp-address", Start: 5, End: 17, Tags: []string{"hard"}},
	}}, // 都道府県なしの住所は未検出

	// ---- 全ルール共通の陰性（適合率のストレス）----
	{"commit 1a2b3c4d5e6f7890", nil, nil},
	{"uuid 550e8400-e29b-41d4-a716-446655440000", nil, nil},
	{"timestamp: 20260611123456789", nil, nil},
	{"金額 1,234,567 円", nil, nil},
	{"sql id IN (1234567, 7654321)", nil, nil},
	{"log user_id=123456789012 trace=abcdef", nil, nil},
	{"price: 1980 yen, qty 12", nil, nil},
	{"semver v1.2.3 build 4567", nil, nil},
	{"color #FF00AA size 1024x768", nil, nil},
	{"coords 35.681236,139.767125", nil, nil},
}
