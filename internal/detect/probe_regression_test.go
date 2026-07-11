package detect

import (
	"testing"

	"github.com/baneido/jp-pii-detector/internal/rule"
)

// probe_regression_test.go は issue #42「実験プローブで確認済みの FN 35 系統・
// FP 40 系統の回帰データセット化」の暫定実装（フィクスチャ不要のインライン
// Go テスト版）。
//
// 背景: 元となった実験プローブの生ログ（35 系統の偽陰性・40 系統の偽陽性の
// 具体的な行データ）はこのリポジトリにもセッションにも存在せず、issue 本文には
// 代表例（空白区切りマイナンバー・0312345678・CSV 2 行目以降・12桁ジョブID・
// JAN・テストカード・型番 TK1234567・スコア「3-2」の住所化 等）が挙げられて
// いるのみで、75 件の網羅列挙は含まれていない。加えて評価データセット本体
// （pii-fixtures.json）は GCS 管理でリポジトリ外・本セッションでは
// $JP_PII_FIXTURES 未設定のため参照・更新できない。
//
// そのため本ファイルは、issue が名指しした代表パターンおよびそれと同系統の
// 表記ゆれ・文脈誤認識を、実際に go test で個別に発火/非発火を再確認した
// 上で（issue 記載のリスク: 「型番 TK1234567」は文脈語なしでは発火しない、
// 等の非再現ケースを個別検証済み）、フィクスチャ不要の回帰テストとして固定化
// したものである。ルール・検出ロジックはこの変更で一切変更しない
// （issue の対応方針どおり）。
//
// 残作業（このファイルでは完結しない）:
//   - pii-fixtures.json 側に、ここで確認した行を Case（Tags 付き）として追加し
//     GCS へ再アップロードする（internal/piifixtures.Case.Tags は本 PR で追加
//     済み。"probe-fn:*" / "probe-fp:*" / "known-limitation" のタグ命名は
//     下記サブテスト名の "probe-fn:" / "probe-fp:" 接頭辞に合わせてある）。
//   - internal/eval/eval_test.go の wantF1 と README バッジ・docs/accuracy.md の
//     3 点更新（データセット反映後、JP_PII_FIXTURES を設定できる環境で実施）。
//   - 元の実験プローブの残り系統（本ファイル未収録分）の洗い出し。

// TestProbeRegressionKnownFalseNegatives は、実験プローブで確認された偽陰性の
// うち再現を確認できた系統を固定化する。ここでの「検出なし」は将来のルール
// 改善（例: #46 数字系ルールの区切り表記ゆれ対応）で意図的に反転しうる。
// 反転した場合はこのテストを更新し、pii-fixtures.json 側にも反映すること
// （テストの更新が必要になること自体が「回帰データセットとして機能している」
// 証拠であり、壊れること自体は問題ではない）。
//
// "known-limitation" を付したケースは、アーキテクチャ上の設計上の割り切り
// （CLAUDE.md に明記済みの ±1 行しか相関しないクロスライン文脈や、桁数のみの
// 郵便番号非対応）であり、バグ修正ではなく将来の設計拡張でのみ変わりうる。
func TestProbeRegressionKnownFalseNegatives(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
	}{
		// jp-my-number: 12 桁が区切り文字（ドット・括弧・スラッシュ）で
		// 分断されると \d{12} 連続要求にマッチしない。issue 記載の
		// 「空白区切りマイナンバー」系統のうち、空白 6-6 / 4-4-4 は #46 で
		// 検出に転じたため下の TestProbeResolvedNumericSeparatorFalseNegatives へ移動。
		{"probe-fn:mynumber-dot-separated", "個人番号：123456.000007"},
		{"probe-fn:mynumber-paren-grouped", "mynumber: (123456)000007"},
		{"probe-fn:mynumber-slash-separated", "my_number: 123456/000007"},

		// 括弧市外局番・空白/ドット区切り携帯は #46 で検出に転じたため下の
		// TestProbeResolvedNumericSeparatorFalseNegatives へ移動。スラッシュ
		// 区切り・混在区切りは依然パターン未対応で FN のまま。
		{"probe-fn:phone-slash-separated-mobile", "連絡先 090/1234/5678"},
		{"probe-fn:phone-mixed-separator", "本社: 03.1234-5678"},

		// jp-postal-code: 郵便番号はハイフンなしの裸 7 桁を検出する
		// パターンを持たない（設計上の意図的な非検出）。
		{"probe-fn:postal-bare-7digit-no-hyphen known-limitation", "郵便番号 1000001"},

		// 都道府県名を伴わない市区町村＋番地は、既定プロファイルでは
		// jp-address-high-recall（高再現率限定）でしか拾えない（既定は非検出）。
		{"probe-fn:address-missing-prefecture known-limitation", "住所: 渋谷区神南1-2-3"},

		// RequireContext 系ルールの区切り文字表記ゆれ。空白区切り年金は #46 で
		// 検出に転じたため下の TestProbeResolvedNumericSeparatorFalseNegatives へ移動。
		{"probe-fn:pension-dot-separated", "年金 1234.567890"},
		{"probe-fn:health-insurance-space-separated", "保険者番号 1234 5678"},
		{"probe-fn:bank-account-space-separated", "口座番号 123 4567"},
		{"probe-fn:bank-account-fullwidth-slash-separated", "口座番号 123／4567"},
		{"probe-fn:drivers-license-dot-separated", "免許 1234.5678.9012"},

		// jp-drivers-license: RequireContextWindow（40 ルーン）を超えて
		// コンテキスト語から離れると昇格せず検出されない
		// （CLAUDE.md に明記済みの距離窓アーキテクチャの限界）。
		{"probe-fn:drivers-license-context-beyond-window known-limitation",
			"運転免許証について説明します。これは長い前置きの文章でありここには本題と関係のない一般的な話が続きます。番号は123456789012です。"},

		// jp-residence-card / jp-passport: 英字部分が小文字だとパターンの
		// [A-Z] に一致しない（大文字専用）。
		{"probe-fn:residence-card-lowercase-letters", "在留カード番号: ab12345678cd"},
		{"probe-fn:passport-lowercase-letters", "パスポート番号: ab1234567"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line))
		})
	}
}

func TestProbeResolvedAddressKanjiNumeralFalseNegative(t *testing.T) {
	d := newDetector(t, "")
	assertRules(t, d.ScanLine("f.txt", 1, "住所: 東京都渋谷区神南二丁目十番七号"), "jp-address")
}

// TestProbeResolvedNumericSeparatorFalseNegatives は、#46（数字系ルールの区切り
// 表記ゆれ対応）で偽陰性から検出に転じた系統を固定化する。元は
// TestProbeRegressionKnownFalseNegatives に「検出なし」として並んでいたもので、
// ルール改善に伴い期待値を反転した（回帰データセットとして機能している証拠）。
func TestProbeResolvedNumericSeparatorFalseNegatives(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line, want string
	}{
		{"mynumber-space-separated-6-6", "マイナンバー: 123456 000007", "jp-my-number"},
		{"mynumber-space-separated-4-4-4", "マイナンバー: 1234 0000 0004", "jp-my-number"},
		{"phone-parenthesized-area-code", "本社: (03)1234-5678", "jp-phone-number"},
		{"phone-space-separated-mobile", "携帯 090 1234 5678", "jp-phone-number"},
		{"phone-dot-separated-mobile", "TEL 090.1234.5678", "jp-phone-number"},
		{"pension-space-separated", "年金 1234 567890", "jp-pension-number"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want)
		})
	}
}

func TestProbeResolvedFixedPhoneWithoutSeparator(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{"電話番号: 0312345678", "TEL: 0662345678"} {
		assertRules(t, d.ScanLine("f.txt", 1, line), "jp-phone-number")
	}
}

// TestProbeResolvedCSVColumnContext は issue 記載の「CSV 2 行目以降」系統。
// 元は隣接ウィンドウ（±1 行）の制約でヘッダ直後の 1 データ行しか検出できない
// known-limitation だったが、#63 の CSV/TSV 列コンテキスト機構
// （internal/detect/csv_context.go）でヘッダのラベルを同一列の全データ行へ
// 伝播するようになったため、3 行目以降も検出に転じた（回帰データセットとして
// 機能している証拠。期待値を反転した）。
func TestProbeResolvedCSVColumnContext(t *testing.T) {
	d := newDetector(t, "")
	csv := "支店番号,口座番号\n001,1234567\n002,2345678\n003,3456789\n"
	fs := d.ScanContent("data.csv", csv)

	got := map[int]bool{}
	for _, f := range fs {
		if f.RuleID == "jp-bank-account" {
			got[f.Line] = true
		}
	}
	// ヘッダのラベルが同一列（口座番号列）の全データ行へ伝播するため、
	// 2〜4 行目すべてが検出される。
	for _, line := range []int{2, 3, 4} {
		if !got[line] {
			t.Errorf("%d 行目が検出されていない（列コンテキストが全データ行へ伝播していない）: %+v", line, fs)
		}
	}
}

// TestProbeRegressionKnownFalsePositives は、実験プローブで確認された偽陽性の
// うち再現を確認できた系統を固定化する。ここでの「検出あり」は望ましくない
// 現状の挙動であり、将来の Validate 強化（例: #04 公知テスト PAN denylist、
// #53 業務ID語彙拡張）で意図的に解消されうる。解消された場合はこのテストを
// 更新し、pii-fixtures.json 側にも反映すること。
func TestProbeRegressionKnownFalsePositives(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		wantRule   string
		wantConf   rule.Confidence
	}{
		// jp-my-number: ラベルや文脈と無関係に、検査用数字さえ偶然一致すれば
		// 12 桁の業務 ID（ジョブID・受付番号等）も拾ってしまう
		// （Context はあくまで信頼度昇格用で、検出のゲートではないため）。
		// issue 記載の「12桁ジョブID」系統。
		{"probe-fp:mynumber-lookalike-job-id", "ジョブID: 202507000004", "jp-my-number", rule.Medium},
		{"probe-fp:mynumber-lookalike-ticket-id", "受付番号は123456000007です", "jp-my-number", rule.Medium},

		// credit-card: 公知のテストカード番号（Stripe/PayPal 等のサンプルで
		// 広く使われる値）は Luhn とブランド桁数を満たすため検出されるが、
		// 実在の個人 PII ではない。issue 記載の「テストカード」系統。
		{"probe-fp:creditcard-wellknown-test-visa-1", "テストカード番号: 4111111111111111", "credit-card", rule.High},
		{"probe-fp:creditcard-wellknown-test-visa-2", "Stripe test card: 4242424242424242", "credit-card", rule.High},
		{"probe-fp:creditcard-wellknown-test-mastercard", "Mastercard test: 5555555555554444", "credit-card", rule.High},
		{"probe-fp:creditcard-wellknown-test-amex-1", "Amex test: 378282246310005", "credit-card", rule.High},
		{"probe-fp:creditcard-wellknown-test-amex-2", "Amex sample: 371449635398431", "credit-card", rule.High},
		{"probe-fp:creditcard-wellknown-test-discover-1", "Discover test card: 6011111111111117", "credit-card", rule.High},
		{"probe-fp:creditcard-wellknown-test-discover-2", "Discover sample: 6011000990139424", "credit-card", rule.High},
		{"probe-fp:creditcard-wellknown-test-diners", "Diners test card: 30569309025904", "credit-card", rule.High},
		{"probe-fp:creditcard-wellknown-test-jcb", "JCB test card: 3530111333300000", "credit-card", rule.High},

		// jp-passport: 「パスポート」等の文脈語がたまたま同じ行にあると、
		// それと無関係な英字2桁+数字7桁の型番も旅券番号として検出される。
		// issue 記載の「型番 TK1234567」系統（元の issue コメントが指摘した
		// とおり、文脈語なしの単独表記では再現しない = 下の
		// no-context ケースは検出なしが正しい仕様どおりの挙動）。
		{"probe-fp:passport-lookalike-model-number-with-context", "海外パスポート対応 型番: TK1234567", "jp-passport", rule.High},

		// jp-drivers-license: 「license no」等の英語ラベルは運転免許以外
		// （ソフトウェアライセンス番号等）でも一般的に使われるため誤検出する。
		{"probe-fp:driverslicense-generic-license-label", "License No: 123456789012", "jp-drivers-license", rule.High},

		// RequireContext 系ルールはラベル語の有無しか見ないため、値の意味論
		// （実際は問い合わせ受付番号等）までは判定できず誤検出する。
		{"probe-fp:bankaccount-lookalike-inquiry-ticket-id", "口座番号に関するお問い合わせ受付番号: 1234567", "jp-bank-account", rule.Medium},
		{"probe-fp:pension-lookalike-inquiry-ticket-id", "年金相談受付番号: 1234-567890", "jp-pension-number", rule.High},
		{"probe-fp:healthinsurance-lookalike-reception-id", "健康保険証の資格確認受付ID 12345678", "jp-health-insurance", rule.Medium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := d.ScanLine("f.txt", 1, tt.line)
			assertRules(t, fs, tt.wantRule)
			if fs[0].Confidence != tt.wantConf {
				t.Errorf("confidence = %v, want %v", fs[0].Confidence, tt.wantConf)
			}
		})
	}

	// 比較対照: issue のレビューが指摘したとおり、文脈語（パスポート/旅券/
	// passport）が同じ行に一切なければ、AA0000000 形式の型番だけでは
	// jp-passport は発火しない（RequireContext のゲートが正しく働いている）。
	// 「型番 TK1234567」という素朴なプローブ文言そのままでは非再現、という
	// issue 対応方針の指摘（点2）を裏付けるための回帰。
	t.Run("probe-fp:passport-lookalike-model-number-without-context-is-not-detected", func(t *testing.T) {
		assertRules(t, d.ScanLine("f.txt", 1, "型番 TK1234567"))
	})
}

func TestProbeResolvedKnownFalsePositives(t *testing.T) {
	d := newDetector(t, "")
	for _, line := range []string{
		"JANコード: 4901234000003",
		"商品バーコード 4512345000004",
		"東京都渋谷区の試合結果はスコア3-2でした",
		"大阪府大阪市の得点はスコア5-3でした",
	} {
		assertRules(t, d.ScanLine("f.txt", 1, line))
	}
}
