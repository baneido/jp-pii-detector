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
//     GCS へ再アップロードする（internal/evalcase.Case.Tags は
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

// TestProbeResolvedLowercaseLetterFalseNegatives は、jp-residence-card /
// jp-passport の英字部分を小文字表記（ab12345678cd / ab1234567 等）にも
// 対応させたことで偽陰性から検出に転じた系統を固定化する。元は
// TestProbeRegressionKnownFalseNegatives に「検出なし」として並んでいたもので、
// パターンの [A-Z] を [A-Za-z] へ拡張し、ルール改善に伴い期待値を反転した
// （回帰データセットとして機能している証拠）。
func TestProbeResolvedLowercaseLetterFalseNegatives(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct{ name, line, want string }{
		{"residence-card-lowercase-letters", "在留カード番号: ab12345678cd", "jp-residence-card"},
		{"passport-lowercase-letters", "パスポート番号: ab1234567", "jp-passport"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line), tt.want)
		})
	}
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

// TestProbeResolvedPostalBareSevenDigitFalseNegative は、ラベル付きコンテキスト下で
// ハイフンなし裸 7 桁の郵便番号を検出するパターンを追加したことで、偽陰性から
// 検出に転じた系統を固定化する。元は TestProbeRegressionKnownFalseNegatives に
// "known-limitation" として並んでいたもので、ルール改善に伴い期待値を反転した
// （回帰データセットとして機能している証拠）。1000001（東京都千代田区千代田＝
// 皇居）は日本郵便の実在集合に含まれる。
func TestProbeResolvedPostalBareSevenDigitFalseNegative(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line, want string
	}{
		{"postal-bare-7digit-no-hyphen", "郵便番号 1000001", "jp-postal-code"},
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

// TestProbeResolvedKnownTestPANFalsePositives は、公知の決済sandbox用PANを
// SHA-256 denylistで棄却するようになったことを固定する。値はLuhnとブランド
// 条件を満たすため、区切り除去後のValidateで明示集合だけを判定する。
func TestProbeResolvedKnownTestPANFalsePositives(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
	}{
		{"visa-1", "テストカード番号: 4111111111111111"},
		{"visa-2", "Stripe test card: 4242424242424242"},
		{"visa-separated", "Stripe test card: 4242-4242-4242-4242"},
		{"mastercard", "Mastercard test: 5555555555554444"},
		{"amex-1", "Amex test: 378282246310005"},
		{"amex-2", "Amex sample: 371449635398431"},
		{"discover-1", "Discover test card: 6011111111111117"},
		{"discover-2", "Discover sample: 6011000990139424"},
		{"diners", "Diners test card: 30569309025904"},
		{"jcb", "JCB test card: 3530111333300000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line))
		})
	}
}

// TestProbeRegressionKnownFalsePositives は、実験プローブで確認された偽陽性の
// うち再現を確認できた系統を固定化する。ここでの「検出あり」は望ましくない
// 現状の挙動であり、将来の Validate 強化（例: #53 業務ID語彙拡張）で
// 意図的に解消されうる。解消された場合はこのテストを
// 更新し、pii-fixtures.json 側にも反映すること。
//
// 「12桁ジョブID」「受付番号は…」「型番: …」「お問い合わせ受付番号」
// 「年金相談受付番号」の 5 系統は、負文脈「隣接ラベル」判定のグルー許容
// （hasLabelBefore）と採番ラベル接尾辞ヒューリスティック（
// hasNumberingSuffixBefore、internal/detect/negative_context.go）の追加で
// 解消され、下の TestProbeResolvedNumberingLabelFalsePositives へ移設した。
func TestProbeRegressionKnownFalsePositives(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
		wantRule   string
		wantConf   rule.Confidence
	}{
		// jp-drivers-license: 「license no」等の英語ラベルは運転免許以外
		// （ソフトウェアライセンス番号等）でも一般的に使われるため誤検出する。
		// ラベル自体が正文脈語（Context の "license no"）そのものであり、
		// 採番ラベル接尾辞ヒューリスティックの保護規則（ラベルに正文脈語を
		// 含む場合は抑制しない）が働くため、この系統は意図的に未解消のまま
		// 残る（別問題。#53 の業務ID語彙拡張が本来の対応方針）。
		{"probe-fp:driverslicense-generic-license-label", "License No: 123456789012", "jp-drivers-license", rule.High},

		// jp-health-insurance: RequireContext 系ルールはラベル語の有無しか
		// 見ないため、値の意味論（実際は資格確認受付ID等）までは判定できず
		// 誤検出する。ラベル直前は「受付ID」で採番ラベル接尾辞ヒューリスティック
		// の対象（id 接尾辞）になるが、値からラベル方向に 12 ルーン遡った
		// トークンに「保険証」（Context 語）が入ってしまうため、保護規則が
		// 働いてしまい抑制されない（トークン窓が偶然この語まで届く、この
		// 具体的な文言に起因する副作用）。窓を狭めると
		// TestKaigoInsuranceRule の「要介護認定 被保険者番号」のような、
		// 空白を挟んだ正当な複合ラベルの保護が効かなくなる（要 #いずれかの
		// 追加の設計拡張。詳細はタスクA報告のスコープ外メモを参照）。
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

// TestProbeResolvedNumberingLabelFalsePositives は、負文脈「隣接ラベル」
// 判定のグルー許容（hasLabelBefore が助詞・コロン・イコールを最大 2 個まで
// 読み飛ばす）と採番ラベル接尾辞ヒューリスティック（hasNumberingSuffixBefore
// が「番号/コード/キー/id/code/key/sku/no」で終わるラベルを未知語彙でも
// 拾う）で、偽陽性から抑制（検出なし）に転じた系統を固定化する。元は
// TestProbeRegressionKnownFalsePositives に「検出あり」として並んでいたもので、
// ルール改善に伴い期待値を反転した（#46 の前例と同じく、回帰データセットとして
// 機能している証拠）。
func TestProbeResolvedNumberingLabelFalsePositives(t *testing.T) {
	d := newDetector(t, "")
	tests := []struct {
		name, line string
	}{
		// 助詞「は」で採番ラベル「受付番号」と値が途切れていたため、旧来の
		// hasUnitBefore（空白・タブしか読み飛ばさない）では抑制できなかった。
		{"probe-fp:mynumber-lookalike-ticket-id", "受付番号は123456000007です"},
		// ASCII 語「ID」とコロンで採番ラベル「ジョブ」と値が途切れており、
		// 明示語彙の隣接一致（「ジョブ」自体）は届かないが、接尾辞
		// ヒューリスティックが「ジョブID」の "id" 接尾辞として拾う。
		{"probe-fp:mynumber-lookalike-job-id", "ジョブID: 202507000004"},
		// コロン+空白で採番ラベル「型番」と値が途切れていたため、旧来の
		// hasUnitBefore では抑制できなかった（グルー許容で解消）。
		{"probe-fp:passport-lookalike-model-number-with-context", "海外パスポート対応 型番: TK1234567"},
		// コロン+空白で採番ラベル「受付番号」と値が途切れていた
		// （グルー許容で解消。値の直前ラベルは「受付番号」で、文中の
		// 「口座番号」は値から離れているため無関係）。
		{"probe-fp:bankaccount-lookalike-inquiry-ticket-id", "口座番号に関するお問い合わせ受付番号: 1234567"},
		// コロン+空白で採番ラベル「受付番号」と値が途切れていた
		// （グルー許容で解消）。
		{"probe-fp:pension-lookalike-inquiry-ticket-id", "年金相談受付番号: 1234-567890"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRules(t, d.ScanLine("f.txt", 1, tt.line))
		})
	}
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
