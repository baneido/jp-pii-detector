package rule

import (
	"testing"

	"github.com/baneido/jp-pii-detector/internal/piifixtures"
)

// このファイルは internal/rule のヘルパー関数（validPhone / validEmail /
// stripSeparators / containsASCIIAlnum / notOrgName / notRoleWord /
// honorificPersonNameValid）の「現状の振る舞い」を固定する安全網テスト。
// 値は internal/detect/detect_test.go と internal/eval/dataset.go の既存
// ケースから採っており、新しい仕様は発明していない。ルール本体をいじる前の
// リグレッション検知を目的とする。

// validPhone はマッチ文字列を受け取り、区切り文字（- / 半角スペース）や先頭の "+" を除去した上で、
// 桁数・先頭桁・国番号（+81）規則を満たす電話番号だけを有効とする。
func TestValidPhone(t *testing.T) {
	piifixtures.Require(t)
	tests := []struct {
		name string
		in   string
		want bool
	}{
		// ---- 有効（実在形式の値はフィクスチャから取得）----
		{"携帯 区切りあり", piifixtures.MustGet(t, "rule.phone_mobile_sep"), true},
		{"携帯 区切りなし", piifixtures.MustGet(t, "rule.phone_mobile_nosep"), true},
		{"固定 10 桁", piifixtures.MustGet(t, "rule.phone_landline_sep"), true},
		{"固定 10 桁・seed 辞書未収録の市外局番", "04992-2-1234", true},
		// 固定電話・区切りなし 10 桁（P10: 市外局番辞書による validPhone 拡張で
		// 新たに検出可能になったパターン）。フィクスチャの市外局番が
		// internal/dict/area_codes.txt のシードデータに含まれていない場合、
		// この行は失敗する（要: シードデータの拡充、または実データへの差し替え）。
		{"固定 10 桁 区切りなし", piifixtures.MustGet(t, "rule.phone_landline_nosep"), true},
		{"IP 電話", piifixtures.MustGet(t, "rule.phone_ip_sep"), true},
		{"国際表記 携帯", piifixtures.MustGet(t, "rule.phone_mobile_intl"), true},
		{"国際表記 固定 9 桁", piifixtures.MustGet(t, "rule.phone_landline_intl"), true},
		// ---- 無効（意図的に不正な値・実在 PII ではないため inline）----
		{"桁数不正（9 桁）", "0123-456-78", false},
		{"第 2 桁が 0", "00-1234-5678", false},
		{"11 桁の固定様式は実在しない", "0123-456-7890", false},
		{"国際表記 +81 + 10 桁で携帯以外は不正", "+81-12-3456-7890", false},
		{"全桁同一はダミー値として棄却", "00000000000", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validPhone(tt.in); got != tt.want {
				t.Errorf("validPhone(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// P10（#56）: 固定電話・区切りなし 10 桁は市外局番辞書（dict.ValidAreaCode）で
// 先頭一致の実在性を検証する。一方、区切りあり固定電話は area_codes.txt の seed
// 辞書が未完成でも取りこぼさない。
func TestValidPhoneAreaCodeDictionaryOnlyAppliesToNoSep(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"区切りなし・辞書に存在しないプレフィックス", "0212345678", false},
		{"区切りあり・seed 辞書未収録の実在市外局番", "04992-2-1234", true},
		{"連番のみ・辞書に存在しないプレフィックス", "0123456789", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validPhone(tt.in); got != tt.want {
				t.Errorf("validPhone(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// validEmail は予約済みドメイン（RFC 2606/6761）・未登録 TLD・ローカル部の
// 不正なドット配置などのダミー値を除外する。
func TestValidEmail(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		// ---- 有効 ----
		{"通常", "taro.yamada@gmail.com", true},
		{"ドット・プラス・サブドメイン", "user.name+tag@sub-domain.company.co.jp", true},
		{"IANA 登録済み TLD", "user@service.dev", true},
		// ---- 無効: 予約済みドメイン/TLD ----
		{"example ラベルは除外", "user@example.com", false},
		{"サブドメインの example も除外", "user@sub.example.co.jp", false},
		{"予約 TLD test", "user@foo.test", false},
		{"予約 TLD invalid", "user@foo.invalid", false},
		{"予約 TLD localhost", "user@foo.localhost", false},
		{"予約 TLD local", "user@host.local", false},
		{"未登録 TLD", "user@service.notatld", false},
		// ---- 無効: ローカル部 ----
		{"連続ドット", "taro..yamada@gmail.com", false},
		{"先頭ドット", ".taro@gmail.com", false},
		{"末尾ドット", "taro.@gmail.com", false},
		{"英数字を含まないローカル部", "_@gmail.com", false},
		// ---- 無効: ドメインのラベル境界 ----
		{"ラベル先頭のハイフン", "user@-foo.com", false},
		{"ラベル末尾のハイフン", "user@foo-.com", false},
		// ---- 無効: 構造不正（防御的ガード）----
		{"@ が先頭", "@gmail.com", false},
		{"@ が末尾", "user@", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validEmail(tt.in); got != tt.want {
				t.Errorf("validEmail(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// validBirthdate は形式が成立する生年月日のうち、実在する暦日だけを有効とする。
// 西暦・和暦の双方で、無効な月日（暦上ありえない値）と和暦の元号年範囲外を棄却する。
func TestValidBirthdate(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		// ---- 有効: 西暦 ----
		{"西暦 ハイフン", "2023-03-15", true},
		{"西暦 年月日", "2000年1月1日", true},
		{"西暦 スラッシュ", "1995/12/31", true},
		{"閏年の2月29日", "2000-02-29", true},
		// ---- 無効: 西暦の暦日 ----
		{"月が99", "2023-99-99", false},
		{"非閏年の2月29日", "2023-02-29", false},
		{"100で割れる非閏年(1900)の2月29日", "1900-02-29", false},
		{"13月", "2023-13-01", false},
		{"0月", "2023-00-10", false},
		{"4月31日", "2023-04-31", false},
		{"0日", "2023-05-00", false},
		// ---- 有効: 和暦 ----
		{"平成 元号年", "平成5年4月1日", true},
		{"令和", "令和3年12月31日", true},
		{"昭和の最終年(64)", "昭和64年1月1日", true},
		// ---- 無効: 和暦の元号年範囲外 ----
		{"昭和65年は存在しない", "昭和65年1月1日", false},
		{"平成32年は存在しない", "平成32年1月1日", false},
		{"大正16年は存在しない", "大正16年1月1日", false},
		// ---- 無効: 和暦でも暦日が不正 ----
		{"和暦で2月30日", "令和2年2月30日", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validBirthdate(tt.in); got != tt.want {
				t.Errorf("validBirthdate(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// stripSeparators はハイフンと半角スペースのみを除去し、その他の文字
// （'+' を含む）は保持する。
func TestStripSeparators(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"000-0000-0000", "00000000000"},
		{"1234 5678 9018", "123456789018"},
		{"+81-90-0000-0000", "+819000000000"},
		{"AB12345678CD", "AB12345678CD"},
		{"", ""},
		{"- -", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := stripSeparators(tt.in); got != tt.want {
				t.Errorf("stripSeparators(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// notOrgName は氏名候補が組織・団体名の語尾（personNameOrgSuffixes）で
// 終わらないことを検証する。値は特定個人を識別しない一般的な組織名・
// 頻出姓のためリテラルで安全。
func TestNotOrgName(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"田中商事", false},
		{"山田工業株式会社", false},
		{"田中", true},
		{"土屋", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := notOrgName(tt.in); got != tt.want {
				t.Errorf("notOrgName(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// notRoleWord は氏名候補が職業・役割・部署の語尾（personNameRoleSuffixes）で
// 終わらないことを検証する。実測 FP（本屋・運転手・取引先・関係者・保護者・
// 経理部・総務課・御中）と、衝突しない一般的な姓の双方を確認する。
func TestNotRoleWord(t *testing.T) {
	tests := []struct {
		name, in string
		want     bool
	}{
		{"本屋", "本屋", false},
		{"運転手", "運転手", false},
		{"取引先", "取引先", false},
		{"関係者", "関係者", false},
		{"保護者", "保護者", false},
		{"経理部", "経理部", false},
		{"総務課", "総務課", false},
		{"御中", "御中", false},
		{"係長", "係長", false},
		{"研修室", "研修室", false},
		{"桐谷太郎", "桐谷太郎", true},
		// 注: 田中・土屋 等の単漢字語尾姓は notRoleWord 単体では denylist に
		// 該当し false になる（田中は "中"、土屋は "屋" と衝突する）。この衝突は
		// honorificPersonNameValid が dict.IsPersonName を先に評価することで
		// 救済する（TestHonorificPersonNameValid 参照）。notRoleWord 単体の
		// 責務は denylist 照合のみであり、辞書一致による救済は行わない。
		{"単漢字語尾姓は denylist 単体では該当（辞書救済は上位で行う）", "田中", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := notRoleWord(tt.in); got != tt.want {
				t.Errorf("notRoleWord(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// honorificPersonNameValid は敬称付き氏名候補の検証器。組織語尾は常に棄却し、
// 姓名辞書一致（dict.IsPersonName）を職業・役割・部署 denylist（notRoleWord）
// より優先して評価するため、単漢字語尾と衝突する実在姓（阿部・服部・土屋・
// 北条 等）は denylist の巻き添えにならない。値はいずれも実在頻出姓・一般的な
// 組織/役割語で、単独では特定個人を識別しないためリテラルで安全。
func TestHonorificPersonNameValid(t *testing.T) {
	tests := []struct {
		name, in string
		want     bool
	}{
		{"辞書収録の衝突姓（屋）", "土屋", true},
		{"辞書収録の衝突姓（部）", "阿部", true},
		{"辞書収録の衝突姓（部）その2", "服部", true},
		{"辞書収録の衝突姓（条+氏族語尾ではない）", "北条", true},
		{"辞書外の実在人名は denylist 非該当なら許可", "桐谷太郎", true},
		{"組織名は常に棄却", "田中商事", false},
		{"株式会社は常に棄却", "山田工業株式会社", false},
		{"辞書外かつ職業語尾は棄却", "本屋", false},
		{"辞書外かつ役割語尾は棄却", "取引先", false},
		{"辞書外かつ部署語尾は棄却", "経理部", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := honorificPersonNameValid(tt.in); got != tt.want {
				t.Errorf("honorificPersonNameValid(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// containsASCIIAlnum はローカル部に ASCII 英数字が 1 文字以上あるかを返す。
func TestContainsASCIIAlnum(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"taro", true},
		{"user.name+tag", true},
		{"123", true},
		{"", false},
		{"___", false},
		{".+%-", false},
		{"あいう", false}, // マルチバイト非 ASCII は英数字とみなさない
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := containsASCIIAlnum(tt.in); got != tt.want {
				t.Errorf("containsASCIIAlnum(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
