package rule

import (
	"fmt"
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
		// ---- 無効: ローカル部/ドメイン第 1 ラベルのダミー値語（部分一致）----
		{"ローカル部が hoge", "hoge@fuga.co.jp", false},
		{"ドメイン第1ラベルが sample", "test1@sample.com", false},
		{"ローカル部が dummy を含む", "dummyuser@company.co.jp", false},
		{"ドメイン第1ラベルが foo", "user@foo.co.jp", false},
		{"ローカル部が hogehoge", "hogehoge@company.co.jp", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validEmail(tt.in); got != tt.want {
				t.Errorf("validEmail(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// 加入者番号部の並びだけでは実在番号と安全に区別できないため、末尾 4 桁が
// 全桁同一または連番でも、電話番号全体の形式が妥当なら許容する。
func TestValidPhoneAllowsSubscriberPatterns(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"携帯 加入者番号部が全桁同一", "090-1234-2222", true},
		{"携帯 加入者番号部が連番", "090-1234-5678", true},
		{"固定 加入者番号部が全桁同一", "03-1234-0000", true},
		{"国際表記 携帯 加入者番号部が全桁同一", "+81-90-1234-2222", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validPhone(tt.in); got != tt.want {
				t.Errorf("validPhone(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// genMyNumber は先頭 11 桁から検査用数字を計算して 12 桁を生成する
// （internal/checksum/checksum_test.go の同名ヘルパーと同じロジックを
// このパッケージのテスト用に書き下したもの）。
func genMyNumber(first11 string) string {
	sum := 0
	for n := 1; n <= 11; n++ {
		p := int(first11[11-n] - '0')
		q := n + 1
		if n >= 7 {
			q = n - 5
		}
		sum += p * q
	}
	r := sum % 11
	check := 0
	if r > 1 {
		check = 11 - r
	}
	return first11 + fmt.Sprint(check)
}

// validMyNumber は検査用数字に加え、先頭ゼロ埋め連番を棄却する。マイナンバーは
// 日付を符号化しないため、先頭 8 桁が実在する暦日（YYYYMMDD）に見えるだけでは
// 棄却しない。
func TestValidMyNumber(t *testing.T) {
	tests := []struct {
		name    string
		first11 string
		want    bool
	}{
		{"検査用数字一致・連番でも日付でもない", "12345678901", true}, // = 123456789018
		{"先頭ゼロ埋め＋末尾昇順連番は棄却", "00000023456", false},  // = 000000234567
		{"先頭8桁が実在する暦日（2025-06-30）でも許容", "20250630123", true},
		{"先頭8桁が実在する暦日（1990-01-23）でも許容", "19900123000", true}, // = 199001230000
		{"先頭8桁が暦日として不正（月56日78）は許容", "12345678901", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := genMyNumber(tt.first11)
			if got := validMyNumber(v); got != tt.want {
				t.Errorf("validMyNumber(%q) = %v, want %v", v, got, tt.want)
			}
		})
	}
	if validMyNumber("123456789012") {
		t.Error("validMyNumber(検査用数字不一致) = true, want false")
	}
	if !validMyNumber("199001230000") {
		t.Error("validMyNumber(199001230000) = false, want true")
	}
}

// validDriversLicense は全桁同一・先頭 0（公安委員会コード未満）のダミー値を
// 棄却する。検査用数字アルゴリズムは非公開のため使わない。
func TestValidDriversLicense(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"実在しうる値（公安委員会コード想定の先頭2桁）", "305012345678", true},
		{"全桁同一は棄却", "111111111111", false},
		{"先頭が0は棄却（公安委員会コード未満）", "012345678901", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validDriversLicense(tt.in); got != tt.want {
				t.Errorf("validDriversLicense(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// validBankAccount / validHealthInsurance は全桁同一のダミー値だけを棄却する。
// 口座番号・保険者番号は検査用数字を持たず、連番も実在しうるため許容する。
func TestValidBankAccount(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"昇順連番も実在しうる", "1234567", true},
		{"全桁同一は棄却", "0000000", false},
		{"先頭ゼロ埋め＋末尾昇順連番も許容", "0000001", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validBankAccount(tt.in); got != tt.want {
				t.Errorf("validBankAccount(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidHealthInsurance(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"昇順連番も実在しうる", "12345678", true},
		{"全桁同一は棄却", "00000000", false},
		{"先頭ゼロ埋め＋末尾昇順連番も許容", "00000123", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validHealthInsurance(tt.in); got != tt.want {
				t.Errorf("validHealthInsurance(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// validPassport は末尾 7 桁が全桁同一の明らかなダミー値（0000000 等）のみを
// 棄却する。旅券冊子記号の先頭文字制限（[T,M] 等）は一次情報の裏取りが
// できるまで導入しない（NH1234567 のような値は現状も検出対象のまま）。
func TestValidPassport(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"実在しうる値", "TK1234567", true},
		{"数字7桁が全桁同一は棄却", "TK0000000", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validPassport(tt.in); got != tt.want {
				t.Errorf("validPassport(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// validResidenceCard は出入国在留管理庁の文字集合仕様で使われない英字 I・O
// を含む値と、数字 8 桁が全桁同一のダミー値を棄却する。
func TestValidResidenceCard(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"実在しうる値", "AB12345678CD", true},
		{"先頭の英字に I を含むと棄却", "IB12345678CD", false},
		{"末尾の英字に O を含むと棄却", "AB12345678CO", false},
		{"数字8桁が全桁同一は棄却", "AB00000000CD", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validResidenceCard(tt.in); got != tt.want {
				t.Errorf("validResidenceCard(%q) = %v, want %v", tt.in, got, tt.want)
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
		// ---- 有効: 元号の単字アルファベット略記（免許証・保険証転記で一般的）----
		{"昭和 単字略記 ドット区切り", "S60.1.2", true},
		{"平成 単字略記 スラッシュ区切り", "H5/4/1", true},
		{"明治 単字略記の最終年", "M45.7.30", true},
		// ---- 有効: 元年（改元年）表記 ----
		{"令和元年", "令和元年5月1日", true},
		{"平成元年", "平成元年1月8日", true},
		{"単字略記 + 元年", "R元.5.1", true},
		// ---- 無効: 元号の単字アルファベット略記だが範囲外・非対応 ----
		{"単字略記 昭和65年は存在しない", "S65.1.1", false},
		{"未対応の単字略記", "X60.1.1", false},
		// ---- 有効: 区切りなし8桁（YYYYMMDD）----
		{"区切りなし8桁", "19850102", true},
		{"区切りなし8桁 西暦2000年代", "20230315", true},
		// ---- 無効: 区切りなし8桁だが暦日が不正 ----
		{"区切りなし8桁 存在しない2月30日", "20230230", false},
		{"区切りなし8桁 月が13", "20231301", false},
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

// validPersonNameFullSplit / validPersonNameSurnameOnly は担当ラベル
// （person-name-high-recall）の Medium/Low パターンをそれぞれ限定する検証器
// （issue #59 段階1）。同一正規表現に対する 2 Pattern 分割で、単独の姓一致
// （渋谷・大和・本田のような地名・企業名と同形の姓）が Medium に一律昇格しない
// ことを固定する回帰テスト。
func TestValidPersonNameFullSplitAndSurnameOnly(t *testing.T) {
	tests := []struct {
		in              string
		wantFullSplit   bool
		wantSurnameOnly bool
	}{
		{"山田太郎", true, false},
		{"山田 太郎", true, false},
		{"渋谷", false, true},
		{"大和", false, true},
		{"本田", false, true},
		{"花子", false, false}, // 単独の名一致（GivenOnly）はどちらのパターンにも含めない
		{"関心", false, false}, // 分割不成立の一般名詞
		{"東大", false, false},
		{"森永", false, true},   // 分割（森+永）は不成立だが、辞書に直接収録された実在の姓（単独一致）
		{"山田錦", false, false}, // denylist（非人名同形語）
		{"営業部", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := validPersonNameFullSplit(tt.in); got != tt.wantFullSplit {
				t.Errorf("validPersonNameFullSplit(%q) = %v, want %v", tt.in, got, tt.wantFullSplit)
			}
			if got := validPersonNameSurnameOnly(tt.in); got != tt.wantSurnameOnly {
				t.Errorf("validPersonNameSurnameOnly(%q) = %v, want %v", tt.in, got, tt.wantSurnameOnly)
			}
		})
	}
}

// validStrictFullName は person-name-structured（クロスライン）と裸の name
// ラベルで使う、姓名辞書検証のうち最も厳しい検証（姓+名の分割かつ名成分 2 文字
// 以上を必須にする。issue #59 段階1）。
func TestValidStrictFullName(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"山田太郎", true},
		{"山田 太郎", true},
		{"越智凪沙", true},
		{"山田", false},  // 単独の姓一致
		{"太郎", false},  // 単独の名一致
		{"渋谷", false},  // 地名・企業名と同形の姓（単独一致）
		{"林 学", false}, // 分割は成立するが名成分が 1 文字
		{"関心", false},  // 分割不成立の一般名詞
		{"山田錦", false}, // denylist（非人名同形語）
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := validStrictFullName(tt.in); got != tt.want {
				t.Errorf("validStrictFullName(%q) = %v, want %v", tt.in, got, tt.want)
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
