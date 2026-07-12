// Package rule は検出ルールの型定義と組み込みルールを提供する。
package rule

import (
	"fmt"
	"regexp"
)

// Confidence は検出結果の信頼度。
type Confidence int

const (
	Low Confidence = iota + 1
	Medium
	High
)

func (c Confidence) String() string {
	switch c {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	}
	return "unknown"
}

// ParseConfidence は文字列を Confidence に変換する。
func ParseConfidence(s string) (Confidence, error) {
	switch s {
	case "low":
		return Low, nil
	case "medium":
		return Medium, nil
	case "high":
		return High, nil
	}
	return 0, fmt.Errorf("invalid confidence %q (low|medium|high)", s)
}

// NegativeContextMode は Pattern が Rule.NegativeContext による棄却判定を
// どのクラスまで適用するかを表す（internal/detect が解釈する）。
type NegativeContextMode int

const (
	// NegativeContextAll はゼロ値（既定）。Rule.NegativeContext の全クラス
	// （汎用窓語・通貨接頭/接尾・カウンタ接尾・採番ラベル接頭、および採番
	// ラベル接頭クラスが 1 語でもあれば働く採番ラベル接尾辞ヒューリスティック）
	// を従来どおり適用する。既存パターンの挙動を変えない後方互換の既定値。
	NegativeContextAll NegativeContextMode = iota
	// NegativeContextAdjacentLabelOnly は、Rule.NegativeContext のうち
	// 採番ラベル接頭クラス（ClassifyNegativeKeyword が
	// NegativeKeywordLabelPrefix と分類する語）の**明示語彙**が値に直接隣接
	// する場合（internal/detect の hasLabelBefore。助詞・コロン・イコールの
	// グルーは許容）だけ棄却する。汎用窓語・通貨・カウンタの各クラスと、
	// 採番ラベル接尾辞ヒューリスティック（hasNumberingSuffixBefore）は
	// 適用しない。後者を適用しない理由: 「お客様番号 090-XXXX-XXXX」の
	// ような正当な電話番号のラベルは「番号」で終わることが多く、接尾辞の
	// 形状だけで判定すると実電話番号まで誤って棄却（FN 化）してしまう。
	// 明示語彙（sku・型番等）への直接隣接に限定すれば、既存の高精度
	// パターンの検出挙動を変えずに既知の誤検出だけを狙い撃ちできる。
	// 同一ルール内で高精度パターンと高偽陽性パターンが混在し、後者にだけ
	// 限定的に負文脈を適用したい場合に使う。
	NegativeContextAdjacentLabelOnly
	// NegativeContextIgnore は Rule.NegativeContext による棄却をこの
	// パターンには一切適用しない（旧 IgnoreNegativeContext: true 相当）。
	NegativeContextIgnore
)

// Pattern は 1 つの正規表現パターン。
// 正規表現にキャプチャグループがある場合、グループ 1 を検出対象とする
// （境界ガード `(?:^|[^0-9])` などをグループ外に置くため）。
type Pattern struct {
	Re *regexp.Regexp
	// Base はパターン単体でマッチした場合の信頼度。
	// コンテキストキーワードが同一行にあれば High に昇格する。
	Base Confidence
	// RequireContext が true の場合、コンテキストキーワードが
	// 同一行に存在しなければ検出を破棄する。
	RequireContext bool
	// RequireContextWindow は、このパターンの RequireContext 判定だけに使う
	// コンテキスト窓。正の値なら Rule.RequireContextWindow を上書きし、0 なら
	// ルール側の値を継承する。同一ルール内の低エントロピーな形式だけを、既存形式
	// より狭い文脈へ限定したい場合に使う。
	RequireContextWindow int
	// NegativeContextMode は Rule.NegativeContext による棄却判定をこの
	// パターンにどう適用するかを表す（既定はゼロ値の NegativeContextAll）。
	// 同一ルール内で既存の高精度パターンと負文脈を必要とする高偽陽性
	// パターンが混在する場合や、汎用の負文脈クラスは誤爆リスクが高いが
	// 明示的な採番ラベルの直接隣接だけは安全に抑制したい場合に使う。
	NegativeContextMode NegativeContextMode
	// Validate はこのパターン固有の追加検証（nil なら検証なし）。
	// ルール全体の Rule.Validate に加えて適用され、パターンごとに
	// 異なる検証（例: 氏名の弱いラベルだけ姓名辞書で照合する）を
	// 行うために使う。引数は正規化済みのマッチ文字列。
	Validate func(match string) bool
	// ValidateLine はマッチの前後を含む正規化済みの行を使うパターン固有の
	// 追加検証（nil なら検証なし）。start/end は行内のバイトオフセットで、
	// キャプチャグループ 1 の半開区間を示す。区切り付きの長いトークンを
	// 部分一致させないなど、マッチ文字列だけでは判定できない場合に使う。
	ValidateLine func(line string, start, end int) bool
}

// Prefilter は行単位の事前判定。正規化済みの行に必要な文字種が
// 含まれない場合、そのルールの正規表現マッチをまるごとスキップする
// （性能最適化）。既定の PrefilterNone は常に走査する安全側の値。
type Prefilter int

const (
	// PrefilterNone は常に走査する（既定）。
	PrefilterNone Prefilter = iota
	// PrefilterDigit は ASCII 数字を含む行のみ走査する。
	// 全角数字は事前判定の前に正規化で半角になっている。
	PrefilterDigit
	// PrefilterAt は '@' を含む行のみ走査する（メールアドレス用）。
	PrefilterAt
	// PrefilterCJK は U+3000 以上の文字（日本語等）を含む行のみ走査する。
	PrefilterCJK
)

// ContextPattern は Context キーワードの単純一致では表現しづらい文脈シグナル
// （銀行名などの固有名詞）を、正規表現で候補を切り出してから辞書照合で検証する
// 仕組み。数百〜千語規模の辞書を Context の線形走査（containsWord）に混ぜて
// ホットパスを劣化させないための専用経路で、Literals による安価な事前ゲートを
// 通過した行だけが正規表現評価に進む。
type ContextPattern struct {
	// Re は候補文字列を切り出す正規表現。キャプチャグループ 1 が候補になる。
	Re *regexp.Regexp
	// Validate は候補が有効な文脈語かどうかを判定する（辞書照合など）。
	Validate func(candidate string) bool
	// ValidateSuffixes は Re が日本語の地の文を候補の前方に取り込む場合に、
	// 候補全体だけでなくルーン境界ごとの接尾部分も長い順に Validate する。
	// 辞書に一致した最長の接尾部分を文脈語として採用する。
	ValidateSuffixes bool
	// Literals はいずれか 1 つも行に含まれなければ Re の評価自体を
	// スキップする安価な事前ゲート（OR 条件）。空なら常に Re を評価する。
	Literals []string
}

// Rule は 1 種類の PII に対応する検出ルール。
type Rule struct {
	ID          string
	Description string
	// Context は信頼度昇格・RequireContext 判定に使う周辺キーワード。
	// 小文字で定義し、ASCII 語は単語境界つき、日本語語は部分一致で評価する。
	Context []string
	// ContextPatterns は辞書照合が必要な文脈シグナル（銀行名等）。Context と
	// 同様に信頼度昇格・RequireContext 判定に使うが、キーワード一致ではなく
	// 正規表現の切り出し＋辞書検証で判定する。
	ContextPatterns []ContextPattern
	// NegativeContext は同一行（または近傍）に存在する場合に検出を
	// 棄却する語。金額・数量・連番 ID など PII でない数字列の文脈を表す。
	// 各語がどの近接判定（値の直前隣接・直後隣接・±window 汎用一致）で
	// 扱われるかは ClassifyNegativeKeyword（negative_context.go）が単一の
	// 情報源として分類する。
	NegativeContext []string
	// RequireContextWindow は RequireContext の肯定語をマッチ前後の
	// ルーン数に限定する。0 の場合は後方互換のため行全体を見る。
	// Base<High（RequireContext ではない）パターンの High 昇格判定にも同じ値を
	// 使うが、そちらは未設定（0）でも行全体には広げず、既定の窓
	// （internal/detect の既定昇格窓 40 ルーン）にフォールバックする。
	// 昇格は検出の成立条件ではなく補助情報のため、無制限に広げると長い 1 行で
	// キーワード 1 個だけで行内の全マッチが昇格してしまうため（#54）。
	RequireContextWindow int
	// Prefilter はパターンがマッチし得ない行を走査前に除外する事前判定。
	// パターンの必須文字種（数字など）を含まない行をスキップする。
	Prefilter Prefilter
	// PrefilterLiterals は、いずれか 1 つも正規化済みの行に含まれなければ
	// このルールの正規表現走査をまるごとスキップするリテラル集合（OR 条件）。
	// 全パターンが特定のラベル語（氏名の「名」「姓」「name」等）を必須とする
	// ルールで、語を含まない大量の行（日本語コメント等）の正規表現評価を
	// 避けるための最適化。空なら無効。ASCII 語は大小文字を区別しない
	// （internal/detect の containsAnyLiteral が判定する。パターン側の
	// `(?i:...)` ラベルに大文字表記が到達できるようにするため）。リテラルは
	// 小文字で定義すること。
	PrefilterLiterals []string
	// Validate はマッチ文字列の追加検証（チェックディジット等）。
	// nil の場合は常に有効。引数は正規化済みのマッチ文字列。
	Validate func(match string) bool
	// Kind は Validate 群を通過した検出値を下位種別に分類する関数
	// （例: jp-phone-number の PhoneKind が返す service/ip/mobile/fixed/
	// international）。nil なら未分類で Finding.Reason.Kind は設定されない。
	// 設定すると internal/detect が検出直後に Reason.Kind へ結果を記録し、
	// 値が設定ファイルの [rules] exclude_kinds（internal/config）に列挙された
	// 種別と一致する場合はその finding を破棄する。検出可否・信頼度そのものには
	// 影響しない補助分類フック。
	Kind     func(match string) string
	Patterns []Pattern
}
