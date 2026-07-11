// Package normalize は日本語テキスト特有の表記ゆれを正規化する。
//
// 正規化はルーン単位の 1:1 変換に限定している。これにより正規化後の
// ルーン位置が常に元テキストのルーン位置と一致し、検出位置の逆引きが
// 不要になる。
package normalize

// hyphens は「-」に正規化するハイフン類似文字（数字隣接を問わず無条件に変換する）。
// 全角ハイフンマイナス (U+FF0D) は ASCII オフセット変換で処理される。
// 不可視文字は \u エスケープで明示し、ソース・diff 上で見分けられるようにする。
var hyphens = map[rune]bool{
	'‐':      true, // HYPHEN
	'‑':      true, // NON-BREAKING HYPHEN
	'‒':      true, // FIGURE DASH
	'–':      true, // EN DASH
	'—':      true, // EM DASH
	'―':      true, // HORIZONTAL BAR
	'−':      true, // MINUS SIGN
	'﹣':      true, // SMALL HYPHEN-MINUS
	'\u00AD': true, // SOFT HYPHEN。意味的にハイフンであり、空白ではなく '-' へ
	// 写像する。マイナンバー・電話番号・郵便番号など空白区切りを許さない
	// パターンでも、この写像により不可視ハイフン挿入によるすり抜けを塞げる。
	'⁃': true, // HYPHEN BULLET
	'﹘': true, // SMALL EM DASH
	'⸺': true, // TWO-EM DASH
}

// isProlongedSoundMark は、数字に隣接する場合のみハイフン扱いする長音記号類か
// を返す。単独では片仮名語・人名区切りとして意味を持つため無条件変換はしない
// （波ダッシュ U+301C は意図的に対象外のまま）。要素数が小さく固定のため、
// map ではなく switch で判定する（ハッシュ計算を避け、ホットパスで安い）。
//   - 'ー' KATAKANA-HIRAGANA PROLONGED SOUND MARK
//   - 'ｰ' HALFWIDTH KATAKANA-HIRAGANA PROLONGED SOUND MARK（半角カナ IME 由来の
//     「0X0ｰXXXXｰXXXX」のような携帯電話番号形の区切りを数字隣接時のみ変換する
//     一方、半角カナ語「ﾃﾞｰﾀ」等は隣接判定により保持する）
//   - '゠' KATAKANA-HIRAGANA DOUBLE HYPHEN（無条件変換にはしない。片仮名人名の
//     区切り「アンリ゠ベルクソン」用途があるため、他の長音記号類と同様に
//     数字隣接時のみハイフン扱いする）
func isProlongedSoundMark(r rune) bool {
	switch r {
	case 'ー', 'ｰ', '゠':
		return true
	}
	return false
}

// halfwidthKatakanaStart/End は半角カナブロック（JIS X 0201 カナ）の範囲。
// U+FF61-FF9F はすべて halfwidthKatakanaFold で 1 対 1 に変換できるため、
// 常に変換対象（isConvTarget）とする。
const (
	halfwidthKatakanaStart = 0xFF61
	halfwidthKatakanaEnd   = 0xFF9F
)

// halfwidthKatakanaFold は半角カナ（U+FF61-FF9F）を対応する全角文字へ写像する
// テーブル（インデックス = コードポイント - halfwidthKatakanaStart）。Unicode の
// 互換分解（NFKD）と同じ対応だが、濁点・半濁点（U+FF9E/FF9F）は結合文字
// （U+3099/U+309A）に写像し、直前の仮名と合成しない。NFKC 相当の合成（ｶﾞ 2ルーン
// → ガ 1ルーン）はルーン数を変えてしまい、internal/normalize の 1 ルーン = 1 ルーンの
// 位置不変条件（正規化後の位置が元テキストの位置と一致する）を破るため、意図的に
// 未合成のまま返す。合成が必要な照合（辞書引きなど）は internal/dict.ComposeKana を
// 呼び出し側で使う。
var halfwidthKatakanaFold = [halfwidthKatakanaEnd - halfwidthKatakanaStart + 1]rune{
	'。', '「', '」', '、', '・', // U+FF61-FF65 句読点・中点
	'ヲ',                                         // U+FF66
	'ァ', 'ィ', 'ゥ', 'ェ', 'ォ', 'ャ', 'ュ', 'ョ', 'ッ', // U+FF67-FF6F 小書き
	'ー',                     // U+FF70 半角プロロング記号
	'ア', 'イ', 'ウ', 'エ', 'オ', // U+FF71-FF75
	'カ', 'キ', 'ク', 'ケ', 'コ', // U+FF76-FF7A
	'サ', 'シ', 'ス', 'セ', 'ソ', // U+FF7B-FF7F
	'タ', 'チ', 'ツ', 'テ', 'ト', // U+FF80-FF84
	'ナ', 'ニ', 'ヌ', 'ネ', 'ノ', // U+FF85-FF89
	'ハ', 'ヒ', 'フ', 'ヘ', 'ホ', // U+FF8A-FF8E
	'マ', 'ミ', 'ム', 'メ', 'モ', // U+FF8F-FF93
	'ヤ', 'ユ', 'ヨ', // U+FF94-FF96
	'ラ', 'リ', 'ル', 'レ', 'ロ', // U+FF97-FF9B
	'ワ', 'ン', // U+FF9C-FF9D
	'゙', '゚', // U+FF9E-FF9F 濁点・半濁点（結合文字。未合成）
}

func mapRune(r rune) rune {
	switch {
	case r >= '！' && r <= '～': // 全角 ASCII → 半角
		return r - 0xFEE0
	case r == '　': // 全角スペース
		return ' '
	case hyphens[r]:
		return '-'
	case r >= halfwidthKatakanaStart && r <= halfwidthKatakanaEnd: // 半角カナ → 全角
		return halfwidthKatakanaFold[r-halfwidthKatakanaStart]
	case isSpaceLike(r), isInvisible(r):
		return ' '
	}
	return r
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

// isSpaceLike は半角スペースへ正規化する Unicode 空白類（無条件）かを返す。
// NO-BREAK SPACE (U+00A0)、EN QUAD〜HAIR SPACE (U+2000-U+200A)、
// NARROW NO-BREAK SPACE (U+202F)、MEDIUM MATHEMATICAL SPACE (U+205F) が対象。
// PDF/Office からのコピペで単純な半角/全角スペースの代わりに紛れ込みやすい。
func isSpaceLike(r rune) bool {
	switch r {
	case '\u00A0', '\u202F', '\u205F':
		return true
	}
	return r >= '\u2000' && r <= '\u200A'
}

// isInvisible は半角スペースへ正規化する不可視文字（無条件）かを返す。
// ZERO WIDTH SPACE (U+200B)、WORD JOINER (U+2060)、
// ZERO WIDTH NO-BREAK SPACE / BOM (U+FEFF) が対象。
// これらをスペースへ写像すると、区切りを許さないパターン（メールアドレス等）
// ではトークンが分断されうるが、現状もこれらの文字を含む行は非マッチのため
// 検出精度が悪化することはない。効果があるのは区切り文字として空白を許す
// パターン（クレジットカード番号、+81 表記の電話番号）に限られ、国内電話番号や
// マイナンバーなど空白区切りを許さないパターンへの効果は、空白区切りパターン
// 自体の対応（別issue）が前提になる。
func isInvisible(r rune) bool {
	switch r {
	case '\u200B', '\u2060', '\uFEFF':
		return true
	}
	return false
}

// isConvTarget は mapRune が別の文字へ写像する文字（全角 ASCII・全角スペース・
// ハイフン類・半角カナ・Unicode 空白類・不可視文字）かを返す。長音記号類
// （「ー」「ｰ」「゠」）は数字隣接時のみ変換するため、ここには含めず
// needsConversion 側で隣接判定する（半角プロロング記号 U+FF70 は全角「ー」へ
// 無条件変換したうえで、写像後の値に対して同じ隣接判定を適用する）。
func isConvTarget(r rune) bool {
	// 変換対象の最小コードポイントは U+00A0（NBSP）のため、それ未満（ASCII を
	// 含む大半の文字）は残りの判定をすべて省略できる。ソースコード行の大半を
	// 占める純 ASCII 文字のファストパスを高速化するための早期リターン
	// （hyphens のマップ引きと isSpaceLike/isInvisible の呼び出しを回避する）。
	if r < '\u00A0' {
		return false
	}
	return (r >= '！' && r <= '～') || r == '　' || hyphens[r] || isSpaceLike(r) || isInvisible(r) ||
		(r >= halfwidthKatakanaStart && r <= halfwidthKatakanaEnd)
}

// needsConversion は s に変換対象が 1 つでも含まれるかを 1 パスで判定する
// （割り当てなし）。全角 ASCII・全角スペース・ハイフン類・Unicode 空白類・
// 不可視文字のいずれか、または数字に隣接する長音記号類があれば true。
// 漢字・かな・数字非隣接の長音記号類だけの行（通常の日本語文）は false となり、
// Line のファストパスで元文字列を返せる。
//
// 旧実装は「U+2010 以上の文字があれば変換が要る」と広く判定していたため、
// 漢字・かな（いずれも U+2010 以上）を含むほぼ全ての日本語行が遅いパスへ入り、
// 変換が不要でも []rune を 2 本割り当てていた。今回追加した対象もすべて
// U+00A0 以上のため、純 ASCII 行のファストパスには影響しない。
func needsConversion(s string) bool {
	prev := rune(-1)
	for _, r := range s {
		switch {
		case isConvTarget(r):
			return true
		case isProlongedSoundMark(r) && isDigit(prev):
			return true
		case isDigit(r) && isProlongedSoundMark(prev):
			return true
		}
		prev = r
	}
	return false
}

// Line は 1 行を正規化する。ルーン数は変化しない。
//   - 全角英数字・記号 → 半角
//   - 全角スペース、Unicode 空白類（NBSP 等）→ 半角スペース
//   - ハイフン類似文字（SOFT HYPHEN 含む）→ '-'
//   - 不可視文字（ZERO WIDTH SPACE 等）→ 半角スペース
//   - 長音記号類「ー」「ｰ」「゠」は数字に隣接する場合のみ '-'（カタカナ語・
//     人名区切りとしての用法は保持する）
//   - 半角カナ（U+FF61-FF9F）→ 対応する全角カナ・句読点（濁点・半濁点は
//     結合文字 U+3099/U+309A のまま。1 ルーン = 1 ルーンを保つため合成しない）
func Line(s string) string {
	// 変換対象を厳密に判定する。対象がなければ（純 ASCII でも、変換対象を
	// 含まない通常の日本語文でも）割り当てなしで元文字列をそのまま返す。
	if !needsConversion(s) {
		return s
	}
	// 変換が必要な場合のみ []rune を 1 回だけ確保し、その場で書き換える。
	// 入力用と出力用に 2 本のルーン列を持たない（割り当てを 2→1 に削減）。
	rs := []rune(s)
	for i, r := range rs {
		rs[i] = mapRune(r)
	}
	// 長音記号類の数字隣接判定は写像後の値で行う。mapRune は長音記号類を
	// 変えないため写像後も位置・値はそのまま残り、全角数字は既に半角化済みである。
	//
	// 連続する長音記号類（例:「1ーーー2」）は、この前方 in-place 走査により
	// 内側の要素が変換済みの隣接値（'-'）を見て非数字と判定され、両端だけが
	// '-' になり内側は「ー」のまま残る（「1ーーー2」→「1-ー-2」）。連鎖全体を
	// 変換してもマイナンバー等の固定桁数パターンはどのみち数字境界ガード
	// （dg()）でマッチしないため、検出上の意味を持たない仕様として固定する
	// （normalize_test.go 参照）。
	for i, r := range rs {
		if !isProlongedSoundMark(r) {
			continue
		}
		prevDigit := i > 0 && isDigit(rs[i-1])
		nextDigit := i+1 < len(rs) && isDigit(rs[i+1])
		if prevDigit || nextDigit {
			rs[i] = '-'
		}
	}
	return string(rs)
}
