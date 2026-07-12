// Package detect は行単位の PII 検出エンジンを提供する。
package detect

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/normalize"
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// IgnoreMarker を含む行は検出対象から除外される（意図的なダミー値向け）。
const IgnoreMarker = "jp-pii-detector:ignore"

// AllowMarker は後方互換のために残している旧除外マーカー。
const AllowMarker = "pii-allow"

// maxAdjacentLineGap は隣接行相関（ScanContent の 2 行ウィンドウ・ScanDiffHunk の
// 文脈行相関・scanCrossLineNames・hasCrossLineNegativeContext）で許容する論理隣接の
// 最大行差。空白のみの行を最大 2 行まで挟んでも「論理的に隣接」とみなす
// （j-i<=3。j-i=1 は空行なしの物理隣接、2〜3 は空行 1〜2 行を挟むケース）。
const maxAdjacentLineGap = 3

// crossLinePromotionWindow は隣接行相関で非 RequireContext ルールを昇格させる際に
// 使う、値のマッチ位置からのルーン窓。digitRuleRequireContextWindow
// （internal/rule/builtin.go）と同じ 40 を採用し、遠く離れたラベルによる
// 誤昇格を抑える。
const crossLinePromotionWindow = 40

// defaultPromotionContextWindow は RequireContextWindow 未設定のルールで
// Base 信頼度を High へ昇格させる際に使う既定のコンテキスト探索半径（ルーン数）。
// 昇格判定はこの半径に制限し、長い行の遠方にある無関係な 1 語だけで行全体の
// マッチが昇格するのを防ぐ（issue #68 段階1(b)）。RequireContext 判定
// （検出可否そのもの）はここでは変えず、ウィンドウ未設定なら従来通り行全体を
// 見る（後方互換）。単一行走査での既定値であり、隣接行相関の昇格には
// crossLinePromotionWindow を使う（scanLineNoIgnore の promotionWindow 引数）。
const defaultPromotionContextWindow = 40

// nextNonBlankIndex は lines[i] より後ろで最初の非空白行（strings.TrimSpace が
// 空でない行）のインデックスを返す。i からの行差が maxGap を超える前に見つから
// なければ -1（間の行がすべて空白のときだけ論理的に隣接とみなすため、非空白行が
// 見つかった時点で探索を打ち切る＝それより先の行との「隣接」は別途その行を
// 起点に評価される）。
func nextNonBlankIndex(lines []string, i, maxGap int) int {
	for j := i + 1; j < len(lines) && j-i <= maxGap; j++ {
		if strings.TrimSpace(lines[j]) != "" {
			return j
		}
	}
	return -1
}

// prevNonBlankIndex は nextNonBlankIndex の逆方向版（lines[i] より前で最初の
// 非空白行）。
func prevNonBlankIndex(lines []string, i, maxGap int) int {
	for j := i - 1; j >= 0 && i-j <= maxGap; j-- {
		if strings.TrimSpace(lines[j]) != "" {
			return j
		}
	}
	return -1
}

// Finding は 1 件の検出結果。
//
// 注意: この型は出力スキーマではない。機械可読な出力（json/sarif 等）は
// internal/report の jsonFinding を経由し、値は既定でマスクされる。Finding を
// 直接 json.Marshal する経路は存在しないが、誤って marshal しても生の PII を
// 漏らさないよう、生値を保持する Match は json:"-" でシリアライズ対象から外す。
type Finding struct {
	RuleID      string          `json:"rule_id"`
	Description string          `json:"description"`
	File        string          `json:"file"`
	Line        int             `json:"line"`   // 1 始まり
	Column      int             `json:"column"` // 1 始まり（ルーン単位）
	Match       string          `json:"-"`      // 元テキスト（生値。マスクは出力層で行う。直接 marshal では出さない）
	Confidence  rule.Confidence `json:"-"`
	// Reason は検出の根拠（調査・チューニング用。既定の出力には含めない）。
	Reason DetectReason `json:"reason,omitempty"`
	// Offset/EndOffset は走査対象テキスト全体の先頭からのルーン単位の半開区間
	// [Offset, EndOffset)。ComputeOffsets を呼んだときのみ設定され、その場合
	// HasOffset が true になる。行・列ベースの位置を文字オフセットへ変換したい
	// 利用側（例: Microsoft Presidio の RecognizerResult）向けの情報で、
	// 単一テキスト走査でのみ意味を持つ（ファイル/差分走査では付与されない）。
	HasOffset bool `json:"-"`
	Offset    int  `json:"-"`
	EndOffset int  `json:"-"`
	// span（ルーン単位、重複解決用）
	start, end int
	// matchStart/matchEnd はパターン全体（境界ガード込み、キャプチャグループ
	// より広いことがある）のルーン単位の半開区間。start/end（キャプチャ
	// グループ＝報告対象）とは別に持ち、scanAdjacentLines /
	// scanAdjacentLinesDiff で person-name のパターン全体が結合用の改行を
	// 越えたかを判定する際に使う。person-name は専用の scanCrossLineNames が
	// 同じ値を person-name-structured として検出するため、この越境候補だけを
	// 対象外にする。jp-birthdate のようにラベル埋め込み正規表現でクロスライン
	// 検出するルールには、この越境情報を理由とした一律抑制を適用しない。
	matchStart, matchEnd int
	// ignoreNegativeContext はマッチしたパターンが Rule.NegativeContext の
	// 適用対象外であることを表す。隣接行の負文脈フィルタにも引き継ぐ。
	ignoreNegativeContext bool
}

// Format は fmt の全verbで生の Match と文脈詳細を出さない。テスト失敗時の
// `%+v` やログ出力を、json:"-" では防げないための安全境界。
func (f Finding) Format(s fmt.State, _ rune) {
	fmt.Fprintf(s, "{RuleID:%q File:%q Line:%d Column:%d Confidence:%s Match:<redacted>}",
		f.RuleID, f.File, f.Line, f.Column, f.Confidence)
}

// DetectReason は検出の根拠を表す。生の PII は含めない。
type DetectReason struct {
	BaseConfidence  string   `json:"base_confidence,omitempty"`
	FinalConfidence string   `json:"final_confidence,omitempty"`
	ContextKeywords []string `json:"context_keywords,omitempty"`
	ContextPromoted bool     `json:"context_promoted,omitempty"`
	RequireContext  bool     `json:"require_context,omitempty"`
	ContextWindow   int      `json:"context_window,omitempty"`
	Validated       bool     `json:"validated,omitempty"`
	// CooccurrenceBoosted は、[rules] cooccurrence_boost 有効時に近傍の別カテゴリ
	// 高信頼 PII との共起で信頼度が 1 段昇格したことを示す（調査・チューニング用）。
	CooccurrenceBoosted bool `json:"cooccurrence_boosted,omitempty"`
	// PathDemoted はテスト経路（testdata/ 等）の信頼度降格が適用されたかを表す
	// （internal/detect/path_profile.go）。true の場合、Confidence は既に
	// 降格後の値（Low）になっている。
	PathDemoted bool `json:"path_demoted,omitempty"`
	// Kind はルール固有の下位種別（Rule.Kind が設定されている場合のみ設定される。
	// internal/rule/rule.go 参照）。現状は jp-phone-number の PhoneKind が返す
	// service/ip/mobile/fixed/international のいずれか。設定ファイルの
	// [rules] exclude_kinds（internal/config）でこの値ごとに検出を除外できる。
	Kind string `json:"kind,omitempty"`
}

// Detector は設定を適用済みの検出エンジン。
type Detector struct {
	rules   []rule.Rule
	cfg     *config.Config
	minConf rule.Confidence
	// normStopwords は正規化済みの stopword（マッチ文字列は常に正規化済みのため）。
	normStopwords []string
	// ctxTokens は ASCII コンテキスト語をあらかじめ識別子トークン列に分割した
	// キャッシュ（キーワードは静的なので行ごとに再分割しないため）。
	ctxTokens map[string][]string
	// crossLineName は person-name-structured ルール（有効時のみ非 nil）。構造化・
	// 複数行の氏名検出を ScanContent で行うかの判定と、検出結果の ID・説明の
	// 単一の出所として使う。高再現率モードでのみ有効になる。
	crossLineName *rule.Rule
	// cooccurrenceBoost は [rules] cooccurrence_boost の opt-in フラグ。
	// ScanContent のみで使う（ScanLine/ScanDiffHunk の既定挙動は変えない）。
	cooccurrenceBoost bool
	// collectDropped 以下は棄却候補記録（DroppedCandidate、--explain-dropped
	// 用）の opt-in 状態。既定 false で、無効時は各記録箇所の bool 分岐 1 個
	// 以外のコストがない（詳細は dropped.go）。droppedMu は internal/source の
	// 並列フルスキャンで同一 Detector の ScanContent が複数ゴルーチンから
	// 呼ばれても dropped への追記が安全になるよう保護する（collectDropped が
	// false の間は一切使わない）。
	collectDropped   bool
	droppedMu        sync.Mutex
	dropped          []DroppedCandidate
	droppedTruncated bool
}

// New は設定に基づいて Detector を構築する。
func New(cfg *config.Config) (*Detector, error) {
	minConf, err := rule.ParseConfidence(cfg.MinConfidence)
	if err != nil {
		return nil, err
	}
	disabled := map[string]bool{}
	for _, id := range cfg.Rules.Disabled {
		disabled[id] = true
	}
	var rules []rule.Rule
	var crossLineName *rule.Rule
	for _, r := range rule.Builtin() {
		if !disabled[r.ID] {
			rules = append(rules, r)
			if r.ID == "person-name-structured" {
				cr := r
				crossLineName = &cr
			}
		}
	}
	for _, r := range cfg.CustomRules() {
		if !disabled[r.ID] {
			rules = append(rules, r)
		}
	}
	normStopwords := make([]string, len(cfg.Allowlist.Stopwords))
	for i, sw := range cfg.Allowlist.Stopwords {
		normStopwords[i] = normalize.Line(sw)
	}
	// ASCII コンテキスト語のトークン分割はキーワードが静的なため一度だけ行う。
	ctxTokens := map[string][]string{}
	for _, r := range rules {
		for _, kw := range r.Context {
			if asciiOnly(kw) {
				if _, ok := ctxTokens[kw]; !ok {
					ctxTokens[kw] = tokenizeIdentifiers(kw)
				}
			}
		}
		for _, kw := range r.NegativeContext {
			if asciiOnly(kw) {
				if _, ok := ctxTokens[kw]; !ok {
					ctxTokens[kw] = tokenizeIdentifiers(kw)
				}
			}
		}
	}
	return &Detector{
		rules:             rules,
		cfg:               cfg,
		minConf:           minConf,
		normStopwords:     normStopwords,
		ctxTokens:         ctxTokens,
		crossLineName:     crossLineName,
		cooccurrenceBoost: cfg.Rules.CooccurrenceBoost,
	}, nil
}

// Rules は有効なルール一覧を返す。
func (d *Detector) Rules() []rule.Rule { return d.rules }

// ScanContent はファイル内容全体を行に分割して走査する。
func (d *Detector) ScanContent(file, content string) []Finding {
	var lines []string
	for line := range strings.SplitSeq(content, "\n") {
		lines = append(lines, strings.TrimSuffix(line, "\r"))
	}
	lineContexts := sourceLineContexts(file, lines)

	// cooccurrence_boost が有効なときだけ、minConf 未満でも昇格候補となりうる
	// Low 候補（Validated またはコンテキスト有りの cooccurrenceBoostRuleIDs）を
	// 保持する。retainBudget は本呼び出し（1 ファイル分の ScanContent）専用の
	// ローカル変数で、ゴルーチン間共有はしない（internal/source の並列走査は
	// ファイル単位でこの関数を呼ぶだけなので新たな共有可変状態にはならない）。
	var retainBudget *int
	if d.cooccurrenceBoost {
		budget := maxCooccurrenceRetainedCandidates
		retainBudget = &budget
	}

	var candidates []Finding
	for i, line := range lines {
		candidates = append(candidates, d.scanLineWithContext(file, i+1, line, lineContexts[i], retainBudget)...)
	}
	// 論理的に隣接する（間が空白のみの行に限り最大 maxAdjacentLineGap 行差までの）
	// 行ペアを走査する。
	for i := range lines {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		j := nextNonBlankIndex(lines, i, maxAdjacentLineGap)
		if j < 0 {
			continue
		}
		candidates = append(candidates, d.scanAdjacentLines(file, i+1, lines[i], j+1, lines[j], lineContexts[i], lineContexts[j])...)
	}
	if d.crossLineName != nil {
		candidates = append(candidates, d.scanCrossLineNames(file, lines)...)
		candidates = append(candidates, d.scanCrossLineSurnameGivenPairs(file, lines)...)
		if sourceKindForPath(file) == sourceKindCSV {
			candidates = append(candidates, d.scanCSVNameColumns(file, lines)...)
		}
	}

	// 隣接行の負コンテキスト（金額・数量・連番 ID 等）で抑制される候補は、
	// cooccurrence_boost のアンカーにも昇格対象にも使わない。
	filtered := candidates[:0]
	for _, f := range candidates {
		if d.hasCrossLineNegativeContext(f, lines, lineContexts, f.Line-1) {
			d.recordDropped(f.RuleID, f.File, f.Line, f.Column, DropReasonCrossLineNegativeContext, f.Confidence)
			continue
		}
		filtered = append(filtered, f)
	}
	candidates = filtered

	if d.cooccurrenceBoost {
		candidates = d.applyCooccurrenceBoost(candidates)
	}

	// Confidence < minConf のふるい落としをここでも行う（cooccurrence_boost 無効時は
	// scanLineNoIgnoreWithContext 内で既に minConf 未満が除かれているため無害な
	// 二重チェック。有効時は、昇格しなかった保持済み Low 候補をここで最終的に除く）。
	filtered = candidates[:0]
	for _, f := range candidates {
		if f.Confidence < d.minConf {
			d.recordDropped(f.RuleID, f.File, f.Line, f.Column, DropReasonBelowMinConfidence, f.Confidence)
			continue
		}
		filtered = append(filtered, f)
	}

	// テスト経路（testdata/ 等）の Medium 系検出は Finding 確定後・重複解決前に
	// 降格する（path_profile.go）。降格であって除外ではないため、allowlist /
	// jp-pii-detector:ignore とは独立に働く。重複解決 (resolveOverlapsPerLine)
	// より先に適用し、降格後の信頼度で重複解決の勝敗判定が行われるようにする
	// （降格された finding が誤って他の重複候補より優先されないようにするため）。
	demoted := d.applyPathDemotion(filtered)

	// 単行・隣接行ペア・クロスライン氏名の各パスは独立に候補を出すため、
	// パスをまたいで同一箇所に重なる finding（例: 12 桁の数字が
	// jp-my-number と jp-drivers-license の両方の候補になるケース）が
	// 残ることがある。File+Line でグループ化した上で resolveOverlaps を
	// 再適用し、パスをまたいだ重複を統合する。共起昇格とパス降格の適用後の
	// 信頼度を重複解決のタイブレークに反映させる。
	resolved := resolveOverlapsPerLine(demoted)
	d.recordOverlapLosses(demoted, resolved)
	return dedupAndSortFindings(resolved)
}

// maxCooccurrenceRetainedCandidates は cooccurrence_boost 有効時に、minConf 未満でも
// 昇格候補として保持する Low 候補の上限（1 ファイルあたり）。氏名系ルールの
// PrefilterLiterals は既に大半の行を除外するが、「name:」等のラベル語が大量に並ぶ
// 病的なファイルでもメモリ・処理時間が線形を超えて悪化しないための安全弁。
const maxCooccurrenceRetainedCandidates = 2000

// cooccurrenceWindowLines は共起昇格を判定する際の前後行数（ウィンドウ半径）。
// 増幅リスク（真の PII が近傍のボーダー FP を道連れに昇格させる）を抑えるため、
// 意図的に狭く取る。
const cooccurrenceWindowLines = 5

// cooccurrenceBoostRuleIDs は共起昇格の対象となる氏名系ルール。
// Low / Medium 候補を 1 段だけ昇格する（P23 のスコープ）。
// person-name-structured はクロスライン検出専用で常に Medium 固定のため対象外。
var cooccurrenceBoostRuleIDs = map[string]bool{
	"person-name":             true,
	"person-name-high-recall": true,
}

// cooccurrenceAnchorRuleIDs は昇格の根拠として使う、他カテゴリの PII ルール。
// 昇格対象（氏名系）とは必ず別カテゴリになるよう cooccurrenceBoostRuleIDs とは
// 重複させない。住所（jp-address / jp-address-high-recall）・銀行口座番号・
// 健康保険番号・生年月日は、根拠に足るチェックサム検証も RequireContext による
// ラベル必須化も無い（住所）か Base が Medium 止まり（口座・保険・生年月日）で、
// 試合スコアや日付を住所と誤検出するような境界事例を道連れに昇格させるリスクが
// 相対的に高いため、現時点では対象に含めない（住所誤検出対策が先行してから
// 再検討する）。
var cooccurrenceAnchorRuleIDs = map[string]bool{
	"jp-my-number":       true,
	"jp-phone-number":    true,
	"jp-postal-code":     true,
	"email-address":      true,
	"credit-card":        true,
	"jp-drivers-license": true,
	"jp-passport":        true,
	"jp-pension-number":  true,
	"jp-residence-card":  true,
}

// applyCooccurrenceBoost は、cooccurrenceBoostRuleIDs の候補（Validated または
// ContextKeywords 有り）を、同一ファイル内の ±cooccurrenceWindowLines 行以内に
// cooccurrenceAnchorRuleIDs の高信頼（High かつ Validated または RequireContext）
// 候補があるときだけ 1 段昇格（Low→Medium、Medium→High）させる。
func (d *Detector) applyCooccurrenceBoost(candidates []Finding) []Finding {
	var anchorLines []int
	for _, f := range candidates {
		if isCooccurrenceAnchor(f) {
			anchorLines = append(anchorLines, f.Line)
		}
	}
	if len(anchorLines) == 0 {
		return candidates
	}
	sort.Ints(anchorLines)

	for i := range candidates {
		f := &candidates[i]
		if !cooccurrenceBoostRuleIDs[f.RuleID] || f.Confidence >= rule.High {
			continue
		}
		if !(f.Reason.Validated || len(f.Reason.ContextKeywords) > 0) {
			continue
		}
		if !hasNearbyAnchorLine(anchorLines, f.Line, cooccurrenceWindowLines) {
			continue
		}
		f.Confidence++
		f.Reason.CooccurrenceBoosted = true
		f.Reason.FinalConfidence = f.Confidence.String()
	}
	return candidates
}

func isCooccurrenceAnchor(f Finding) bool {
	return cooccurrenceAnchorRuleIDs[f.RuleID] && f.Confidence >= rule.High &&
		(f.Reason.Validated || f.Reason.RequireContext)
}

// hasNearbyAnchorLine は sorted な anchorLines に、line から window 行以内の
// 要素があるかを二分探索で判定する（O(log n)。全候補×全アンカーの O(n^2) を避ける）。
func hasNearbyAnchorLine(anchorLines []int, line, window int) bool {
	lo, hi := line-window, line+window
	idx := sort.SearchInts(anchorLines, lo)
	return idx < len(anchorLines) && anchorLines[idx] <= hi
}

// ComputeOffsets は ScanContent に渡したのと同一の content を使い、各 finding に
// テキスト全体の先頭からのルーン単位オフセット（半開区間 [Offset, EndOffset)）を
// 付与して返す。行・列ベースの検出位置を文字オフセットベースへ変換したい利用側
// （例: Microsoft Presidio の RecognizerResult は文字オフセットを要求する）向けの
// ヘルパー。
//
// content は ScanContent と同じく "\n" 区切りで行に分割されるため、ここで求める
// 行頭のルーン位置は ScanContent が見た行と一致する。正規化は 1 ルーン = 1 ルーンの
// 1:1 変換なので、列はそのまま行頭からのルーン数として使える。
func ComputeOffsets(content string, findings []Finding) []Finding {
	starts := lineStartRuneOffsets(content)
	for i := range findings {
		f := &findings[i]
		idx := f.Line - 1
		// 行・列の境界を対称に防御する（Column は通常 1 始まりだが、Column<1 だと
		// Offset が負になり [Offset,EndOffset) 不変条件を破るため弾く）。
		if idx < 0 || idx >= len(starts) || f.Column < 1 {
			continue
		}
		f.Offset = starts[idx] + (f.Column - 1)
		f.EndOffset = f.Offset + utf8.RuneCountInString(f.Match)
		f.HasOffset = true
	}
	return findings
}

// lineStartRuneOffsets は content の各行（"\n" 区切り、1 始まり）の先頭が、
// テキスト全体の先頭から何ルーン目に当たるかを返す。戻り値の index i は (i+1) 行目の
// 行頭オフセット。CRLF の場合も \r は行内のルーンとして数えられるため、行内の列は
// そのまま行頭オフセットに加算できる（\r は行末側にあり、検出値より後ろにある）。
func lineStartRuneOffsets(content string) []int {
	starts := []int{0}
	runes := 0
	for _, r := range content {
		runes++
		if r == '\n' {
			starts = append(starts, runes)
		}
	}
	return starts
}

// dedupAndSortFindings は候補から重複を除き、ファイル・行・列・終端で安定ソートする。
// 同一キー（ルール・ファイル・行・span）の候補が複数ある場合は信頼度の高い方を残す。
// findingKey は信頼度を含まないため、先勝ちのままだと隣接行相関による昇格結果
// （High）が、先に追加された未昇格の同一 finding（Medium/Low、標準の単一行走査由来）に
// 負けて捨てられてしまう（min_confidence=medium 運用で顕在化する）。
func dedupAndSortFindings(candidates []Finding) []Finding {
	index := map[string]int{}
	var findings []Finding
	for _, f := range candidates {
		key := findingKey(f)
		if i, ok := index[key]; ok {
			if f.Confidence > findings[i].Confidence {
				findings[i] = f
			}
			continue
		}
		index[key] = len(findings)
		findings = append(findings, f)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		if findings[i].Column != findings[j].Column {
			return findings[i].Column < findings[j].Column
		}
		return findings[i].end < findings[j].end
	})
	return findings
}

// DiffLine は差分 hunk の 1 行（新ファイル側）。Added が true なら追加行、
// false なら文脈行（未変更行）。
type DiffLine struct {
	Text  string
	Added bool
}

// ScanDiffHunk は差分 hunk（文脈行＋追加行）を走査し、検出値が追加行に乗る
// finding だけを返す（行番号はウィンドウ内 1 始まり）。
//
// 設計意図: 文脈行（未変更行）は正のコンテキスト（ラベル等）の補完にのみ使い、
// 抑制（ignore マーカー・負コンテキスト）の駆動には使わない。これにより、
// 追加した値の隣の既存行に「円」等の負コンテキストや古い jp-pii-detector:ignore が
// あっても、追加行の新規 PII を取りこぼさない（セキュリティ検出器として偽陰性を避ける）。
// 同一行の抑制（値そのものの行）は通常どおり適用される。一方、追加行同士が隣接する
// 場合（両方 Added）は、フルスキャン（ScanContent）と同じく隣接行の負コンテキストを
// 適用する。そうしないと、同じ 2 行の追加が CI のフルスキャンでは抑制され
// pre-commit --staged では報告されるという非対称が生まれるため。
//
// この「抑制は検出値が乗る行に対してのみ適用し、隣接行のマーカーを巻き添えに
// しない」という原則は diff 経路専用ではなく、ScanContent 側の隣接行走査
// （scanAdjacentLines）にも同様に適用される。
func (d *Detector) ScanDiffHunk(file string, lines []DiffLine) []Finding {
	texts := make([]string, len(lines))
	added := make([]bool, len(lines))
	for i, l := range lines {
		texts[i] = l.Text
		added[i] = l.Added
	}
	lineContexts := sourceLineContextsForDiff(file, texts, added)

	var candidates []Finding
	// 追加行は単独走査（同一行コンテキスト・同一行抑制が正しく適用される）。
	// cooccurrence_boost は ScanContent（フルスキャン）専用のため retainBudget は
	// 常に nil を渡す（diff hunk は文脈行を昇格の根拠にしない設計を維持する）。
	for i, line := range texts {
		if added[i] {
			candidates = append(candidates, d.scanLineWithContext(file, i+1, line, lineContexts[i], nil)...)
		}
	}
	// 論理的に隣接する行ペアを文脈行ラベルで昇格させる（間は空白のみ・最大
	// maxAdjacentLineGap 行差まで）。抑制は値の行（追加行）基準。
	for i := range texts {
		if strings.TrimSpace(texts[i]) == "" {
			continue
		}
		j := nextNonBlankIndex(texts, i, maxAdjacentLineGap)
		if j < 0 {
			continue
		}
		candidates = append(candidates,
			d.scanAdjacentLinesDiff(file, i+1, texts[i], j+1, texts[j], added[i], added[j], lineContexts[i], lineContexts[j])...)
	}

	// 文脈行由来の cross-line 負コンテキストは適用しない（上記の設計意図）。
	// 非追加行を空文字にマスクした行スライスを使うことで、
	// hasCrossLineNegativeContext の ±1 行参照が文脈行の負コンテキストを
	// 拾わないようにしつつ、追加行同士の負コンテキストは通常どおり適用する。
	maskedTexts := make([]string, len(texts))
	for i, t := range texts {
		if added[i] {
			maskedTexts[i] = t
		}
	}
	filtered := candidates[:0]
	for _, f := range candidates {
		if d.hasCrossLineNegativeContext(f, maskedTexts, lineContexts, f.Line-1) {
			d.recordDropped(f.RuleID, f.File, f.Line, f.Column, DropReasonCrossLineNegativeContext, f.Confidence)
			continue
		}
		filtered = append(filtered, f)
	}
	// テスト経路の Medium 系検出降格は ScanContent と同様、重複解決より先に
	// 適用する（降格後の信頼度で重複解決の勝敗判定が行われるようにするため）。
	demoted := d.applyPathDemotion(filtered)

	// ScanContent と同様、単行パスと隣接行ペアパスをまたいだ重複を統合する
	// （cross-line names は diff 走査では実行されないため対象は 2 系統のみ）。
	resolved := resolveOverlapsPerLine(demoted)
	d.recordOverlapLosses(demoted, resolved)
	return dedupAndSortFindings(resolved)
}

func findingKey(f Finding) string {
	return f.RuleID + "\x00" + f.File + "\x00" + itoa(f.Line) + "\x00" + itoa(f.start) + "\x00" + itoa(f.end)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// scanAdjacentLines は論理的に隣接する 2 行（firstLineNo・secondLineNo。間に
// 空白のみの行を最大 maxAdjacentLineGap 行差まで挟んでもよい）を結合して走査する。
// RequireContext ルールはラベル・値がどちらの行にあってもコンテキストが成立し、
// 非 RequireContext ルールも値の位置から crossLinePromotionWindow ルーン以内に
// ラベルがあれば High へ昇格する（遠距離ラベルによる誤昇格は窓で抑える）。
//
// ignore マーカーは結合文字列ではなく値が乗る行ごとに判定する（scanLineNoIgnore を
// 使い ScanLine の全体判定を経由しない）ため、ラベル側だけの marker が値側の
// 検出を消さない（scanAdjacentLinesDiff と対称）。
func (d *Detector) scanAdjacentLines(file string, firstLineNo int, first string, secondLineNo int, second string, firstCtx, secondCtx lineContext) []Finding {
	combined := first + "\n" + second
	firstRunes := []rune(first)
	secondRunes := []rune(second)
	sep := len(firstRunes)

	var out []Finding
	for _, f := range d.scanLineNoIgnore(file, firstLineNo, combined, crossLinePromotionWindow) {
		switch {
		case f.end <= sep: // 値は 1 行目
			// person-name は専用の scanCrossLineNames と重複する越境候補だけを
			// 対象外にする。他ルールのラベル埋め込み cross-line match は維持する。
			if f.RuleID == "person-name" && f.matchEnd > sep+1 {
				continue
			}
			if ignoredLine(first) {
				continue
			}
			f.Line = firstLineNo
			f.Column = f.start + 1
			f.Match = string(firstRunes[f.start:f.end])
			if d.hasSourceNegativeForFinding(f, first, firstCtx) {
				continue
			}
		case f.start > sep: // 値は 2 行目
			if f.RuleID == "person-name" && f.matchStart < sep {
				continue
			}
			if ignoredLine(second) {
				continue
			}
			start := f.start - sep - 1
			end := f.end - sep - 1
			if start < 0 || end > len(secondRunes) {
				continue
			}
			if ignoredLine(second) {
				continue
			}
			f.Line = secondLineNo
			f.Column = start + 1
			f.Match = string(secondRunes[start:end])
			f.start, f.end = start, end
			if d.hasSourceNegativeForFinding(f, second, secondCtx) {
				continue
			}
		default:
			continue
		}
		out = append(out, f)
	}
	return out
}

// scanCrossLineNames はフォーム・設定ファイルで氏名のラベルと値が別の行に
// 分かれて現れるケース（例: `氏名:` の次行に `山田太郎`）を検出する。同一行
// 前提の person-name ルールでは取りこぼすため、ScanContent から隣接行ごとに
// 呼ぶ。person-name-structured（高再現率）が有効なときだけ実行され、eval が使う
// ScanLine 経路は通らないため評価指標には影響しない。
//
// 値は CrossLineNameValueRe で取り出し、ValidCrossLineName（姓名辞書照合・
// プレースホルダ/組織名棄却）で検証する。同一行の強いラベルより厳しく辞書照合を
// 必須にするのは、クロスラインの「次行＝値」前提が同一行ほど強くないため。
func (d *Detector) scanCrossLineNames(file string, lines []string) []Finding {
	if rule.Medium < d.minConf {
		return nil
	}
	var out []Finding
	for i := range lines {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		j := nextNonBlankIndex(lines, i, maxAdjacentLineGap)
		if j < 0 {
			continue
		}
		label, value := lines[i], lines[j]
		// ラベル行・値行はそれぞれ「ラベルと区切りだけ」「氏名だけ」をアンカー付きで
		// 要求するため、行末コメント（jp-pii-detector:ignore を含む）が付くと正規表現が
		// マッチせず自然に抑制される。明示的な ignore マーカー判定は不要。
		if !rule.CrossLineNameLabelRe.MatchString(normalize.Line(label)) {
			continue
		}
		normValue := normalize.Line(value)
		m := rule.CrossLineNameValueRe.FindStringSubmatchIndex(normValue)
		if m == nil || m[2] < 0 {
			continue
		}
		entity := normValue[m[2]:m[3]]
		if !rule.ValidCrossLineName(entity) || d.allowlisted(entity) {
			continue
		}
		// 正規化は 1:1（ルーン数保存）のため、norm 上のルーン位置は元行と一致する。
		rs := len([]rune(normValue[:m[2]]))
		re := rs + len([]rune(entity))
		origRunes := []rune(value)
		out = append(out, Finding{
			RuleID:      d.crossLineName.ID,
			Description: d.crossLineName.Description,
			File:        file,
			Line:        j + 1,
			Column:      rs + 1,
			Match:       string(origRunes[rs:re]),
			Confidence:  rule.Medium,
			Reason: DetectReason{
				BaseConfidence:  rule.Medium.String(),
				FinalConfidence: rule.Medium.String(),
				Validated:       true,
			},
			start: rs,
			end:   re,
		})
	}
	return out
}

// scanAdjacentLinesDiff は scanAdjacentLines の差分版。検出値が追加行に乗る
// finding だけを残す（RequireContext・非 RequireContext のいずれも対象。
// 非 RequireContext ルールは crossLinePromotionWindow ルーン以内のラベルでのみ
// 昇格する）。文脈行の ignore マーカーでは抑制せず（scanLineNoIgnore を使う）、
// 抑制判定は値が乗る行（必ず追加行）に対してのみ行う。
func (d *Detector) scanAdjacentLinesDiff(file string, firstLineNo int, first string, secondLineNo int, second string, firstAdded, secondAdded bool, firstCtx, secondCtx lineContext) []Finding {
	if !firstAdded && !secondAdded {
		return nil
	}
	combined := first + "\n" + second
	firstRunes := []rune(first)
	secondRunes := []rune(second)
	sep := len(firstRunes)

	var out []Finding
	for _, f := range d.scanLineNoIgnore(file, firstLineNo, combined, crossLinePromotionWindow) {
		switch {
		case f.end <= sep: // 値は 1 行目
			// scanAdjacentLines と同じく person-name の越境候補だけを抑制する。
			if f.RuleID == "person-name" && f.matchEnd > sep+1 {
				continue
			}
			if !firstAdded || ignoredLine(first) {
				continue
			}
			f.Line = firstLineNo
			f.Column = f.start + 1
			f.Match = string(firstRunes[f.start:f.end])
			if d.hasSourceNegativeForFinding(f, first, firstCtx) {
				continue
			}
		case f.start > sep: // 値は 2 行目
			if f.RuleID == "person-name" && f.matchStart < sep {
				continue
			}
			if !secondAdded || ignoredLine(second) {
				continue
			}
			start := f.start - sep - 1
			end := f.end - sep - 1
			if start < 0 || end > len(secondRunes) {
				continue
			}
			f.Line = secondLineNo
			f.Column = start + 1
			f.Match = string(secondRunes[start:end])
			f.start, f.end = start, end
			if d.hasSourceNegativeForFinding(f, second, secondCtx) {
				continue
			}
		default:
			continue
		}
		out = append(out, f)
	}
	return out
}

func (d *Detector) hasSourceNegativeForFinding(f Finding, line string, lineCtx lineContext) bool {
	if f.ignoreNegativeContext || len(lineCtx.Statements) == 0 || !d.ruleHasNegativeContext(f.RuleID) {
		return false
	}
	norm := normalize.Line(line)
	start, ok := runeOffsetToByteOffset(norm, f.start)
	if !ok {
		return false
	}
	end, ok := runeOffsetToByteOffset(norm, f.end)
	if !ok {
		return false
	}
	st := lineCtx.statementFor(start, end)
	return st != nil && st.NegativeText != ""
}

func (d *Detector) ruleHasNegativeContext(ruleID string) bool {
	for _, r := range d.rules {
		if r.ID == ruleID {
			return len(r.NegativeContext) > 0
		}
	}
	return false
}

func runeOffsetToByteOffset(s string, target int) (int, bool) {
	if target < 0 {
		return 0, false
	}
	idx := 0
	for pos := range s {
		if idx == target {
			return pos, true
		}
		idx++
	}
	if idx == target {
		return len(s), true
	}
	return 0, false
}

// ScanLine は 1 行を走査する。lineNo は 1 始まり。
func (d *Detector) ScanLine(file string, lineNo int, line string) []Finding {
	if line == "" || ignoredLine(line) {
		return nil
	}
	return d.scanLineNoIgnore(file, lineNo, line, 0)
}

// scanLineWithContext は ScanContent の行単位走査の本体。retainBudget が非 nil
// なら cooccurrence_boost 用に、minConf 未満でも昇格候補（Validated または
// コンテキスト有りの cooccurrenceBoostRuleIDs）を一時的に保持する
// （ScanContent 専用の保持モード。ScanLine/ScanDiffHunk の経路は常に nil を渡し
// 既存挙動を変えない）。
func (d *Detector) scanLineWithContext(file string, lineNo int, line string, lineCtx lineContext, retainBudget *int) []Finding {
	if line == "" || ignoredLine(line) {
		return nil
	}
	return d.scanLineNoIgnoreWithContext(file, lineNo, line, lineCtx, 0, retainBudget)
}

// scanLineNoIgnore は ScanLine の本体（ignore マーカー判定を除く）。差分・
// ScanContent の隣接行走査では、文脈行に残った ignore マーカーで隣接行の値を
// 抑制しないよう、この経路を使って結合文字列を走査する。promotionWindow は
// 非 RequireContext ルールを文脈語で昇格させる際に使うルーン窓（0 なら
// defaultPromotionContextWindow、隣接行相関では crossLinePromotionWindow）。
// cooccurrence_boost 用の候補保持は行わない。
func (d *Detector) scanLineNoIgnore(file string, lineNo int, line string, promotionWindow int) []Finding {
	return d.scanLineNoIgnoreWithContext(file, lineNo, line, lineContext{}, promotionWindow, nil)
}

// scanLineNoIgnoreWithContext が本体。retainBudget が非 nil かつ残数 > 0 の場合のみ、
// minConf 未満の cooccurrenceBoostRuleIDs 候補（Validated またはコンテキスト有り）を
// 保持する（呼び出し元でその後 applyCooccurrenceBoost → 最終 minConf フィルタを適用する
// 前提。ScanLine/ScanDiffHunk からの呼び出しは retainBudget=nil のため従来どおり
// minConf 未満は即座に破棄する）。promotionWindow は非 RequireContext ルールの
// 昇格窓で、0 以下なら defaultPromotionContextWindow に解決する。
func (d *Detector) scanLineNoIgnoreWithContext(file string, lineNo int, line string, lineCtx lineContext, promotionWindow int, retainBudget *int) []Finding {
	if line == "" {
		return nil
	}
	norm := normalize.Line(line)
	hasDigit, hasAt, hasCJK := classifyLine(norm)

	// コンテキスト判定・元行のルーン展開はコストが高いため、
	// 必要になるまで遅延させる（大半の行はどのパターンにもマッチしない）。
	var normRunes []rune
	var origRunes []rune

	var found []Finding
	for _, r := range d.rules {
		// 必須文字種を含まない行はパターンマッチ自体をスキップする。
		// 大半のルールは数字必須のため、数字のないコード行がほぼ無コストになる。
		switch r.Prefilter {
		case rule.PrefilterDigit:
			if !hasDigit {
				continue
			}
		case rule.PrefilterAt:
			if !hasAt {
				continue
			}
		case rule.PrefilterCJK:
			if !hasCJK {
				continue
			}
		}
		// リテラルプレフィルタ: ラベル語を 1 つも含まない行は、このルールの
		// 正規表現走査をまるごとスキップする（氏名ルールのホットパス最適化）。
		if len(r.PrefilterLiterals) > 0 && !containsAnyLiteral(norm, r.PrefilterLiterals) {
			continue
		}
		// ctxForMatch は window>0 のときだけマッチ前後 window ルーンに限定して
		// コンテキスト語を探し、window<=0 なら行全体を見る。呼び出し側が窓を
		// 使い分ける: RequireContext 判定（検出可否そのもの）には
		// r.RequireContextWindow を渡し、未設定（0）なら後方互換のため行全体を
		// 見る。Base 信頼度の昇格判定には promotionWindow を渡すが、これは常に
		// 呼び出し側で 0 以下なら defaultPromotionContextWindow に解決してから
		// 渡す（issue #68 段階1(b)。無制限昇格による FP 増幅を防ぐ）ため、ここでは
		// 単純に window>0 かどうかだけを見ればよい。ContextPatterns（銀行名辞書等の
		// アンカー正規表現＋辞書検証経路）も同じ探索対象文字列 hay に対して評価する。
		ctxForMatch := func(start, end int, window int) []string {
			var hay string
			if window > 0 {
				hay = contextWindow(norm, start, end, window, &normRunes)
			} else {
				hay = norm
			}
			kws := d.matchingContexts(hay, r.Context)
			if len(r.ContextPatterns) > 0 {
				kws = append(kws, matchContextPatterns(hay, r.ContextPatterns)...)
			}
			if st := lineCtx.statementFor(start, end); st != nil && st.PositiveText != "" {
				kws = append(kws, d.matchingContexts(st.PositiveText, r.Context)...)
				if len(r.ContextPatterns) > 0 {
					kws = append(kws, matchContextPatterns(st.PositiveText, r.ContextPatterns)...)
				}
			}
			return kws
		}
		hasNegativeNear := func(start, end int) bool {
			if len(r.NegativeContext) == 0 {
				return false
			}
			st := lineCtx.statementFor(start, end)
			if st != nil && st.NegativeText != "" {
				return true
			}
			if d.statementHasCleanPositiveLabel(st, r.Context) {
				// 同一文に（負文脈語を伴わない）このルール自身の正ラベルが
				// 明示されている場合は、離れた場所の一般的な負文脈語（金額単位・
				// 件数等）で誤って棄却しない（正ラベル優先。issue #68 段階1(a)）。
				return false
			}
			return d.hasNegativeContextNear(norm, start, end, negativeContextWindowRunes, &normRunes, r.NegativeContext)
		}
		for _, p := range r.Patterns {
			// FindAll はマッチ全体（末尾の境界ガード文字を含む）の直後から
			// 次を探すため、`090-…-2222,090-…-4444` のように区切りが 1 文字
			// だけの隣接エンティティを取りこぼす。キャプチャ終端から再検索
			// することで、境界文字を次のマッチの先頭ガードとして再利用する。
			// 再検索スライスは常にエンティティ直後の境界文字（非数字等）から
			// 始まるため、`^` がエンティティ途中で誤マッチすることはない。
			for pos := 0; pos < len(norm); {
				m := p.Re.FindStringSubmatchIndex(norm[pos:])
				if m == nil {
					break
				}
				fullStart, fullEnd := m[0]+pos, m[1]+pos
				start, end := fullStart, fullEnd
				if len(m) >= 4 && m[2] >= 0 {
					start, end = m[2]+pos, m[3]+pos
				}
				next := end
				if next <= pos {
					next = pos + 1 // 空マッチ対策（通常は到達しない）
				}
				pos = next
				entity := norm[start:end]
				if insideUUIDv4Token(norm, start, end) {
					if d.collectDropped {
						d.recordDroppedMatch(r.ID, file, lineNo, norm, start, DropReasonUUIDToken, p.Base)
					}
					continue
				}
				reason := DetectReason{
					BaseConfidence: p.Base.String(),
					RequireContext: p.RequireContext,
					ContextWindow:  r.RequireContextWindow,
				}
				if p.RequireContext {
					kws := ctxForMatch(start, end, r.RequireContextWindow)
					if len(kws) == 0 {
						if d.collectDropped {
							d.recordDroppedMatch(r.ID, file, lineNo, norm, start, DropReasonRequireContextMissing, p.Base)
						}
						continue
					}
					reason.ContextKeywords = kws
				}
				if !p.IgnoreNegativeContext && hasNegativeNear(start, end) {
					if d.collectDropped {
						d.recordDroppedMatch(r.ID, file, lineNo, norm, start, DropReasonNegativeContext, p.Base)
					}
					continue
				}
				if r.Validate != nil {
					if !r.Validate(entity) {
						if d.collectDropped {
							d.recordDroppedMatch(r.ID, file, lineNo, norm, start, DropReasonValidateFailed, p.Base)
						}
						continue
					}
					reason.Validated = true
				}
				if p.Validate != nil {
					if !p.Validate(entity) {
						if d.collectDropped {
							d.recordDroppedMatch(r.ID, file, lineNo, norm, start, DropReasonValidateFailed, p.Base)
						}
						continue
					}
					reason.Validated = true
				}
				if p.ValidateLine != nil {
					if !p.ValidateLine(norm, start, end) {
						if d.collectDropped {
							d.recordDroppedMatch(r.ID, file, lineNo, norm, start, DropReasonValidateLineFailed, p.Base)
						}
						continue
					}
					reason.Validated = true
				}
				if d.allowlisted(entity) {
					if d.collectDropped {
						d.recordDroppedMatch(r.ID, file, lineNo, norm, start, DropReasonAllowlisted, p.Base)
					}
					continue
				}
				// r.Kind は Validate 群通過後に確定した検出値へ適用する下位種別
				// 分類（例: jp-phone-number の PhoneKind）。Reason.Kind への記録は
				// 常に行うが、その種別が設定ファイルの [rules] exclude_kinds に
				// 含まれる場合は、信頼度や minConf の判定を待たずにここで
				// finding を破棄する。既定の exclude_kinds は空のため、
				// これまでの検出結果は変わらない。
				if r.Kind != nil {
					reason.Kind = r.Kind(entity)
					if slices.Contains(d.cfg.Rules.ExcludeKinds, reason.Kind) {
						if d.collectDropped {
							d.recordDroppedMatch(r.ID, file, lineNo, norm, start, DropReasonKindExcluded, p.Base)
						}
						continue
					}
				}
				// RequireContext のパターンはキーワードの存在が検出の前提
				// であり昇格の根拠にならないため、Base の信頼度のまま報告する
				// （口座番号などの△ルールが常に high になるのを防ぐ）。
				conf := p.Base
				if !p.RequireContext && conf < rule.High {
					// promotionWindow<=0（通常の単一行走査）なら
					// defaultPromotionContextWindow に解決する。隣接行相関から
					// 渡される crossLinePromotionWindow はそのまま使う。
					window := promotionWindow
					if window <= 0 {
						window = defaultPromotionContextWindow
					}
					kws := ctxForMatch(start, end, window)
					if len(kws) > 0 {
						reason.ContextKeywords = kws
						reason.ContextPromoted = true
						reason.ContextWindow = window
						conf = rule.High
					}
				}
				if conf < d.minConf && !retainForCooccurrenceBoost(retainBudget, r.ID, reason) {
					if d.collectDropped {
						d.recordDroppedMatch(r.ID, file, lineNo, norm, start, DropReasonBelowMinConfidence, conf)
					}
					continue
				}
				reason.FinalConfidence = conf.String()
				// バイトオフセット → ルーン位置（正規化は 1:1 なので元行と一致）
				rs := len([]rune(norm[:start]))
				re := rs + len([]rune(entity))
				// パターン全体（境界ガード込み）のルーン位置も併せて記録する
				// （scanAdjacentLines 等の越境判定用。詳細は Finding.matchStart
				// のコメントを参照）。
				mrs := len([]rune(norm[:fullStart]))
				mre := len([]rune(norm[:fullEnd]))
				if origRunes == nil {
					origRunes = []rune(line)
				}
				found = append(found, Finding{
					RuleID:                r.ID,
					Description:           r.Description,
					File:                  file,
					Line:                  lineNo,
					Column:                rs + 1,
					Match:                 string(origRunes[rs:re]),
					Confidence:            conf,
					Reason:                reason,
					start:                 rs,
					end:                   re,
					matchStart:            mrs,
					matchEnd:              mre,
					ignoreNegativeContext: p.IgnoreNegativeContext,
				})
			}
		}
	}
	resolved := resolveOverlaps(found)
	d.recordOverlapLosses(found, resolved)
	return resolved
}

// retainForCooccurrenceBoost は minConf 未満の候補を、cooccurrence_boost の
// 昇格判定用に一時保持してよいかを返す。対象は cooccurrenceBoostRuleIDs に
// 限定し、かつ Validated またはコンテキスト有りの候補のみ（プレースホルダ等を
// 除いた notPlaceholderName 通過済みの氏名候補が主だが、無条件の Low 氏名候補を
// すべて保持するとメモリ・性能に影響するため、シグナルのない候補は従来どおり
// 破棄する）。保持するたびに retainBudget を消費し、上限（maxCooccurrenceRetainedCandidates）
// に達したら以降は従来どおり破棄する。
func retainForCooccurrenceBoost(retainBudget *int, ruleID string, reason DetectReason) bool {
	if retainBudget == nil || *retainBudget <= 0 {
		return false
	}
	if !cooccurrenceBoostRuleIDs[ruleID] {
		return false
	}
	if !reason.Validated && len(reason.ContextKeywords) == 0 {
		return false
	}
	*retainBudget--
	return true
}

func ignoredLine(line string) bool {
	return containsMarkerToken(line, IgnoreMarker) || containsMarkerToken(line, AllowMarker)
}

// containsMarkerToken は line 内に marker がトークン境界付き（`\b`相当）で
// 出現するかを返す。単純な strings.Contains による部分文字列一致だと、旧
// マーカー pii-allow が pii-allowlist のような無関係な識別子・ファイル名にも
// 一致し、行全体が意図せず不可視化されてしまう。マーカーの直前・直後の文字が
// マーカートークンの継続文字（英数字・ハイフン・アンダースコア）でない場合の
// みマッチとみなすことで、独立した「単語」としてのみ照合する。
func containsMarkerToken(line, marker string) bool {
	for idx := 0; ; {
		pos := strings.Index(line[idx:], marker)
		if pos < 0 {
			return false
		}
		start := idx + pos
		end := start + len(marker)
		before := true
		if start > 0 {
			r, _ := utf8.DecodeLastRuneInString(line[:start])
			before = !isMarkerTokenChar(r)
		}
		after := true
		if end < len(line) {
			r, _ := utf8.DecodeRuneInString(line[end:])
			after = !isMarkerTokenChar(r)
		}
		if before && after {
			return true
		}
		// 境界に失敗した候補の次の文字から再探索する（marker 自体を
		// スキップしすぎて後続の正しい出現を見逃さないよう 1 文字だけ進める）。
		idx = start + 1
	}
}

// isMarkerTokenChar はマーカートークンの継続文字（英数字・ハイフン・
// アンダースコア）かどうかを返す。
func isMarkerTokenChar(r rune) bool {
	return r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// containsAnyLiteral は haystack に literals のいずれかが含まれるかを返す
// （リテラルプレフィルタ用。OR 条件）。ASCII 大文字小文字は無視する。氏名ルールの
// ASCII 強ラベル・裸の name ラベルが `(?i:...)` 化された（#48）ため、プレフィルタ側
// も大文字小文字を無視しないと FULL_NAME: 等の行が正規表現に到達する前にスキップ
// されてしまう。大半の行（正規化済みでも ASCII 大文字を含まない行）では最初の
// ループで決着し、小文字化コピーを確保しない。
func containsAnyLiteral(haystack string, literals []string) bool {
	for _, lit := range literals {
		if strings.Contains(haystack, lit) {
			return true
		}
	}
	if !hasASCIIUpper(haystack) {
		return false
	}
	lower := strings.ToLower(haystack)
	for _, lit := range literals {
		if strings.Contains(lower, lit) {
			return true
		}
	}
	return false
}

// hasASCIIUpper は s に ASCII 大文字が 1 つでも含まれるかを返す。マルチバイト
// UTF-8 の継続バイトは常に 0x80 以上のため、バイト単位の走査でも安全に判定できる。
func hasASCIIUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

// classifyLine は Prefilter 判定に使う文字種の有無を 1 パスで調べる。
func classifyLine(s string) (hasDigit, hasAt, hasCJK bool) {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '@':
			hasAt = true
		case r >= 0x3000: // CJK 記号・かな・漢字はすべて U+3000 以上
			hasCJK = true
		}
		if hasDigit && hasAt && hasCJK {
			break
		}
	}
	return
}

// insideUUIDv4Token は検出候補 [start,end) が UUIDv4 トークンの内部に
// 完全に含まれるかを返す。UUID は PII ではないため、内部の数字列や
// 英数字列を郵便番号・口座番号などとして部分一致させない。
func insideUUIDv4Token(s string, start, end int) bool {
	if start < 0 || end < start || end > len(s) {
		return false
	}
	left, right := start, end
	for left > 0 && isUUIDTokenByte(s[left-1]) {
		left--
	}
	for right < len(s) && isUUIDTokenByte(s[right]) {
		right++
	}
	token := s[left:right]
	return isHyphenatedUUIDv4(token) || isCompactUUIDv4(token)
}

func isHyphenatedUUIDv4(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHexByte(s[i]) {
				return false
			}
		}
	}
	return s[14] == '4' && isUUIDVariantByte(s[19])
}

func isCompactUUIDv4(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return s[12] == '4' && isUUIDVariantByte(s[16])
}

func isUUIDTokenByte(c byte) bool {
	return c == '-' || isHexByte(c)
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}

func isUUIDVariantByte(c byte) bool {
	return c == '8' || c == '9' || c == 'a' || c == 'A' || c == 'b' || c == 'B'
}

// allowlisted は entity（正規化済みのマッチ文字列）が除外対象かを返す。
func (d *Detector) allowlisted(entity string) bool {
	for i, sw := range d.cfg.Allowlist.Stopwords {
		if entity == sw || entity == d.normStopwords[i] {
			return true
		}
	}
	for _, re := range d.cfg.AllowRegexes() {
		if re.MatchString(entity) {
			return true
		}
	}
	return false
}
