package detect

import (
	"github.com/baneido/jp-pii-detector/internal/rule"
)

// DroppedCandidate は検出候補が確定に至らず棄却された記録（opt-in、FN 分析用。
// issue #43 段階4）。生のマッチ値は絶対に保持しない（Finding.Match の
// json:"-" と同じ安全境界の思想。値はマスク済みですら持たない。位置と
// ルールで特定するには十分という判断）。
type DroppedCandidate struct {
	RuleID string
	File   string
	Line   int // 1 始まり
	Column int // 1 始まり（ルーン単位）
	// Reason は棄却理由。下記 DropReasonXxx 定数のいずれか（固定語彙）。
	Reason string
	// PatternBase はこの候補が仮に採用されていた場合の信頼度。パターン
	// ループ内の棄却は Pattern.Base、below-min-confidence・overlap-lost・
	// path-demotion-below-min・cross-line-negative-context は棄却時点で
	// 解決済みの Finding.Confidence を使う。FN 分析での優先度付けに使う
	// 補助情報であり、検出可否・出力には一切影響しない。
	PatternBase rule.Confidence
}

// 棄却理由の語彙（この文字列で固定。--explain-dropped の text/json 出力に
// そのまま現れる安定した識別子のため、値を変更しないこと）。
const (
	// DropReasonRequireContextMissing は RequireContext のパターンで、
	// 近傍にコンテキストキーワードが無く破棄されたことを表す。
	DropReasonRequireContextMissing = "require-context-missing"
	// DropReasonNegativeContext は同一行（source context 由来を含む）の
	// 負文脈で破棄されたことを表す。
	DropReasonNegativeContext = "negative-context"
	// DropReasonCrossLineNegativeContext は論理隣接行の負文脈
	// （hasCrossLineNegativeContext、ScanContent/ScanDiffHunk 経由）で
	// 破棄されたことを表す。
	DropReasonCrossLineNegativeContext = "cross-line-negative-context"
	// DropReasonValidateFailed は Rule.Validate または Pattern.Validate が
	// false を返して破棄されたことを表す（チェックサム等）。
	DropReasonValidateFailed = "validate-failed"
	// DropReasonValidateLineFailed は Pattern.ValidateLine が false を
	// 返して破棄されたことを表す。
	DropReasonValidateLineFailed = "validate-line-failed"
	// DropReasonAllowlisted は allowlist（stopword / 正規表現）に一致して
	// 破棄されたことを表す。
	DropReasonAllowlisted = "allowlisted"
	// DropReasonKindExcluded は Rule.Kind の下位種別が設定ファイルの
	// [rules] exclude_kinds に一致して破棄されたことを表す。
	DropReasonKindExcluded = "kind-excluded"
	// DropReasonBelowMinConfidence は最終信頼度が min_confidence 未満で
	// 破棄されたことを表す。cooccurrence_boost で一旦保持に回った候補が
	// 結局昇格しなかった場合の最終的な破棄もここに含む
	// （保持に回った時点そのものは記録しない）。
	DropReasonBelowMinConfidence = "below-min-confidence"
	// DropReasonOverlapLost は resolveOverlaps/resolveOverlapsPerLine の
	// 重複解決で他候補に敗れて破棄されたことを表す。
	DropReasonOverlapLost = "overlap-lost"
	// DropReasonPathDemotionBelowMin はテスト経路の信頼度降格
	// （path_profile.go）で Low に落ち、min_confidence 未満になって
	// 破棄されたことを表す。
	DropReasonPathDemotionBelowMin = "path-demotion-below-min"
	// DropReasonUUIDToken は候補が UUIDv4 トークンの内部に完全に含まれる
	// ため破棄されたことを表す。
	DropReasonUUIDToken = "uuid-token"
)

// maxDroppedCandidates は collectDropped 有効時に、TakeDropped で回収する
// までの間に累積する DroppedCandidate 件数の上限。巨大リポジトリのフル
// スキャン等、病的に大きな入力でも無制限にメモリを消費しないための安全弁。
// 超過分は黙って捨てず droppedTruncated を立てる（DroppedTruncated 参照）。
const maxDroppedCandidates = 1000

// CollectDropped は棄却候補の記録（DroppedCandidate）を有効/無効にする
// （既定 false）。無効時は記録のコストが各記録箇所の bool 分岐 1 個のみで、
// 性能・挙動・出力は従来と完全に不変（golden 等への影響ゼロ）。
// --explain-dropped 用。並列フルスキャン開始前（Detector 構築直後）に
// 呼ぶことを想定する。
func (d *Detector) CollectDropped(enabled bool) {
	d.collectDropped = enabled
}

// TakeDropped は記録済みの DroppedCandidate を返し、内部の蓄積をクリアする
// （drain 方式）。ScanContent/ScanLine/ScanDiffHunk を必要な回数呼び出した
// 後にまとめて回収する想定（フルスキャンで複数ファイルを走査する場合も、
// 全走査完了後に 1 度だけ呼べばよい）。CollectDropped(false)（既定）の
// ままなら常に nil を返す。
func (d *Detector) TakeDropped() []DroppedCandidate {
	d.droppedMu.Lock()
	defer d.droppedMu.Unlock()
	out := d.dropped
	d.dropped = nil
	return out
}

// DroppedTruncated は直近の TakeDropped 以降、上限（maxDroppedCandidates）に
// 達して記録を打ち切ったことがあるかを返し、内部フラグをリセットする
// （TakeDropped と対で、1 回の走査ごとに呼ぶ想定）。
func (d *Detector) DroppedTruncated() bool {
	d.droppedMu.Lock()
	defer d.droppedMu.Unlock()
	t := d.droppedTruncated
	d.droppedTruncated = false
	return t
}

// recordDropped は collectDropped が有効なときだけ棄却候補を記録する
// （無効時はこの関数を呼んでもコストは bool 分岐 1 個のみ）。
// internal/source の並列フルスキャンでは同一 Detector の ScanContent が
// 複数ゴルーチンから呼ばれるため、mutex で dropped への追記を保護する。
func (d *Detector) recordDropped(ruleID, file string, line, column int, reason string, base rule.Confidence) {
	if !d.collectDropped {
		return
	}
	d.droppedMu.Lock()
	defer d.droppedMu.Unlock()
	if len(d.dropped) >= maxDroppedCandidates {
		d.droppedTruncated = true
		return
	}
	d.dropped = append(d.dropped, DroppedCandidate{
		RuleID:      ruleID,
		File:        file,
		Line:        line,
		Column:      column,
		Reason:      reason,
		PatternBase: base,
	})
}

// recordDroppedMatch は scanLineNoIgnoreWithContext のパターンマッチループ
// 専用ヘルパー。正規化済み行 norm 内のバイトオフセット byteStart をルーン
// 列番号へ変換してから recordDropped する。呼び出し側で d.collectDropped を
// 確認してから呼ぶこと（ここでは確認しない。無効時にルーン変換のコストを
// 発生させないため、ホットパスの呼び出し箇所ごとに `if d.collectDropped`
// で包む規約にしている）。
//
// lineNo・norm の座標系は呼び出し元がそのまま渡したものを使う。
// scanAdjacentLines/scanAdjacentLinesDiff が結合する論理隣接行ペアの走査中
// （lineNo は先頭行、norm は 2 行を "\n" で結合した仮想テキスト）に記録
// された場合、値が 2 行目に乗る候補の列番号は結合テキスト上の位置になり、
// 実際の物理行の列に再マップされない（生存した finding の位置には影響
// しない、opt-in の FN 分析専用の既知の制限）。
func (d *Detector) recordDroppedMatch(ruleID, file string, lineNo int, norm string, byteStart int, reason string, base rule.Confidence) {
	column := len([]rune(norm[:byteStart])) + 1
	d.recordDropped(ruleID, file, lineNo, column, reason, base)
}

// recordOverlapLosses は resolveOverlaps・resolveOverlapsPerLine 呼び出し
// 前後の候補集合を比較し、重複解決で負けた（出力に残らなかった）候補を
// overlap-lost として記録する。resolveOverlaps 自体のシグネチャは変更しない
// （detect_test.go 内の既存の直接呼び出しとの互換を保つため）。
// findingKey（RuleID+File+Line+start+end）が同一になりうる候補（例:
// 同一スパンの完全な重複）も多重集合として扱い、正しく差分を取る。
func (d *Detector) recordOverlapLosses(before, after []Finding) {
	if !d.collectDropped {
		return
	}
	remaining := make(map[string]int, len(after))
	for _, f := range after {
		remaining[findingKey(f)]++
	}
	for _, f := range before {
		key := findingKey(f)
		if remaining[key] > 0 {
			remaining[key]--
			continue
		}
		d.recordDropped(f.RuleID, f.File, f.Line, f.Column, DropReasonOverlapLost, f.Confidence)
	}
}
