package detect

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/baneido/jp-pii-detector/internal/rule"
)

const (
	minConfidenceScore = 0
	maxConfidenceScore = 100

	mediumScoreThreshold = 40
	highScoreThreshold   = 75
)

// confidenceScoreEvidence は既存の検出成立条件を通過した候補にだけ付与する
// 補助証拠。負文脈・検証失敗・allowlist 等の棄却理由は従来どおり先に hard drop
// し、点数で復活させない。
type confidenceScoreEvidence struct {
	contextDistance      int
	contextDistanceKnown bool
	crossLineContext     bool
	structuredContext    bool
	patternBoundContext  bool
	structuredPair       bool
	sameRecordBoost      bool
}

// confidenceFromScore は内部スコアを既存の 3 値 Confidence に写像する唯一の
// しきい値定義。段階導入中は finalizeFindingScore が既存 Confidence の帯域内へ
// clamp するため、min_confidence や JSON/SARIF の公開挙動は変わらない。
func confidenceFromScore(score int) rule.Confidence {
	switch {
	case score >= highScoreThreshold:
		return rule.High
	case score >= mediumScoreThreshold:
		return rule.Medium
	default:
		return rule.Low
	}
}

func baseConfidenceScore(conf rule.Confidence) int {
	switch conf {
	case rule.High:
		return 80
	case rule.Medium:
		return 50
	default:
		return 20
	}
}

func confidenceScoreBounds(conf rule.Confidence) (int, int) {
	switch conf {
	case rule.High:
		return highScoreThreshold, maxConfidenceScore
	case rule.Medium:
		return mediumScoreThreshold, highScoreThreshold - 1
	default:
		return minConfidenceScore, mediumScoreThreshold - 1
	}
}

// finalizeFindingScore は既存 Confidence を互換性境界として、検証・文脈距離・
// 構造証拠を加算したスコアを確定する。スコアは必ず元の Confidence 帯に収め、
// 固定しきい値で再写像しても同じ Confidence になることを保証する。
func finalizeFindingScore(f *Finding) {
	score := baseConfidenceScore(f.Confidence)
	// high-recall 専用ルールは標準ルールより広い候補集合を拾うため、同一
	// Confidence・同一スパンでは標準ルールの帰属を維持する弱い prior を置く。
	// private-eval-v2 の全3プロファイルで、これが無い場合は jp-address の TP が
	// jp-address-high-recall へ移るだけの意図しないルール帰属ドリフトを確認した。
	if strings.HasSuffix(f.RuleID, "-high-recall") {
		score -= 20
	}
	if f.Reason.Validated {
		score += 5
	}
	if len(f.Reason.ContextKeywords) > 0 {
		switch {
		case f.scoreEvidence.structuredContext:
			score += 8
		case f.scoreEvidence.crossLineContext:
			score += 2
		case f.scoreEvidence.contextDistanceKnown && f.scoreEvidence.contextDistance <= 8:
			score += 6
		case f.scoreEvidence.contextDistanceKnown && f.scoreEvidence.contextDistance <= defaultPromotionContextWindow:
			score += 4
		default:
			score += 1
		}
	}
	if f.Reason.RequireContext {
		score += 2
	}
	if f.scoreEvidence.structuredPair {
		score += 8
	}
	if f.scoreEvidence.patternBoundContext {
		score += 8
	}
	if f.Reason.CooccurrenceBoosted {
		if f.scoreEvidence.sameRecordBoost {
			score += 7
		} else {
			score += 2
		}
	}

	lo, hi := confidenceScoreBounds(f.Confidence)
	if score < lo {
		score = lo
	}
	if score > hi {
		score = hi
	}
	f.ConfidenceScore = score
	f.Confidence = confidenceFromScore(score)
}

// comparisonScore は手組みの Finding で ConfidenceScore が未設定でも
// 従来の Confidence 相当の安定した値を返す。
func comparisonScore(f Finding) int {
	if f.ConfidenceScore != 0 {
		return f.ConfidenceScore
	}
	return baseConfidenceScore(f.Confidence)
}

// contextScoreEvidenceForMatch はマッチと肯定文脈語の最短距離を求める。距離は
// ルーン数、同一 statement/CSV 列/SQL 列など位置を持たない構造文脈は
// structured=true として別の強い証拠にする。
func contextScoreEvidenceForMatch(line string, start, end int, keywords []string, structured bool) confidenceScoreEvidence {
	ev := confidenceScoreEvidence{structuredContext: structured}
	lineRunes := []rune(line)
	startRune := utf8.RuneCountInString(line[:start])
	endRune := startRune + utf8.RuneCountInString(line[start:end])
	for _, keyword := range keywords {
		needle := []rune(keyword)
		if len(needle) == 0 {
			continue
		}
		for ks := 0; ks+len(needle) <= len(lineRunes); ks++ {
			matched := true
			for j := range needle {
				if unicode.ToLower(lineRunes[ks+j]) != unicode.ToLower(needle[j]) {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
			ke := ks + len(needle)
			distance := runeSpanDistance(startRune, endRune, ks, ke)
			if !ev.contextDistanceKnown || distance < ev.contextDistance {
				ev.contextDistance = distance
				ev.contextDistanceKnown = true
				ev.crossLineContext = runeSpansCrossLine(lineRunes, startRune, endRune, ks, ke)
			}
		}
	}
	return ev
}

func runeSpanDistance(aStart, aEnd, bStart, bEnd int) int {
	switch {
	case bEnd <= aStart:
		return aStart - bEnd
	case aEnd <= bStart:
		return bStart - aEnd
	default:
		return 0
	}
}

func runeSpansCrossLine(s []rune, aStart, aEnd, bStart, bEnd int) bool {
	lo, hi := aEnd, bStart
	if bEnd <= aStart {
		lo, hi = bEnd, aStart
	}
	if lo < 0 || hi < lo || hi > len(s) {
		return false
	}
	return strings.Contains(string(s[lo:hi]), "\n")
}
