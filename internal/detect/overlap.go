package detect

import "sort"

// resolveOverlaps は同一行内で範囲が重なる検出を信頼度順
// （同率なら内部スコア、範囲長、RuleID の辞書順）で集約する。
// 例: クレジットカード 16 桁の先頭 12 桁にマイナンバーのパターンが
// 重なった場合、検証を通った信頼度の高い方だけを残す。
//
// 呼び出し元は fs を同一ファイル・同一行の finding だけに揃えること
// （start/end は行内オフセットのため、異なる行の finding を混ぜると
// 無関係な検出同士を誤って重複解決してしまう）。複数の走査パス
// （単行・隣接行ペア・クロスライン氏名）をまたいで統合したい場合は
// resolveOverlapsPerLine を使う。
func resolveOverlaps(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		// 既存のいずれかが f 以上なら f を捨てる。
		drop := false
		for _, kept := range out {
			if overlaps(f, kept) && !better(f, kept) {
				drop = true
				break
			}
		}
		if drop {
			continue
		}
		// f が勝つ場合は、f と重なる既存をすべて取り除いてから加える。
		keep := out[:0]
		for _, kept := range out {
			if !overlaps(f, kept) {
				keep = append(keep, kept)
			}
		}
		out = append(keep, f)
	}
	return out
}

// resolveOverlapsPerLine は単行走査・隣接行ペア走査・クロスライン氏名走査など、
// 複数のパスから集めた候補をまとめて重複解決する。resolveOverlaps は同一行内の
// finding しか正しく比較できない（start/end が行内オフセットのため）ので、
// File+Line でグループ化してからグループごとに resolveOverlaps を適用する。
// ここでの並べ替えはグループ化のためだけのもので、最終的な順序は呼び出し元の
// dedupAndSortFindings が File・Line・Column で再ソートする。
func resolveOverlapsPerLine(fs []Finding) []Finding {
	if len(fs) < 2 {
		return fs
	}
	sorted := make([]Finding, len(fs))
	copy(sorted, fs)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].File != sorted[j].File {
			return sorted[i].File < sorted[j].File
		}
		return sorted[i].Line < sorted[j].Line
	})

	var out []Finding
	for i := 0; i < len(sorted); {
		j := i + 1
		for j < len(sorted) && sorted[j].File == sorted[i].File && sorted[j].Line == sorted[i].Line {
			j++
		}
		out = append(out, resolveOverlaps(sorted[i:j])...)
		i = j
	}
	return out
}

func overlaps(a, b Finding) bool {
	return a.start < b.end && b.start < a.end
}

// better は a が b より優先されるかを返す。信頼度・内部スコア・範囲の長さが
// 同率の場合は RuleID の辞書順にフォールバックする。Builtin() の定義順（候補スライスへの
// 挿入順）に依存しない決定的なタイブレークにするための措置で、ルール追加順が
// 変わっても重複解決の結果が変わらないようにする。
func better(a, b Finding) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	// --fail-on 判定用に追加収集した候補が、従来から存在する報告・共起昇格
	// 候補と同信頼度で重なっても、報告結果を変えない。
	if a.failOnly != b.failOnly {
		return !a.failOnly
	}
	if comparisonScore(a) != comparisonScore(b) {
		return comparisonScore(a) > comparisonScore(b)
	}
	if (a.end - a.start) != (b.end - b.start) {
		return (a.end - a.start) > (b.end - b.start)
	}
	return a.RuleID < b.RuleID
}
