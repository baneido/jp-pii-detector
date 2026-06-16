package detect

// resolveOverlaps は同一行内で範囲が重なる検出を信頼度順
// （同率なら範囲が長い方、それも同率なら先勝ち）で集約する。
// 例: クレジットカード 16 桁の先頭 12 桁にマイナンバーのパターンが
// 重なった場合、検証を通った信頼度の高い方だけを残す。
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

func overlaps(a, b Finding) bool {
	return a.start < b.end && b.start < a.end
}

func better(a, b Finding) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	return (a.end - a.start) > (b.end - b.start)
}
