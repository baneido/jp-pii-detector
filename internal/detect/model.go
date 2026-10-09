package detect

import (
	"fmt"

	"github.com/baneido/jp-pii-detector/internal/external"
)

// Model はモデル起点の PII 候補を返す認識器（internal/model.Recognizer が満たす。
// docs/design-ai-detection.md）。候補の座標系は外部レコグナイザのプロトコル v1 と
// 同じ（1 始まりの行・ルーン列・ルーン長）。並行に呼ばれる。
type Model interface {
	Recognize(text string) ([]external.Candidate, error)
}

// SetModel はモデル起点の認識器を設定する。設定すると ScanContent と
// ScanDiffHunk 系が、組み込みルールの検出に加えてモデルの候補を返す。候補は
// 外部レコグナイザの候補と同じ検証（無効化ルール・範囲・ignore マーカー・
// allowlist・min_confidence）を通す。ルール ID は組み込みルールの ID をそのまま
// 使う（設計書 §6.4）ため、外部レコグナイザに課す "-external" 接尾辞は要求しない。
func (d *Detector) SetModel(m Model) {
	d.model = m
}

// ModelError は走査中に起きた最初の推論エラーを返す（無ければ nil）。ScanContent
// はエラーを返せないため、呼び出し側（cmd/jp-pii-detect）が走査後にこれを確かめ、
// 不完全な走査を成功扱いにしない。
func (d *Detector) ModelError() error {
	d.modelMu.Lock()
	defer d.modelMu.Unlock()
	return d.modelErr
}

// modelFindings は text をモデルに読ませ、候補を Finding へ変換する。lines は
// text を "\n" で分割し行末の "\r" を除いたもの。keep が非 nil なら、keep(行番号)
// が true の行に乗る候補だけを残す（diff 走査で追加行だけを報告するため）。
func (d *Detector) modelFindings(file, text string, lines []string, keep func(line int) bool) []Finding {
	if d.model == nil {
		return nil
	}
	cands, err := d.model.Recognize(text)
	if err != nil {
		d.modelMu.Lock()
		if d.modelErr == nil {
			d.modelErr = fmt.Errorf("モデルによる走査に失敗しました（%s）: %w", file, err)
		}
		d.modelMu.Unlock()
		return nil
	}
	var out []Finding
	for _, c := range cands {
		if keep != nil && (c.Line < 1 || c.Line > len(lines) || !keep(c.Line)) {
			continue
		}
		c.File = file
		if f, ok := d.candidateToFinding(file, lines, c, true); ok {
			out = append(out, f)
		}
	}
	return out
}
