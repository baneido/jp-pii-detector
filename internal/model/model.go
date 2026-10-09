// Package model は、ローカルで動く日本語のトークン分類モデル（Sumi:
// ModernBERT-Ja-130M を PII 抽出用に微調整したもの）で PII の候補区間を挙げる
// 認識器を提供する（docs/design-ai-detection.md の「モデル起点」）。
//
// このパッケージの責務は「テキスト → 候補（ルール ID・行・ルーン列・長さ・確信度）」
// までで、ignore マーカー・allowlist・min_confidence・重複解決は呼び出し側の
// internal/detect が、外部レコグナイザの候補と同じ経路で行う。
//
// 推論（ONNX Runtime の呼び出し）は cgo が必要なため ort.go に分け、
// `-tags ort` かつ cgo 有効のビルドでだけ組み込む。それ以外のビルドでは Open が
// エラーを返す（ort_stub.go）。窓の分割・ラベルのデコード・確認器は純 Go で、
// 推論関数を差し替えてテストできる。
package model

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/external"
)

// 学習時の最大入力長は 256 トークン（Sumi の train_report.json）。<s> と </s> の
// 2 つを除いた本文トークン数の上限。
const maxWindowTokens = 254

// bosID / eosID は ModernBERT-Ja の <s> / </s>（tokenizer.json の post_processor）。
const (
	bosID = 1
	eosID = 2
)

// spanThreshold 未満の確率のスパンは候補にしない。highProb 以上を high、mediumProb
// 以上を medium、それ未満を low とする。
//
// ponytail: PoC（docs/design-ai-detection.md §13）の値をそのまま使っており、
// 評価セットでの校正はしていない。§8 段階 0 の評価セットができたら校正し直す。
const (
	spanThreshold = 0.5
	highProb      = 0.95
	mediumProb    = 0.7
)

// InferFunc は 1 窓分のトークン ID 列（<s>・</s> 込み）を受け取り、トークンごとの
// ラベル logits（[len(ids)][ラベル数]）を返す。並行に呼ばれる。
type InferFunc func(ids []int64) ([][]float32, error)

// Recognizer はモデル起点の候補を挙げる。並行に使ってよい（infer が並行安全な限り）。
type Recognizer struct {
	tok         *tokenizer
	infer       InferFunc
	labels      []string
	temperature float64
	close       func() error
}

// 期待するモデルディレクトリの中身。
const (
	onnxFile       = "model.int8.onnx"
	tokenizerFile  = "tokenizer.json"
	labelsFile     = "sumi_labels.json"
	calibratorFile = "calibrator.json"
)

// newRecognizer はモデルディレクトリのトークナイザ・ラベル・校正値を読み込み、
// 推論関数 infer と組み合わせる。
func newRecognizer(dir string, infer InferFunc, closeFn func() error) (*Recognizer, error) {
	tok, err := loadTokenizer(filepath.Join(dir, tokenizerFile))
	if err != nil {
		return nil, err
	}
	var labels struct {
		LabelList []string `json:"label_list"`
	}
	if err := readJSON(filepath.Join(dir, labelsFile), &labels); err != nil {
		return nil, err
	}
	if len(labels.LabelList) == 0 {
		return nil, fmt.Errorf("%s: label_list が空です", labelsFile)
	}
	var cal struct {
		Method      string  `json:"method"`
		Temperature float64 `json:"temperature"`
	}
	if err := readJSON(filepath.Join(dir, calibratorFile), &cal); err != nil {
		return nil, err
	}
	if cal.Method != "temperature" || cal.Temperature <= 0 {
		return nil, fmt.Errorf("%s: temperature scaling 以外の校正には未対応です", calibratorFile)
	}
	return &Recognizer{tok: tok, infer: infer, labels: labels.LabelList, temperature: cal.Temperature, close: closeFn}, nil
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// Close はモデルのセッションを解放する。
func (r *Recognizer) Close() error {
	if r.close == nil {
		return nil
	}
	return r.close()
}

// span はテキスト上のルーン単位の半開区間と、Sumi の種別・確率。
type span struct {
	typ        string
	start, end int
	prob       float64
}

// Recognize は text の PII 候補を返す。File は空のまま（呼び出し側が設定する）。
// 行番号・列は text を "\n" で分割した 1 始まりの行と、行内の 1 始まりのルーン列
// （internal/external のプロトコル v1 と同じ座標系）。
func (r *Recognizer) Recognize(text string) ([]external.Candidate, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	runes := []rune(text)
	toks := r.tok.encode(text)
	var spans []span
	for _, w := range windows(runes, toks) {
		ids := make([]int64, 0, len(w)+2)
		ids = append(ids, bosID)
		for _, t := range w {
			ids = append(ids, t.ID)
		}
		ids = append(ids, eosID)
		logits, err := r.infer(ids)
		if err != nil {
			return nil, err
		}
		if len(logits) != len(ids) {
			return nil, fmt.Errorf("モデル出力のトークン数 %d が入力 %d と一致しません", len(logits), len(ids))
		}
		spans = append(spans, r.decode(w, logits[1:len(logits)-1])...)
	}
	return toCandidates(runes, spans), nil
}

// windows はトークン列を maxWindowTokens 以下の窓に切る。窓の末尾は、改行を
// 含むトークンの直後で切れるときはそこで切る（行の途中で切らない）。1 行が窓に
// 収まらないとき（minify された JS、base64 等）は行の途中で切る。
//
// ponytail: 窓は重ねていないので、窓の境界をまたぐ PII は分断される。設計書 §6.3 は
// 前後数行を重ねる案。境界での取りこぼしが評価で問題になったら重ねる。
func windows(runes []rune, toks []token) [][]token {
	var out [][]token
	for len(toks) > maxWindowTokens {
		cut := maxWindowTokens
		for i := maxWindowTokens; i > maxWindowTokens/2; i-- {
			if strings.ContainsRune(string(runes[toks[i-1].Start:toks[i-1].End]), '\n') {
				cut = i
				break
			}
		}
		out = append(out, toks[:cut])
		toks = toks[cut:]
	}
	if len(toks) > 0 {
		out = append(out, toks)
	}
	return out
}

// decode は 1 窓の logits（<s>・</s> を除いた本文トークン分）を BIO ラベルとして
// 読み、スパンにまとめる。スパンの確率は構成トークンの確率の最小値（Sumi と同じ）。
func (r *Recognizer) decode(w []token, logits [][]float32) []span {
	var out []span
	var cur *span
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	for i, t := range w {
		label, prob := r.argmax(logits[i])
		typ, inside := strings.CutPrefix(label, "I-")
		begin := false
		if !inside {
			typ, begin = strings.CutPrefix(label, "B-")
		}
		switch {
		case begin || (inside && (cur == nil || cur.typ != typ)):
			flush()
			cur = &span{typ: typ, start: t.Start, end: t.End, prob: prob}
		case inside:
			cur.end = max(cur.end, t.End)
			cur.prob = min(cur.prob, prob)
		default:
			flush()
		}
	}
	flush()
	return out
}

// argmax は温度で割った logits の softmax の最大要素のラベルと確率を返す。
func (r *Recognizer) argmax(logits []float32) (string, float64) {
	best := 0
	for i, v := range logits {
		if v > logits[best] {
			best = i
		}
	}
	var sum float64
	top := float64(logits[best]) / r.temperature
	for _, v := range logits {
		sum += math.Exp(float64(v)/r.temperature - top)
	}
	if best >= len(r.labels) {
		return "O", 1 / sum
	}
	return r.labels[best], 1 / sum
}
