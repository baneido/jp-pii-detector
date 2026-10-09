package model

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"unicode/utf8"
)

// unkPenalty は Hugging Face tokenizers の Unigram が未知文字に与えるスコアの
// 減点幅（語彙の最小スコア − 10）。同ライブラリの K_UNK_PENALTY と同じ値。
const unkPenalty = 10.0

// token は 1 トークンの ID と、元テキスト上のルーン単位の半開区間 [Start, End)。
type token struct {
	ID         int64
	Start, End int
}

// tokenizer は Sumi（ModernBERT-Ja）の tokenizer.json が定義する Unigram
// トークナイザの最小実装。Hugging Face tokenizers と同じ ID 列と文字オフセットを
// 返すことを、tokenizer_test.go のゴールデン比較で確認している。
//
// 対応している構成は次の組み合わせだけで、それ以外の tokenizer.json は
// loadTokenizer がエラーにする（黙って異なる分割をしないため）:
//   - normalizer: なし
//   - pre_tokenizer: Metaspace（replacement "▁"、prepend_scheme "never"、split false）
//   - model: Unigram（byte_fallback true）
//
// 半角スペースだけを "▁" に置き換え、文字列全体を 1 語として Viterbi で分割する。
// 単独 1 文字の語彙が無い文字は未知文字とし、連続する未知文字を 1 つにまとめてから
// UTF-8 バイトごとの <0xXX> トークンへ置き換える（各バイトトークンの位置は、まとめた
// 範囲全体を指す。Hugging Face tokenizers と同じ挙動）。added_tokens の文字列は
// 本文中でも字句どおり一致させ、その ID を割り当てる。
type tokenizer struct {
	pieces   map[string]piece
	maxRunes int
	unkScore float64
	bytes    [256]int64
	added    []addedToken // 長い順
}

type piece struct {
	id    int64
	score float64
}

type addedToken struct {
	content string
	id      int64
}

type tokenizerJSON struct {
	Normalizer   json.RawMessage `json:"normalizer"`
	PreTokenizer struct {
		Type          string `json:"type"`
		Replacement   string `json:"replacement"`
		PrependScheme string `json:"prepend_scheme"`
		Split         bool   `json:"split"`
	} `json:"pre_tokenizer"`
	Model struct {
		Type         string               `json:"type"`
		ByteFallback bool                 `json:"byte_fallback"`
		Vocab        [][2]json.RawMessage `json:"vocab"`
	} `json:"model"`
	AddedTokens []struct {
		ID      int64  `json:"id"`
		Content string `json:"content"`
	} `json:"added_tokens"`
}

func loadTokenizer(path string) (*tokenizer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var j tokenizerJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	pt := j.PreTokenizer
	if s := strings.TrimSpace(string(j.Normalizer)); s != "" && s != "null" {
		return nil, fmt.Errorf("%s: normalizer には未対応です", path)
	}
	if pt.Type != "Metaspace" || pt.Replacement != "▁" || pt.PrependScheme != "never" || pt.Split {
		return nil, fmt.Errorf("%s: pre_tokenizer の構成に未対応です（%+v）", path, pt)
	}
	if j.Model.Type != "Unigram" || !j.Model.ByteFallback {
		return nil, fmt.Errorf("%s: model は byte_fallback 付きの Unigram のみ対応です", path)
	}
	t := &tokenizer{pieces: make(map[string]piece, len(j.Model.Vocab))}
	for i := range t.bytes {
		t.bytes[i] = -1
	}
	minScore := math.Inf(1)
	for id, v := range j.Model.Vocab {
		var s string
		var score float64
		if err := json.Unmarshal(v[0], &s); err != nil {
			return nil, fmt.Errorf("%s: vocab[%d]: %w", path, id, err)
		}
		if err := json.Unmarshal(v[1], &score); err != nil {
			return nil, fmt.Errorf("%s: vocab[%d]: %w", path, id, err)
		}
		t.pieces[s] = piece{id: int64(id), score: score}
		t.maxRunes = max(t.maxRunes, utf8.RuneCountInString(s))
		minScore = min(minScore, score)
		var b int
		if len(s) == 6 && strings.HasPrefix(s, "<0x") && strings.HasSuffix(s, ">") {
			if _, err := fmt.Sscanf(s, "<0x%02X>", &b); err == nil {
				t.bytes[b] = int64(id)
			}
		}
	}
	for b, id := range t.bytes {
		if id < 0 {
			return nil, fmt.Errorf("%s: バイトトークン <0x%02X> が語彙にありません", path, b)
		}
	}
	t.unkScore = minScore - unkPenalty
	for _, a := range j.AddedTokens {
		t.added = append(t.added, addedToken{content: a.Content, id: a.ID})
	}
	sort.SliceStable(t.added, func(i, k int) bool { return len(t.added[i].content) > len(t.added[k].content) })
	return t, nil
}

// encode は text をトークン列にする（<s>・</s> は付けない）。
func (t *tokenizer) encode(text string) []token {
	runes := []rune(text)
	var out []token
	seg := 0
	for i := 0; i < len(runes); {
		if a, ok := t.matchAdded(runes, i); ok {
			out = t.viterbi(runes, seg, i, out)
			n := utf8.RuneCountInString(a.content)
			out = append(out, token{ID: a.id, Start: i, End: i + n})
			i += n
			seg = i
			continue
		}
		i++
	}
	return t.viterbi(runes, seg, len(runes), out)
}

func (t *tokenizer) matchAdded(runes []rune, i int) (addedToken, bool) {
	if runes[i] != '<' {
		return addedToken{}, false // added_tokens はすべて "<" で始まる（loadTokenizer では検証しない。Sumi の語彙に限った最適化）
	}
	for _, a := range t.added {
		n := utf8.RuneCountInString(a.content)
		if i+n <= len(runes) && string(runes[i:i+n]) == a.content {
			return a, true
		}
	}
	return addedToken{}, false
}

// viterbi は runes[from:to] を最大スコアで分割し、out に追記して返す。
func (t *tokenizer) viterbi(runes []rune, from, to int, out []token) []token {
	n := to - from
	if n <= 0 {
		return out
	}
	// Metaspace: 半角スペースだけを ▁ に置き換える（ルーン数は変わらない）。
	seg := make([]rune, n)
	for i, r := range runes[from:to] {
		if r == ' ' {
			r = '▁'
		}
		seg[i] = r
	}
	best := make([]float64, n+1)
	prev := make([]int, n+1)  // 直前の分割位置
	ids := make([]int64, n+1) // -1 は未知文字
	for i := 1; i <= n; i++ {
		best[i] = math.Inf(-1)
	}
	var sb strings.Builder
	for i := 0; i < n; i++ {
		if math.IsInf(best[i], -1) {
			continue
		}
		hasSingle := false
		sb.Reset()
		for k := i; k < n && k-i < t.maxRunes; k++ {
			sb.WriteRune(seg[k])
			p, ok := t.pieces[sb.String()]
			if !ok {
				continue
			}
			if k == i {
				hasSingle = true
			}
			if s := best[i] + p.score; s > best[k+1] {
				best[k+1], prev[k+1], ids[k+1] = s, i, p.id
			}
		}
		if !hasSingle {
			if s := best[i] + t.unkScore; s > best[i+1] {
				best[i+1], prev[i+1], ids[i+1] = s, i, -1
			}
		}
	}
	// 後ろから辿って分割を復元する。
	var rev []token
	for k := n; k > 0; k = prev[k] {
		rev = append(rev, token{ID: ids[k], Start: from + prev[k], End: from + k})
	}
	for i := len(rev) - 1; i >= 0; i-- {
		tok := rev[i]
		if tok.ID >= 0 {
			out = append(out, tok)
			continue
		}
		// 連続する未知文字を 1 つにまとめ、UTF-8 バイトごとのトークンにする。
		end := tok.End
		for i > 0 && rev[i-1].ID < 0 {
			i--
			end = rev[i].End
		}
		for _, b := range []byte(string(runes[tok.Start:end])) {
			out = append(out, token{ID: t.bytes[b], Start: tok.Start, End: end})
		}
	}
	return out
}
