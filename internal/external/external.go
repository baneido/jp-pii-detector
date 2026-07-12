// Package external は .jp-pii.toml の [external_recognizer] で設定した外部コマンドを
// 検出候補の生成器として呼び出す opt-in フックを提供する（プロトコル v1）。
//
// このパッケージは exec.Command でユーザー指定の argv を実行するだけの薄い I/O 層で、
// 検出値の意味解釈・ルール ID の検証・allowlist / ignore マーカー・重複解決といった
// PII 検出そのものの判断は一切行わない（呼び出し側の internal/detect.MergeExternalFindings
// が担う）。ここでの責務は「1 回の走査につき子プロセスを 1 つ起動し、JSONL でファイル群を
// 送り、JSONL で候補を受け取り、タイムアウト・異常終了・プロトコル違反を検出器本体を
// 壊さずに吸収すること」に限定する。
//
// # プロトコル v1（JSONL）
//
// ファイルごとに子プロセスを 1 つ起動すると（フルスキャン等、ファイル数が多い走査では）
// 起動コストが支配的になるため、v1 は「1 回の走査につき子プロセスを 1 つ」起動し、
// 複数ファイルをまとめて JSONL で送受信する（末尾に子プロセスの選定理由と旧案の比較を
// 記す）。
//
// 親→子（標準入力、1 行 1 JSON、全ファイル送信後に標準入力を閉じる）:
//
//	{"version":1,"file":"<path>","text":"<ファイル全文>"}
//
// ファイルごとに 1 行。行の順序は任意（子は file で対応付けて返す）。text は
// 走査対象ファイルの内容そのもの（正規化前の原文）。
//
// 子→親（標準出力、1 行 1 検出。ファイルをまたいで任意の順序でよい）:
//
//		{"file":"<path>","rule_id":"person-name-external","line":1,"column":1,"length":3,"confidence":"medium"}
//
//	  - file: 対応するリクエスト行の file をそのまま返す。一致するリクエストが無い
//	    file 値は呼び出し側で無視される。
//	  - rule_id: "-external" で終わる必要がある（組み込みルール ID の偽装を防ぐ）。
//	    本パッケージ自体はこの接尾辞を検証しない（受信 JSON の構造検証のみを担当し、
//	    意味検証は呼び出し側の責務にする）。
//	  - line: 1 始まりの行番号（text を "\n" で分割した行、"\r\n" の "\r" は行末に
//	    含めない）。
//	  - column: 1 始まりのルーン列（UTF-8 のバイト位置ではなくコードポイント単位。
//	    internal/normalize と同じ「ルーン基準」の座標系）。
//	  - length: 検出値のルーン数。
//	  - confidence: "low" | "medium" | "high"。それ以外の値は呼び出し側が low として
//	    扱う（本パッケージはここでは検証しない。受信した文字列をそのまま Candidate に
//	    積む）。
//
// 値そのもの（マッチ文字列）はプロトコルに含めない。子の自己申告値を信用せず、
// 親側が file の text から line/column/length で切り出す（呼び出し側の責務）。
//
// 標準エラーは子の診断用に自由に使ってよい（プロトコルの一部ではない）。本パッケージは
// 標準エラー全体を回収し、Run の戻り値 diagnostics に文字列として含める（report には
// 出力されない。呼び出し側がログ相当として標準エラー等に出す）。
//
// # 失敗時の扱い
//
// タイムアウト・0 以外の終了コード・標準出力の JSON 構文/型エラーは、いずれも
// 「この走査回の候補をすべて破棄」として扱う（部分的な結果を信用しない。壊れた/
// 悪意ある子が一部だけ正しく見える出力を混ぜてくる可能性を考慮する）。個々の候補が
// 意味的に不正（rule_id の接尾辞違反、範囲外のスパン等）な場合はその候補だけを
// 破棄する側（呼び出し側 internal/detect の責務）に委ねる。検出器本体（組み込み
// ルールによる通常の検出）はこのパッケージの失敗に関わらず常に継続できるよう、
// Run はエラーを返さず (nil candidates, diagnostics) で失敗を表現する。
//
// # 子プロセス起動モデルの選定理由
//
// 設計時点の選択肢は (a) ファイルごとに子プロセスを 1 つ起動する、(b) 走査全体で
// 子プロセスを 1 つだけ起動し複数ファイルを連続送信する、の 2 案があった。(a) は
// プロトコルが単純になる一方、Python 等インタプリタ系ランタイムでは起動コスト
// （インタプリタ起動 + モデルロード）がファイル数に比例して積み上がり、GiNZA/BERT の
// ような重量級 NER を想定する用途では現実的でない。(b) はプロトコルがわずかに複雑に
// なる（応答に file を含める必要がある）代わりに、子プロセスの起動・モデルロードが
// 1 回で済む。実装のしやすさよりも実運用での起動コストを優先し、(b) を採用した。
package external

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ProtocolVersion は本パッケージが送信するリクエスト行の version フィールドの値。
const ProtocolVersion = 1

// DefaultTimeout は Config.Timeout が 0 以下のときに使うタイムアウト。
const DefaultTimeout = 30 * time.Second

// DefaultMaxFindings は Config.MaxFindings が 0 以下のときに使う上限。
const DefaultMaxFindings = 1000

// maxResponseLineBytes は子プロセスの標準出力 1 行あたりの読み取り上限バイト数。
// 応答は rule_id・line・column・length・confidence のみを運ぶ小さな JSON のはずで、
// これを大きく超える行は壊れた/悪意ある出力とみなし、bufio.Scanner の
// ErrTooLong 経由で「不正な行」として通常の malformed-JSON 経路（走査回の結果を
// 丸ごと破棄）に合流させる。
const maxResponseLineBytes = 1 << 20 // 1MiB

// Config は [external_recognizer] を internal/config から渡すための設定値
// （internal/config.Config.ExternalRecognizerConfig が変換する）。
type Config struct {
	// Command は実行する外部コマンドの argv（例: []string{"python3", "my_ner.py"}）。
	// シェル解釈は行わず exec.Command にそのまま渡す。空、または Command[0] が
	// 空文字列なら Enabled() は false になる。
	Command []string
	// Timeout は子プロセスの実行タイムアウト。0 以下なら DefaultTimeout を使う。
	Timeout time.Duration
	// MaxFindings は 1 回の Run で受理する候補数の上限。0 以下なら
	// DefaultMaxFindings を使う。上限到達後に届いた行は読み捨てる
	// （子プロセスの標準出力パイプを詰まらせないため読み続けるが、Candidate には
	// 積まない）。
	MaxFindings int
}

// Enabled はコマンドが設定されているかを返す。false の場合 Run は何もしない。
func (c Config) Enabled() bool {
	return len(c.Command) > 0 && c.Command[0] != ""
}

// FileInput は子プロセスへ送る 1 ファイル分の走査対象。
type FileInput struct {
	// File はファイルパス（呼び出し側の表記をそのまま使う。internal/source は
	// filepath.ToSlash 済みのパスを渡す）。
	File string
	// Text はファイルの内容（正規化前の原文）。
	Text string
}

// Candidate は子プロセスから受け取った検出候補 1 件。JSON の構造検証のみ済み
// （型・必須フィールドの形は正しい）で、rule_id の接尾辞や line/column/length の
// 範囲妥当性はまだ検証されていない（呼び出し側 internal/detect の責務）。
type Candidate struct {
	File       string
	RuleID     string
	Line       int
	Column     int
	Length     int
	Confidence string
}

// request は親→子（stdin）の 1 行分。
type request struct {
	Version int    `json:"version"`
	File    string `json:"file"`
	Text    string `json:"text"`
}

// response は子→親（stdout）の 1 行分。
type response struct {
	File       string `json:"file"`
	RuleID     string `json:"rule_id"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	Length     int    `json:"length"`
	Confidence string `json:"confidence"`
}

// Run は cfg.Command を 1 回だけ起動し、inputs を JSONL で送信して候補を集める。
//
// cfg.Enabled() が false、または inputs が空の場合は何もせず (nil, nil) を返す
// （プロセスは一切起動しない。既定の未設定状態でコストがかからないことの根拠）。
//
// タイムアウト・0 以外の終了コード・標準出力の JSON 構文/型エラーは、いずれも
// 「この走査回の候補をすべて破棄」として扱い (nil, diagnostics) を返す。呼び出し側は
// これを「外部候補なし」として扱い、通常の検出だけで走査を継続すればよい
// （検出器本体を壊さないという設計方針）。diagnostics は空の場合もある成功時にも
// 子プロセスの標準エラー出力があれば含まれる（人間可読なログ用途。値そのものは
// 含めていない前提だが、子が何を書くかは制御できないため、呼び出し側は
// レポートには出さずログ相当として扱うこと）。
func Run(ctx context.Context, cfg Config, inputs []FileInput) (candidates []Candidate, diagnostics []string) {
	if !cfg.Enabled() || len(inputs) == 0 {
		return nil, nil
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxFindings := cfg.MaxFindings
	if maxFindings <= 0 {
		maxFindings = DefaultMaxFindings
	}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, cfg.Command[0], cfg.Command[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, []string{fmt.Sprintf("標準入力パイプを作成できません: %v", err)}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, []string{fmt.Sprintf("標準出力パイプを作成できません: %v", err)}
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, []string{fmt.Sprintf("外部レコグナイザを起動できません（command=%v）: %v", cfg.Command, err)}
	}

	// 標準入力への書き込みは別ゴルーチンで行う。子プロセスが全リクエストを
	// 受信し終える前に応答を書き始める実装（ストリーミング処理）でも、親が
	// 書き込み中に stdout を読まないとパイプのバッファが埋まって双方が
	// 待ち続けるデッドロックになりうるため、書き込みと読み取りを並行させる。
	writeErrCh := make(chan error, 1)
	go func() {
		defer stdin.Close()
		enc := json.NewEncoder(stdin)
		for _, in := range inputs {
			if err := enc.Encode(request{Version: ProtocolVersion, File: in.File, Text: in.Text}); err != nil {
				writeErrCh <- err
				return
			}
		}
		writeErrCh <- nil
	}()

	ok := true
	var diags []string
	var cands []Candidate
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), maxResponseLineBytes)
readLoop:
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			// 空行は許容する（末尾の空行等、実害のない出力ゆれのため）。
			continue
		}
		var resp response
		if err := json.Unmarshal(line, &resp); err != nil {
			ok = false
			diags = append(diags, fmt.Sprintf(
				"標準出力に不正な JSON 行を検出したため、この走査回の外部候補をすべて破棄しました: %v", err))
			// ここで読み取りをやめるだけだと、子プロセスがまだ書き込み中
			// （パイプのバッファが埋まってブロックする量を出力し続ける）の場合、
			// 誰も stdout を読まなくなったまま cmd.Wait() が子プロセスの自然な
			// 終了を待ち続け、実質的にタイムアウトいっぱいまで応答が遅れる
			// （デッドロックではないが「不正行を検出したのに即座に失敗しない」
			// という応答性の問題）。ここで即座に cancel してプロセスを強制終了させ、
			// 待ち時間を最小化する（defer cancel() と二重に呼ぶことになるが
			// context.CancelFunc は冪等なので安全）。
			cancel()
			break readLoop
		}
		if len(cands) >= maxFindings {
			// 上限到達後も読み捨てを続け、パイプを詰まらせて子プロセスを
			// ブロックさせないようにする（新規候補としては積まない）。
			continue
		}
		cands = append(cands, Candidate{
			File:       resp.File,
			RuleID:     resp.RuleID,
			Line:       resp.Line,
			Column:     resp.Column,
			Length:     resp.Length,
			Confidence: resp.Confidence,
		})
	}
	if err := scanner.Err(); err != nil {
		ok = false
		diags = append(diags, fmt.Sprintf("標準出力の読み取りに失敗したため外部候補を破棄しました: %v", err))
		// 上と同じ理由（読み取りをやめた後に子プロセスが書き込みでブロックし、
		// Wait() がタイムアウトいっぱいまで戻らなくなるのを避ける）で即座に cancel する。
		cancel()
	}

	writeErr := <-writeErrCh
	waitErr := cmd.Wait()

	switch {
	case cctx.Err() == context.DeadlineExceeded:
		ok = false
		diags = append(diags, fmt.Sprintf("タイムアウト（%s）のため外部候補を破棄しました", timeout))
	case waitErr != nil:
		ok = false
		diags = append(diags, fmt.Sprintf("外部レコグナイザが異常終了したため外部候補を破棄しました: %v", waitErr))
	}
	if writeErr != nil {
		// 子プロセスの異常終了（上記 waitErr）に伴う broken pipe 等が典型的な原因。
		// 単独では致命扱いにしない（waitErr 側で既に ok=false になっているはず）。
		diags = append(diags, fmt.Sprintf("標準入力への書き込みで問題が発生しました（診断用）: %v", writeErr))
	}
	if stderrBuf.Len() > 0 {
		diags = append(diags, "外部レコグナイザの標準エラー出力: "+strings.TrimSpace(stderrBuf.String()))
	}
	if !ok {
		return nil, diags
	}
	return cands, diags
}
