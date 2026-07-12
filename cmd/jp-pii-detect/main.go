// jp-pii-detect は日本特化の個人情報（PII）静的検出器。
// git commit hook / GitHub Actions CI からの利用を想定する。
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/baneido/jp-pii-detector/internal/baseline"
	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/external"
	"github.com/baneido/jp-pii-detector/internal/report"
	"github.com/baneido/jp-pii-detector/internal/rule"
	"github.com/baneido/jp-pii-detector/internal/source"
)

var version = "dev" // -ldflags "-X main.version=..." で上書き

// resolveVersion は表示するバージョン文字列を決める。
// 優先順位:
//  1. -ldflags "-X main.version=..." での明示指定
//  2. go install module@vX.Y.Z で埋め込まれるモジュールバージョン
//  3. ローカルビルド（go build）時は VCS リビジョンから推定
//  4. いずれも無ければ "dev"
func resolveVersion() string {
	info, ok := debug.ReadBuildInfo()
	return versionFrom(version, info, ok)
}

// versionFrom は resolveVersion の純粋なロジック部分（テスト用に分離）。
func versionFrom(ldflagsVersion string, info *debug.BuildInfo, ok bool) string {
	// ldflags で明示指定されていれば最優先。
	if ldflagsVersion != "dev" && ldflagsVersion != "" {
		return ldflagsVersion
	}
	if !ok || info == nil {
		return ldflagsVersion
	}
	// go install module@vX.Y.Z でインストールした場合はここに入る。
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	// ローカルビルド: 埋め込まれた VCS 情報からコミットを復元する。
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev != "" {
		if len(rev) > 12 {
			rev = rev[:12]
		}
		return ldflagsVersion + "-" + rev + dirty
	}
	return ldflagsVersion
}

const usage = `jp-pii-detect - 日本特化の個人情報（PII）静的検出器

Usage:
  jp-pii-detect scan [flags] [path...]   パス配下を走査（既定: カレントディレクトリ）
  jp-pii-detect scan --staged            git のステージ済み追加行を走査（pre-commit 用）
  jp-pii-detect scan --diff <range>      git diff の追加行を走査（例: origin/main...HEAD）
  jp-pii-detect scan --stdin             標準入力のテキスト 1 本を走査（外部連携用）
  jp-pii-detect rules [--config <path>]  検出ルール一覧を表示（config 適用後の実効ルール。カスタムルールを含む）
  jp-pii-detect version                  バージョンを表示

Scan flags:
  --staged                 ステージ済み変更のみ走査
  --diff <range>           指定リビジョン範囲の追加行を走査
  --stdin                  標準入力のテキストを 1 本のテキストとして走査。json 出力に
                           offset/end_offset（テキスト先頭からのルーン単位の半開区間）を
                           付与する。Microsoft Presidio など文字オフセット基準の連携用。
                           入力に JSON の \uXXXX エスケープ（ensure_ascii=True 出力等）が
                           含まれる場合は復号したビューを走査し、offset/end_offset も
                           復号後テキスト上のルーンオフセットになる点に注意
  --format <fmt>           出力形式: text|json|sarif|github (既定: text)
  --config <path>          設定ファイル (既定: .jp-pii.toml をリポジトリルートまで上方探索)
  --min-confidence <lvl>   報告する最小信頼度: low|medium|high (既定: 設定ファイル値 or medium)
  --fail-on <lvl>          終了コード 1 にする最小信頼度: low|medium|high
                           (既定: 未指定時は従来どおり報告された検出が1件でもあれば exit 1。
                           指定時は --min-confidence で報告しつつ、この閾値未満の検出だけの
                           場合は exit 0 にできる。可視化したい閾値と CI を落としたい閾値を
                           分離するためのフラグ)
  --unmask                 検出値をマスクせず出力
  --explain                text/json 出力に検出理由（コンテキスト昇格・検証有無等）を含める
  --explain-dropped        検出候補がどの段階で棄却されたかを text/json 出力に追加する
                           （FN 分析用。json 出力の dropped 配列に生の値は含めない）
  --high-recall            偽陽性リスクの高い再現率重視ルールを有効化
  --exit-zero              検出があっても終了コード 0 を返す
  --baseline <path>        ベースラインファイルを読み込み、記録済み（fingerprint が
                           一致）の検出を結果と終了コードから除外する。--staged /
                           --diff / フルスキャンいずれとも併用可能
  --update-baseline        現在の検出内容でベースラインファイルを新規作成、または
                           既存ファイルに追記して終了コード 0 で終了する
                           （--baseline <path> の指定が必須）
  --show-baseline          ベースラインで除外された検出も参考表示する（終了コードには
                           影響しない。--baseline <path> の指定が必須）

パスとフラグの順序は問いません（例: "scan . --high-recall" も
"scan --high-recall ." と同じ意味になります）。"--" 以降は常にパスとして扱います。

Exit codes: 0=検出なし 1=検出あり 2=エラー
  （フルスキャン時、一部ファイルが読み取れなかった場合も 2 を返す。
    収集済みの検出は通常どおり出力し、警告を stderr に出す）
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "rules":
		os.Exit(runRules(os.Args[2:]))
	case "version":
		fmt.Println(resolveVersion())
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	staged := fs.Bool("staged", false, "")
	diffRange := fs.String("diff", "", "")
	stdin := fs.Bool("stdin", false, "")
	format := fs.String("format", "text", "")
	configPath := fs.String("config", "", "")
	minConf := fs.String("min-confidence", "", "")
	failOn := fs.String("fail-on", "", "")
	unmask := fs.Bool("unmask", false, "")
	explain := fs.Bool("explain", false, "")
	explainDropped := fs.Bool("explain-dropped", false, "")
	highRecall := fs.Bool("high-recall", false, "")
	exitZero := fs.Bool("exit-zero", false, "")
	baselinePath := fs.String("baseline", "", "")
	updateBaseline := fs.Bool("update-baseline", false, "")
	showBaseline := fs.Bool("show-baseline", false, "")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	// Go の flag パッケージは最初の非フラグ引数（パス等）でパースを止めるため、
	// "scan . --high-recall" のようにパスの後ろに置かれたフラグは無視され、パス
	// として扱われた "--high-recall" が存在チェックに回って分かりにくい
	// "no such file" エラーになる。フラグと値をパス等より前に並べ替えてから渡す。
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return 2
	}
	if *updateBaseline && *baselinePath == "" {
		return fail(fmt.Errorf("--update-baseline には --baseline <path> の指定が必要です"))
	}
	if *showBaseline && *baselinePath == "" {
		return fail(fmt.Errorf("--show-baseline には --baseline <path> の指定が必要です"))
	}

	var failThreshold rule.Confidence
	if *failOn != "" {
		t, err := rule.ParseConfidence(*failOn)
		if err != nil {
			return fail(fmt.Errorf("--fail-on: %w", err))
		}
		failThreshold = t
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fail(err)
	}
	if *minConf != "" {
		cfg.MinConfidence = *minConf
	}
	if *highRecall {
		cfg.SetHighRecall(true)
	}
	det, err := detect.New(cfg)
	if err != nil {
		return fail(err)
	}
	// --explain-dropped 指定時のみ棄却候補の記録を有効化する。既定では
	// CollectDropped を呼ばないため、Detector.TakeDropped/DroppedTruncated は
	// 常にゼロ値（nil/false）を返し、後段の report.Text/JSON の出力は
	// 従来と完全に不変になる。
	if *explainDropped {
		det.CollectDropped(true)
	}

	var findings []detect.Finding
	var warnings []error
	switch {
	case *stdin:
		var data []byte
		data, err = io.ReadAll(os.Stdin)
		if err == nil {
			text := string(data)
			// フルスキャン（internal/source の scanFiles）の最終段と同じ JSON
			// \uXXXX エスケープの復号ビュー（source.DecodeEscapedView）を適用
			// する。stdin はまさに JSON をそのままパイプで流し込む用途（外部
			// 連携・エージェントのフック等）が多く、適用価値が高い。復号が
			// 成立した場合、以後の ScanContent と ComputeOffsets は必ず同じ
			// text（復号後テキスト）に対して行う。json 出力の offset/end_offset
			// はその結果、復号後テキスト上のルーンオフセットになる（usage の
			// --stdin 節に注記）。復号を無効にするフラグは設けない（フル
			// スキャン側にも opt-out が無く、対称性を保つため。将来必要になれば
			// ここに条件分岐で opt-out を足せる）。
			if decoded, ok := source.DecodeEscapedView(text); ok {
				text = decoded
			}
			stdinFindings := det.ScanContent("<stdin>", text)
			// 外部レコグナイザ（opt-in、internal/external）: フルスキャン
			// （internal/source）と同じく 1 走査 1 プロセスで、--stdin では
			// このテキスト 1 本だけを渡す。未設定時は cfg.ExternalRecognizerEnabled()
			// が false のためここに一切コストがかからない。git diff 系
			// （--staged/--diff）は対象外（設計メモ・CLAUDE.md 参照）。
			if cfg.ExternalRecognizerEnabled() {
				candidates, diagnostics := external.Run(context.Background(), cfg.ExternalRecognizerConfig(),
					[]external.FileInput{{File: "<stdin>", Text: text}})
				for _, msg := range diagnostics {
					fmt.Fprintln(os.Stderr, "jp-pii-detect: external-recognizer:", msg)
				}
				if len(candidates) > 0 {
					stdinFindings = det.MergeExternalFindings("<stdin>", text, stdinFindings, candidates)
				}
			}
			// ComputeOffsets は外部レコグナイザ由来の finding も含めて
			// offset/end_offset を付与する（Presidio 連携等、文字オフセット基準の
			// 利用側は外部候補も同じ形式で受け取れる）。
			findings = detect.ComputeOffsets(text, stdinFindings)
		}
	case *staged:
		findings, err = source.ScanStaged(det, cfg)
	case *diffRange != "":
		findings, err = source.ScanDiff(det, cfg, *diffRange)
	default:
		paths := fs.Args()
		if len(paths) == 0 {
			paths = []string{"."}
		}
		findings, warnings, err = source.ScanPaths(det, cfg, paths)
	}
	if err != nil {
		return fail(err)
	}
	// 個々のファイルの読み取りエラーは致命的にせず、収集済みの findings は
	// 通常どおり出力する。ただし黙って exit 0 にすると走査が不完全なまま
	// 「検出なし」を装うことになり危険なため、警告を出力した上で常に exit 2
	// にする（findings があっても --exit-zero 指定でも上書きしない）。
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "jp-pii-detect: warning:", w)
	}

	// --update-baseline: 現在の findings（--staged / --diff / フルスキャンいずれの
	// モードでも同じ findings 変数に集約されている）でベースラインファイルを
	// 新規作成、または既存ファイルへ追記して終了コード 0 で終了する。他の
	// フラグ（--baseline での既存フィルタ・出力形式）とは独立した早期リターン。
	if *updateBaseline {
		return updateBaselineFile(*baselinePath, findings)
	}

	// --baseline: 記録済み（fingerprint 一致）の検出を結果・終了コードから除外する。
	// detect パッケージ側の走査（並列）はここまでで完了しており、Filter は
	// 単一 goroutine の後処理なので追加のデータレース懸念はない。
	reportFindings := findings
	exitFindings := findings
	var fpSalt string
	if *baselinePath != "" {
		bf, err := baseline.Load(*baselinePath)
		if err != nil {
			return fail(err)
		}
		fpSalt = bf.Salt
		kept, baselined := baseline.Filter(findings, bf)
		exitFindings = kept
		reportFindings = kept
		if *showBaseline {
			// 参考表示用: フィルタ済み分も併せて出力するが、終了コードの判定には使わない。
			reportFindings = append(append([]detect.Finding{}, kept...), baselined...)
		}
	}
	var fpArgs []string
	if fpSalt != "" {
		fpArgs = []string{fpSalt}
	}
	// --explain-dropped 未指定時は CollectDropped が一度も呼ばれていないため、
	// dropped は常に nil・droppedTruncated は常に false になる
	// （report.Text/JSON の出力が従来と完全に不変であることの根拠）。
	dropped := det.TakeDropped()
	droppedTruncated := det.DroppedTruncated()

	switch *format {
	case "text":
		report.Text(os.Stdout, reportFindings, *unmask, *explain, dropped, droppedTruncated)
	case "json":
		if err := report.JSON(os.Stdout, reportFindings, *unmask, *explain, dropped, droppedTruncated, fpArgs...); err != nil {
			return fail(err)
		}
	case "sarif":
		if err := report.SARIF(os.Stdout, reportFindings, det.Rules(), *unmask); err != nil {
			return fail(err)
		}
	case "github":
		report.GitHub(os.Stdout, reportFindings, *unmask)
	default:
		return fail(fmt.Errorf("unknown format %q (text|json|sarif|github)", *format))
	}

	if len(warnings) > 0 {
		return 2
	}
	if *exitZero {
		return 0
	}
	if shouldFail(exitFindings, failThreshold) {
		return 1
	}
	return 0
}

// shouldFail は終了コードを 1 にすべきかを判定する。呼び出し側は --baseline
// でフィルタ済みの findings（未指定時は生の findings と同じ）を渡す。--fail-on
// が未指定（threshold のゼロ値）の場合は既存の契約どおり「報告された検出が
// 1件でもあれば失敗」。--fail-on 指定時は、report で可視化する min_confidence
// とは独立に、その閾値以上の検出が1件でもあるかどうかだけで判定する
// （min_confidence を下げて medium/low を可視化しつつ、CI は high のときだけ
// 落とす、といった使い分けができる）。
func shouldFail(findings []detect.Finding, threshold rule.Confidence) bool {
	if threshold == 0 {
		return len(findings) > 0
	}
	for _, f := range findings {
		if f.Confidence >= threshold {
			return true
		}
	}
	return false
}

// updateBaselineFile は現在の findings でベースラインファイルを新規作成、
// または既存ファイルに追記して保存する。gitleaks --baseline-path / detect-secrets
// の baseline 更新運用と同様、常に終了コード 0 で返す（走査・書き込み自体の
// エラーのみ 2 を返す）。
func updateBaselineFile(path string, findings []detect.Finding) int {
	bf, err := baseline.Load(path)
	switch {
	case err == nil:
		baseline.Merge(bf, findings)
	case baseline.IsNotExist(err):
		bf, err = baseline.FromFindings(findings, "")
		if err != nil {
			return fail(err)
		}
	default:
		return fail(err)
	}
	if err := baseline.Save(path, bf); err != nil {
		return fail(err)
	}
	fmt.Printf("baseline を更新しました: %s（%d 件）\n", path, len(bf.Entries))
	return 0
}

// runRules は --config を反映した実効ルール一覧（builtin + custom の合成後）を
// 状態タグ（有効/無効・高再現率）付きで表示する。detect.New と同じ合成ロジック
// を経由するため、scan コマンドが実際に使うルール集合と一致する。disabled 指定や
// high_recall（および --high-recall）の効果で実際に有効なルールがどれかを、
// 無効化されたルールも一覧から外さずそのまま確認できる。
//
// 同一 ID の Rule が複数エントリ持つ場合がある（例: jp-address は数字番地用と
// 漢数字番地用で Prefilter が異なる別エントリを同一 ID で持つ。
// internal/rule/builtin.go 参照）。一覧表示では 1 行にまとめる。
func runRules(args []string) int {
	fs := flag.NewFlagSet("rules", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	highRecall := fs.Bool("high-recall", false, "")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fail(err)
	}
	if *highRecall {
		cfg.SetHighRecall(true)
	}
	disabled := map[string]bool{}
	for _, id := range cfg.Rules.Disabled {
		disabled[id] = true
	}
	highRecallIDs := map[string]bool{}
	for _, id := range rule.HighRecallRuleIDs() {
		highRecallIDs[id] = true
	}

	all := append([]rule.Rule{}, rule.Builtin()...)
	all = append(all, cfg.CustomRules()...)
	// 同一 ID の Rule が複数エントリ持つ場合（jp-address 等）は 1 行にまとめる。
	seen := map[string]bool{}
	for _, r := range all {
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		status := "有効"
		if disabled[r.ID] {
			status = "無効"
		}
		tags := []string{status}
		if highRecallIDs[r.ID] {
			tags = append(tags, "高再現率")
		}
		ctx := ""
		for _, p := range r.Patterns {
			if p.RequireContext {
				ctx = " (コンテキストキーワード必須)"
				break
			}
		}
		fmt.Printf("%-28s [%s] %s%s\n", r.ID, strings.Join(tags, "・"), r.Description, ctx)
	}
	return 0
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "jp-pii-detect:", err)
	return 2
}

// reorderArgs は Go の flag パッケージが最初の非フラグ引数でパースを止める
// 制約を回避するため、args 内のフラグ（とその値）をすべて前方に、パス等の
// 非フラグ引数を後方に安定的に並べ替える。これにより
// "scan . --high-recall" のようにパスの後ろに置かれたフラグも
// "scan --high-recall ." と同じように解釈される。相対順序はそれぞれの
// グループ内で保持するため、フラグを複数回指定した場合の「最後の指定が勝つ」
// 挙動や、パスを複数指定した場合の順序は変わらない。"--" 以降は常に
// 非フラグ引数として扱う（Go の flag パッケージ自体の挙動と同じ）。
func reorderArgs(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		name, hasValue := flagName(a)
		if name == "" {
			positional = append(positional, a)
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			// "-weird.txt" のようにフラグと同じ見た目でも、この FlagSet に
			// 定義されていないトークンはパスとして保持する。既知フラグだけを
			// 前方へ移動しないと、従来は最初のパス以降に置けたハイフン始まりの
			// ファイル名が「未定義のフラグ」に変わってしまう。
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		if hasValue {
			continue
		}
		// bool フラグは値を取らない。それ以外（string 等）は次のトークンを値として
		// 一緒に前方へ運ぶ。
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !bf.IsBoolFlag() {
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		}
	}
	if len(positional) == 0 {
		return flags
	}
	return append(append(flags, "--"), positional...)
}

// flagName は "-x" / "--x" / "-x=v" / "--x=v" からフラグ名を取り出す。
// フラグの形をしていなければ空文字を返す（呼び出し側で非フラグ引数として扱う）。
func flagName(a string) (name string, hasValue bool) {
	if len(a) < 2 || a[0] != '-' {
		return "", false
	}
	minuses := 1
	if a[1] == '-' {
		minuses = 2
		if len(a) == 2 { // "--" は呼び出し側で別処理
			return "", false
		}
	}
	s := a[minuses:]
	if s == "" || s[0] == '-' || s[0] == '=' {
		return "", false
	}
	if eq := strings.IndexByte(s, '='); eq >= 0 {
		return s[:eq], true
	}
	return s, false
}
