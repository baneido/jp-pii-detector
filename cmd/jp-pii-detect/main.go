// jp-pii-detect は日本特化の個人情報（PII）静的検出器。
// git commit hook / GitHub Actions CI からの利用を想定する。
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/detect"
	"github.com/baneido/jp-pii-detector/internal/report"
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
                           付与する。Microsoft Presidio など文字オフセット基準の連携用
  --format <fmt>           出力形式: text|json|sarif|github (既定: text)
  --config <path>          設定ファイル (既定: .jp-pii.toml をリポジトリルートまで上方探索)
  --min-confidence <lvl>   報告する最小信頼度: low|medium|high (既定: 設定ファイル値 or medium)
  --unmask                 検出値をマスクせず出力
  --explain                JSON 出力に検出理由を含める
  --high-recall            偽陽性リスクの高い再現率重視ルールを有効化
  --exit-zero              検出があっても終了コード 0 を返す

Exit codes: 0=検出なし 1=検出あり 2=エラー
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
	unmask := fs.Bool("unmask", false, "")
	explain := fs.Bool("explain", false, "")
	highRecall := fs.Bool("high-recall", false, "")
	exitZero := fs.Bool("exit-zero", false, "")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 2
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

	var findings []detect.Finding
	switch {
	case *stdin:
		var data []byte
		data, err = io.ReadAll(os.Stdin)
		if err == nil {
			text := string(data)
			findings = detect.ComputeOffsets(text, det.ScanContent("<stdin>", text))
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
		findings, err = source.ScanPaths(det, cfg, paths)
	}
	if err != nil {
		return fail(err)
	}

	switch *format {
	case "text":
		report.Text(os.Stdout, findings, *unmask)
	case "json":
		if err := report.JSON(os.Stdout, findings, *unmask, *explain); err != nil {
			return fail(err)
		}
	case "sarif":
		if err := report.SARIF(os.Stdout, findings, det.Rules(), *unmask); err != nil {
			return fail(err)
		}
	case "github":
		report.GitHub(os.Stdout, findings, *unmask)
	default:
		return fail(fmt.Errorf("unknown format %q (text|json|sarif|github)", *format))
	}

	if len(findings) > 0 && !*exitZero {
		return 1
	}
	return 0
}

// runRules は --config を反映した実効ルール一覧（builtin + custom の合成後、
// 無効化ルールを除いたもの）を表示する。detect.New と同じ合成ロジックを
// 経由するため、scan コマンドが実際に使うルール集合と一致する。
func runRules(args []string) int {
	fs := flag.NewFlagSet("rules", flag.ExitOnError)
	configPath := fs.String("config", "", "")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fail(err)
	}
	det, err := detect.New(cfg)
	if err != nil {
		return fail(err)
	}
	for _, r := range det.Rules() {
		ctx := ""
		for _, p := range r.Patterns {
			if p.RequireContext {
				ctx = " (コンテキストキーワード必須)"
				break
			}
		}
		fmt.Printf("%-22s %s%s\n", r.ID, r.Description, ctx)
	}
	return 0
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "jp-pii-detect:", err)
	return 2
}
