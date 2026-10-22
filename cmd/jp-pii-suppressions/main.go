// Command jp-pii-suppressions は、走査対象ツリーで検出がどれだけ・どのルールについて
// 抑制されているか（行内 ignore マーカー `jp-pii-detector:ignore` / 旧 `pii-allow`、
// および .jp-pii.toml の [allowlist]）をルール別に集計する。抑制の多いルールは
// 誤検出（ノイズ）の多いルールの手がかりになる。
//
// 配布バイナリ（jp-pii-detect）には含まれない開発・フィードバック用の道具で、
// 次のように実行する（詳細は docs/feedback.md）。
//
//	go run github.com/baneido/jp-pii-detector/cmd/jp-pii-suppressions@latest [flags] [path ...]
//
// 出力はルール ID・件数・allowlist の要素番号（regexes / stopwords は値を含みうるため
// 番号のみ）・（--files 指定時のみ）ファイルパスだけで、マッチ値は出さない。
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/baneido/jp-pii-detector/internal/config"
	"github.com/baneido/jp-pii-detector/internal/suppression"
)

const usage = `使い方: jp-pii-suppressions [flags] [path ...]

走査対象（既定: .）で ignore マーカーと [allowlist] が抑制している検出を
ルール別に集計します。マッチ値は出力しません。

flags:
  --config <path>          設定ファイル（既定: カレントから上方向に .jp-pii.toml を探索）
  --format markdown|json   出力形式（既定: markdown）
  --high-recall            高再現率ルールを有効にして集計する
  --name-roster            名簿ファイル判定を有効にして集計する
  --min-confidence <lvl>   min_confidence を上書きする（low|medium|high）
  --files                  マーカー行の多いファイルのパスも出力する（Issue へ貼る場合は
                           パスに機密が無いか確認してください）
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("jp-pii-suppressions", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "")
	format := fs.String("format", "markdown", "")
	highRecall := fs.Bool("high-recall", false, "")
	nameRoster := fs.Bool("name-roster", false, "")
	minConf := fs.String("min-confidence", "", "")
	files := fs.Bool("files", false, "")
	help := fs.Bool("help", false, "")
	fs.BoolVar(help, "h", false, "")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "jp-pii-suppressions: %v\n\n%s", err, usage)
		return 2
	}
	if *help {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if *format != "markdown" && *format != "json" {
		fmt.Fprintf(stderr, "jp-pii-suppressions: unknown format %q (markdown|json)\n", *format)
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "jp-pii-suppressions: %v\n", err)
		return 2
	}
	if *minConf != "" {
		cfg.MinConfidence = *minConf
	}
	if *highRecall {
		cfg.SetHighRecall(true)
	}
	if *nameRoster {
		cfg.SetNameRoster(true)
	}
	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}
	rep, warnings, err := suppression.Run(cfg, paths, suppression.Options{IncludeFiles: *files})
	for _, w := range warnings {
		fmt.Fprintf(stderr, "jp-pii-suppressions: warning: %v\n", w)
	}
	if err != nil {
		fmt.Fprintf(stderr, "jp-pii-suppressions: %v\n", err)
		return 2
	}
	if *format == "json" {
		err = suppression.WriteJSON(stdout, rep)
	} else {
		err = suppression.WriteMarkdown(stdout, rep)
	}
	if err != nil {
		fmt.Fprintf(stderr, "jp-pii-suppressions: %v\n", err)
		return 2
	}
	return 0
}
