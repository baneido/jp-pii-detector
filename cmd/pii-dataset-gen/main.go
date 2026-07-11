// Command pii-dataset-gen は internal/fixturegen が計算合成する「ルール ×
// 表記ゆれ」マトリクスの合成契約ケースを、version付きJSONとして書き出す。
//
// 出力する値はすべて checksum のチェックディジット算出ロジックや dict の実在辞書
// から計算合成したもので、人物レコードから採取していない。ただし実在番号空間との
// 偶然一致は保証できないため、値をログへ出さず、private corpusや公式F1へ混ぜない。
// このCLIはGCSへ書き込まず、出力先はリポジトリ管理外を指定する。
//
//	go run ./cmd/pii-dataset-gen -output /path/outside/repo/synthetic-cases.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/baneido/jp-pii-detector/internal/fixturegen"
)

func main() {
	output := flag.String("output", "", "output JSON path for synthetic contract cases; must NOT be committed")
	flag.Parse()

	if *output == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}

	if err := run(*output, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(output string, stdout, stderr *os.File) error {
	file := fixturegen.GenerateFile()

	b, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal dataset: %w", err)
	}
	b = append(b, '\n')

	if err := os.WriteFile(output, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", output, err)
	}

	fmt.Fprintf(stdout, "wrote %d synthetic cases to %s\n", len(file.Dataset), output)
	fmt.Fprint(stdout, fixturegen.Summary(file.Dataset))
	fmt.Fprintln(stderr, "warning: synthetic contract data must not be merged into the private accuracy corpus or committed")
	return nil
}
