// Command pii-dataset-gen は internal/fixturegen が計算合成する「ルール ×
// 表記ゆれ」マトリクスの評価ケースを、internal/piifixtures と互換の JSON
// （{"strings": {...}, "dataset": [...]}）として書き出す。
//
// 出力する値はすべて checksum のチェックディジット算出ロジックや dict の実在辞書
// から計算合成したもので、リテラルの実在 PII ではない（internal/fixturegen の
// パッケージコメントを参照）。ただし、既存の外部評価データセット
// （internal/piifixtures が JP_PII_FIXTURES から読み込む GCS 管理の JSON）と
// マージする際は、レビューのうえ人手で行うこと。この CLI 自体は GCS への
// アップロードを行わず、出力先はこのリポジトリの管理外のパスを指定すること
// （このリポジトリへコミットしない。ドッグフード CI 対策）。
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
	output := flag.String("output", "", "output JSON path (piifixtures-compatible; must NOT be committed to this repo)")
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
	fmt.Fprintln(stderr, "warning: review before merging into the external JP_PII_FIXTURES dataset; do not commit this file to the repository")
	return nil
}
