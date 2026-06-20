日本郵便の UTF-8 版 KEN_ALL（住所の郵便番号）から、7 桁完全一致ビットセット
`internal/dict/postal_codes.bitset` を自動再生成しました（`.github/workflows/postal-update.yml`）。

- 取得元: <https://www.post.japanpost.jp/zipcode/dl/utf-zip.html>
- 生成: `go run ./internal/dict/gen`
- 検証: ビットセットのサイズ・取り込み件数・`go vet`・`go test ./...`・dogfooding 済み
- 精度: フィクスチャが設定されていれば `TestAccuracy`（F1 ゲート）も実行され、`docs/accuracy.md` と
  README バッジを実測で再生成して本 PR に含めています。

> 注: この PR は `GITHUB_TOKEN` で作成されるため、通常の CI は自動起動しません。
> マージ前に CI を回すには、ブランチへ空コミットを push するか PR を close→reopen してください。
> 郵便番号の増減で F1 が `wantF1` の許容を超えて動いた場合はワークフロー自体が失敗するので、
> その際は `internal/eval/eval_test.go` の `wantF1` を実測へ更新してください。
