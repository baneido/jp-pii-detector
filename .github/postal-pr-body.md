日本郵便の UTF-8 版 KEN_ALL（住所の郵便番号）から、7 桁完全一致ビットセット
`internal/dict/postal_codes.bitset` とフォールバック用 `internal/dict/postal_prefixes.txt`
を自動再生成しました（`.github/workflows/postal-update.yml`）。

- 取得元: <https://www.post.japanpost.jp/zipcode/dl/utf-zip.html>
- 生成: `go run ./internal/dict/gen`
- 検証: ビットセットのサイズ・プレフィックス数・`go vet`・`go test ./internal/dict/...`・dogfooding 済み

> 注: この PR は `GITHUB_TOKEN` で作成されるため、通常の CI が自動起動しません。
> マージ前に CI を回すには、ブランチへ空コミットを push するか PR を close→reopen してください。
> 郵便番号の増減で `jp-postal-code` の精度数値が動いた場合は、フィクスチャ環境で
> `go test ./internal/eval -update` を実行してバッジと `docs/accuracy.md` を再生成してください。
