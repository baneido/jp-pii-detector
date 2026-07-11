日本郵便の UTF-8 版 KEN_ALL（住所の郵便番号）と事業所の個別郵便番号（jigyosyo）から、
7 桁完全一致ビットセット `internal/dict/postal_codes.bitset` と、市区町村名一覧
`internal/dict/municipalities.txt`（`dict.MunicipalitySuffixMatch` / jp-address-high-recall
の Validate が使う）を自動再生成しました（`.github/workflows/postal-update.yml`）。

- 取得元: <https://www.post.japanpost.jp/zipcode/dl/utf-zip.html>、
  <https://www.post.japanpost.jp/zipcode/dl/jigyosyo/index-zip.html>
- 生成: `go run ./internal/dict/gen -ken-all-input ... -jigyosyo-input ... -municipalities-output ...`
- 検証: ビットセット・市区町村名一覧のサイズ/件数・取り込み件数・`go vet`・`go test ./...`・dogfooding 済み
- 精度: write権限を持つ自動更新jobには非公開コーパスを渡しません。maintainerが
  `go run ./cmd/pii-fixture eval` を明示実行して確認します。

> 注: この PR は `GITHUB_TOKEN` で作成されるため、通常の CI は自動起動しません。
> マージ前に CI を回すには、ブランチへ空コミットを push するか PR を close→reopen してください。
> 郵便番号の増減で実測値が動いた場合は、非公開評価後に
> `go test ./internal/eval -run 'TestGenerateDoc|TestReadmeBadges' -update` を実行し、
> `docs/accuracy.md`・`docs/accuracy.json`・README.md を同じPRへ追加してください。
> 市区町村名一覧の件数が 1,800〜4,000 件の範囲を外れた場合もワークフローが失敗します
> （`internal/dict/municipalities_test.go` の `TestMunicipalitiesDictSanity` と同じ範囲）。
