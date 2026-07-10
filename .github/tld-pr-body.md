IANA の root zone TLD 一覧（<https://data.iana.org/TLD/tlds-alpha-by-domain.txt>）から、
`internal/dict/tlds-alpha-by-domain.txt` を自動更新しました（`.github/workflows/tld-update.yml`）。

- 取得元: <https://data.iana.org/TLD/tlds-alpha-by-domain.txt>
- 追加: __ADDED_COUNT__ 件
- 削除: __REMOVED_COUNT__ 件
- 検証: 取得物の非空・先頭行フォーマット・件数閾値・`go vet`・`go test ./...`・dogfooding 済み
- 精度: フィクスチャが設定されていれば `TestAccuracy`（F1 ゲート）も実行され、`docs/accuracy.md` と
  README バッジを実測で再生成して本 PR に含めています。

> 注: この PR は `GITHUB_TOKEN` で作成されるため、通常の CI は自動起動しません。
> マージ前に CI を回すには、ブランチへ空コミットを push するか PR を close→reopen してください。
> TLD の増減で F1 が `wantF1` の許容を超えて動いた場合はワークフロー自体が失敗する（PR は作られない）ので、
> その際は `internal/eval/eval_test.go` の `wantF1` を実測へ更新してください。

> **削除された TLD がある場合は要注意（gTLD/ccTLD の廃止は極めて稀）**: IANA 側の一時的な配信異常で
> リストが縮退しただけの可能性もあるため、マージ前に
> <https://data.iana.org/TLD/tlds-alpha-by-domain.txt> を目視で確認してください。
> 該当する TLD を含むメールアドレスが既存コードやドキュメントに残っていないかも確認すること。
