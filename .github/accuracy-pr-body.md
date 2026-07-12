非公開評価コーパスに対する実測値で、検出精度のゴールデンファイル（`docs/accuracy.json`）と
`docs/accuracy.md`、README.md のバッジを再生成しました（`.github/workflows/accuracy-update.yml`）。

- 実行日時: __GENERATED_AT__
- トリガー: workflow_dispatch（手動実行、実行者: __ACTOR__）
- 実行ログ: __RUN_URL__
- 変更対象: `docs/accuracy.md`、`docs/accuracy.json`、`README.md`
- 再生成コマンド: `go test ./internal/eval -run 'TestGenerateDoc|TestReadmeBadges' -update`

このPRをマージすると、main への push で実行される `ci.yml` の `private-eval` ジョブ
（実測値とゴールデンの完全一致を検証するジョブ）が green に戻ります。

> **マージ前に確認してください**: 実測値が想定外に悪化している場合（例: 特定ルールの
> F1 が 0.00 になっている等）は、検出ルール自体の劣化ではなくコーパス側の問題
> （欠損・破損・分母の変化など）の可能性があります。`docs/accuracy.md` の差分を
> 目視で確認してからマージしてください。

> 注: この PR は `GITHUB_TOKEN` で作成されるため、通常の CI は自動起動しません。
> マージ前に CI（特に本PRが解消するはずの `private-eval`）を回すには、ブランチへ
> 空コミットを push するか PR を close→reopen してください。
