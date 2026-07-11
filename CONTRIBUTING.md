# コントリビューションガイド

`jp-pii-detect` への貢献に興味を持っていただきありがとうございます。

## 特に歓迎する貢献

最も価値が高いのは **誤検出（false positive）と見逃し（false negative）の報告** です。
実際のコードベースでの検出漏れ・過検出のフィードバックが、検出精度の改善に直結します。

- 誤検出・見逃しは、[Issue テンプレート](.github/ISSUE_TEMPLATE) から報告してください。
- **実在する PII は絶対に貼らないでください。** 再現用のテキストは必ずマスク／ダミー化して
  ください（`090-XXXX-XXXX` など）。

## 開発環境

Go があればビルド・テストできます。

```console
$ go build ./cmd/jp-pii-detect   # バイナリのビルド
$ go test ./...                  # 全テスト
$ go test -race ./...            # データ競合の検査（並列スキャンの回帰防止・必須）
$ go vet ./...                   # 静的解析
```

通常の単体・結合テストは `internal/testfixtures` の公開合成値だけで完結します。
実在しうる値を含む非公開評価コーパスは `$JP_PII_FIXTURES` で明示的に渡し、
precision / recall / F1 の計測にだけ使います。取得・一時実行・明示キャッシュの手順は
[docs/development.md](docs/development.md) を参照してください。

## 検出ルールの追加・変更

ルールの追加・変更手順は [docs/development.md](docs/development.md) のガイドを参照してください。

精度の回帰を防ぐため、CI には **`docs/accuracy.json` とのゼロ許容の差分ゲート** があります。
ルール・辞書・正規化を変更すると精度の実測値が動くため、その場合は
`JP_PII_FIXTURES=<path> go test ./internal/eval -run 'TestGenerateDoc|TestReadmeBadges' -update`
で `docs/accuracy.md` / `docs/accuracy.json` / README バッジを再生成し、まとめてコミットして
ください（CI が同じコマンドを実行して差分がないか検証します）。

## 検出結果が変わる変更のルール

**検出結果が変わる変更（ルール・辞書・正規化の変更）は、PR 説明とリリースノートに必ず明記**
してください。どのルールがどう変わり、既存利用者の検出結果にどう影響するかを記載します。

## 実 PII を貼らない

テストケース・issue・PR のいずれにも、採取した PII を含めないでください。公開テストでは
`internal/testfixtures`、予約済み値、公開された非個人属性だけを使い、生値を失敗ログへ出さないでください。

## Pull Request

PR を作成する前に、`go test -race ./...` が通ること、`./jp-pii-detect scan --format github .`
（dogfood スキャン）で検出 0 件であることを確認してください。詳細は
[Pull Request テンプレート](.github/PULL_REQUEST_TEMPLATE.md) を参照してください。
