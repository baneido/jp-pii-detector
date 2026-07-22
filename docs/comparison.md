# シークレット検出ツールとの比較と併用ガイド

`jp-pii-detect` は、gitleaks などの既存のシークレット検出ツールを**置き換えるものではありません**。
両者は目的が異なります。シークレットスキャナは API キーや認証情報の混入を防ぐためのもので、
日本語圏の個人情報（マイナンバー・住所・氏名など）は検出対象外です。逆に `jp-pii-detect` は
シークレットを検出しません。したがって正解は「どちらか一方」ではなく、**両方を併用する**ことです。
このドキュメントでは各ツールの守備範囲を整理し、併用の構成例を示します。

## 比較表

凡例：✅ 対応 / 部分的 = 限定的・設定や拡張が前提 / – = 対象外または非対応

| 項目 | jp-pii-detect | gitleaks | trufflehog | secretlint | detect-secrets | Microsoft Presidio |
|---|---|---|---|---|---|---|
| 主な検出対象 | 日本語 PII | シークレット | シークレット | シークレット | シークレット | 汎用 PII（多言語・NER 中心） |
| 日本語 PII（マイナンバー・住所・氏名等） | ✅ | – | – | – | – | 部分的（カスタムレコグナイザで拡張） |
| チェックディジット等の値検証 | ✅（マイナンバー検査用数字・Luhn） | – | ✅（クレデンシャルの実在検証・種類が異なる） | 部分的（プラグイン次第） | 部分的（エントロピー等） | 部分的（一部エンティティ） |
| 日本語正規化（全角・長音・和暦） | ✅ | – | – | – | – | – |
| 差分スキャン（`--staged` / `--diff`） | ✅ | ✅（git 連携） | ✅（git 履歴・差分） | 部分的 | 部分的（ステージ済みファイル） | –（ライブラリ/サービス） |
| ベースライン | ✅ | ✅ | 部分的（起点コミット指定等） | – | ✅（`.secrets.baseline`） | – |
| SARIF 出力 | ✅ | ✅ | – | ✅（SARIF フォーマッタ） | – | – |
| 配布形態 | 単一バイナリ（Go） | 単一バイナリ（Go） | 単一バイナリ（Go） | Node.js | Python | Python（ライブラリ/サービス） |
| pre-commit 対応 | ✅ | ✅ | ✅ | ✅ | ✅ | – |

各ツールの詳細な仕様は、それぞれの公式ドキュメントを参照してください。上表は「日本語 PII 検出」という
観点からの整理であり、シークレット検出の網羅性や検証精度を比較するものではありません。

### Presidio との連携

Microsoft Presidio は多言語対応の汎用 PII 検出フレームワークで、カスタムレコグナイザによる拡張を
前提としています。本リポジトリには Presidio 向けのアダプタ（[integrations/presidio/](../integrations/presidio/)）が
含まれており、`jp-pii-detect` の日本特化ルールを Presidio のパイプラインから利用できます。既に Presidio を
運用している場合は、この組み合わせで日本語 PII の検出を補強できます。

## 併用構成例

### pre-commit（gitleaks と jp-pii-detect を並べる）

同じ `.pre-commit-config.yaml` にシークレットスキャナと `jp-pii-detect` を並べれば、
コミット前にシークレットと日本語 PII の両方をチェックできます。

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
  - repo: https://github.com/baneido/jp-pii-detector
    rev: v0.4.3
    hooks:
      - id: jp-pii-detect
```

### GitHub Actions（両方を走らせる）

```yaml
name: security-scan
on: pull_request

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2

  pii-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: baneido/jp-pii-detector@v0.4.3
        with:
          # jp-pii-detect のバイナリ版を固定
          version: v0.4.3
          args: scan --diff origin/${{ github.base_ref }}...HEAD --format github
```

## jp-pii-detect がやらないこと

期待値を正しく持っていただくため、`jp-pii-detect` の対象外を明記します。

- **シークレットの検出**: API キー、アクセストークン、パスワード、秘密鍵などは検出しません。
  これらは gitleaks / trufflehog / secretlint / detect-secrets などの専用ツールを併用してください。
- **非日本語圏の PII**: 日本固有の番号体系・住所・氏名を対象としており、海外の SSN や各国固有の
  識別子などは検出対象外です。多言語の汎用 PII 検出が必要な場合は Presidio 等を検討してください。
