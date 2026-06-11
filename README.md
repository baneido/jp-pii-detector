# jp-pii-detecter

日本特化の個人情報（PII）静的検出器。リポジトリに混入したマイナンバー・電話番号・住所などを
コミット前（git hook）や CI/CD（GitHub Actions）で検出します。

- **日本特化**: マイナンバー検査用数字の検証、全角・長音記号の正規化、和暦、JCB カードなどに対応
- **高速**: Go 製シングルバイナリ。pre-commit ではステージ済み差分の追加行のみを走査
- **CI フレンドリー**: 終了コード・JSON・SARIF・GitHub Actions アノテーション出力
- **二次漏えい防止**: 検出値は既定でマスク表示

検出できる PII の種類と手法の調査・整理は [docs/detection-methods.md](docs/detection-methods.md) を参照してください。

## インストール

```console
$ go install github.com/baneido/jp-pii-detecter/cmd/jp-pii-detect@latest
```

## 使い方

```console
$ jp-pii-detect scan .                        # カレントディレクトリ以下をフルスキャン
$ jp-pii-detect scan --staged                 # ステージ済み変更の追加行のみ（pre-commit 用）
$ jp-pii-detect scan --diff origin/main...HEAD  # PR の追加行のみ（CI 用）
$ jp-pii-detect rules                         # 検出ルール一覧
```

出力例（検出値はマスクされます）:

```
users.csv:4:6   [high]  jp-phone-number 電話番号（携帯・固定・IP・国際表記）  09*********78
```

終了コード: `0` = 検出なし / `1` = 検出あり / `2` = エラー

## git commit hook での利用

### pre-commit フレームワーク

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/baneido/jp-pii-detecter
    rev: v0.1.0
    hooks:
      - id: jp-pii-detect
```

### 素の git hook

`.git/hooks/pre-commit`:

```sh
#!/bin/sh
exec jp-pii-detect scan --staged
```

## GitHub Actions での利用

```yaml
name: pii-check
on: pull_request

jobs:
  pii-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: baneido/jp-pii-detecter@main
        with:
          args: scan --diff origin/${{ github.base_ref }}...HEAD --format github
```

`--format github` を指定すると、検出箇所が PR の該当行にアノテーション表示されます。
`--format sarif` の出力は GitHub Code Scanning に取り込めます。

## 設定（.jp-pii.toml）

リポジトリルートに `.jp-pii.toml` を置くと自動で読み込まれます（`--config` で明示指定も可能）。

```toml
# 報告する最小信頼度: low | medium | high（既定: medium）
min_confidence = "medium"

[rules]
# 無効化するルール ID（`jp-pii-detect rules` で一覧表示）
disabled = ["person-name"]

[allowlist]
# 走査から除外するパス（正規表現）
paths = ["^testdata/", "\\.lock$"]
# マッチ文字列に対する除外（正規表現）。例: 自社ドメインのメール
regexes = ["@baneido\\.com$"]
# 完全一致で除外するダミー値
stopwords = ["090-0000-0000"]
```

意図的なダミー値には行内コメントでマーカーを付けられます:

```python
TEST_PHONE = "090-1234-5678"  # pii-allow テスト用ダミー
```

## 検出ルール

| ルール ID | 対象 | 手法 |
|---|---|---|
| `jp-my-number` | マイナンバー（個人番号） | 12 桁 + 検査用数字検証（総務省令のアルゴリズム） |
| `jp-phone-number` | 電話番号 | 携帯/IP/固定/+81 表記 + 桁数検証 |
| `jp-postal-code` | 郵便番号 | 〒マーク or コンテキスト |
| `jp-address` | 住所 | 都道府県〜番地のパターン |
| `email-address` | メールアドレス | パターン + 予約ドメイン除外 |
| `credit-card` | クレジットカード番号 | Luhn + ブランドプレフィックス（JCB 対応） |
| `jp-drivers-license` | 運転免許証番号 | 12 桁 + コンテキスト必須 |
| `jp-passport` | 旅券番号 | パターン + コンテキスト必須 |
| `jp-pension-number` | 基礎年金番号 | パターン + コンテキスト必須 |
| `jp-residence-card` | 在留カード番号 | パターン + コンテキスト必須 |
| `jp-bank-account` | 銀行口座番号 | 7 桁 + コンテキスト必須 |
| `jp-health-insurance` | 健康保険 保険者番号等 | 8 桁 + コンテキスト必須 |
| `person-name` | 氏名（ラベル付き） | `氏名:` 等のラベル。信頼度 low（既定では非表示） |
| `jp-birthdate` | 生年月日（ラベル付き） | 西暦・和暦 |

## 開発

```console
$ go test ./...
$ go build ./cmd/jp-pii-detect
```
