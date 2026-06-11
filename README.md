# jp-pii-detecter

![PII detection F1](https://img.shields.io/badge/PII検出_F1（評価データセット）-0.92-green)

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

リポジトリルートに `.jp-pii.toml` を置くと自動で読み込まれます。探索はカレントディレクトリから
親方向にリポジトリルート（`.git` のあるディレクトリ）まで行うため、サブディレクトリからの実行でも
ルートの設定が使われます（`--config` で明示指定も可能）。

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

「検出精度」は同梱のラベル付き評価データセット（[internal/eval/dataset.go](internal/eval/dataset.go)）に対する
**F1 スコア**（適合率と再現率の調和平均）です。`go test ./internal/eval` で検証しており
（数値が動くと CI が落ちる）、内訳は [docs/accuracy.md](docs/accuracy.md) を参照してください。
評価データセットに対する値であり、あらゆる入力での精度を保証するものではありません。

| ルール ID | 対象 | 手法 | 検出精度（F1） |
|---|---|---|:--:|
| `jp-my-number` | マイナンバー（個人番号） | 12 桁 + 検査用数字検証（総務省令のアルゴリズム） | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) |
| `jp-phone-number` | 電話番号 | 携帯/IP/固定/+81 表記 + 桁数検証 | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) |
| `jp-postal-code` | 郵便番号 | 〒マーク or コンテキスト | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) |
| `jp-address` | 住所 | 都道府県〜番地のパターン | ![F1 0.89](https://img.shields.io/badge/F1-0.89-green) |
| `email-address` | メールアドレス | パターン + 予約ドメイン除外 | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) |
| `credit-card` | クレジットカード番号 | Luhn + ブランドプレフィックス（JCB 対応） | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) |
| `jp-drivers-license` | 運転免許証番号 | 12 桁 + コンテキスト必須 | ![F1 0.80](https://img.shields.io/badge/F1-0.80-yellowgreen) |
| `jp-passport` | 旅券番号 | パターン + コンテキスト必須 | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) |
| `jp-pension-number` | 基礎年金番号 | パターン + コンテキスト必須 | ![F1 0.80](https://img.shields.io/badge/F1-0.80-yellowgreen) |
| `jp-residence-card` | 在留カード番号 | パターン + コンテキスト必須 | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) |
| `jp-bank-account` | 銀行口座番号 | 7 桁 + コンテキスト必須 | ![F1 0.67](https://img.shields.io/badge/F1-0.67-yellow) |
| `jp-health-insurance` | 健康保険 保険者番号等 | 8 桁 + コンテキスト必須 | ![F1 0.80](https://img.shields.io/badge/F1-0.80-yellowgreen) |
| `person-name` | 氏名（ラベル付き） | `氏名:` 等のラベル。信頼度 low（既定では非表示） | ![F1 0.75](https://img.shields.io/badge/F1-0.75-yellowgreen) |
| `jp-birthdate` | 生年月日（ラベル付き） | 西暦・和暦 | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) |

## 開発

```console
$ go test ./...                  # 全テスト（検出精度の回帰ガードを含む）
$ go build ./cmd/jp-pii-detect
```

検出精度は [internal/eval](internal/eval) のラベル付きデータセットで計測しています。
`go test ./internal/eval` が実測 F1 と README バッジの一致を検証するため、ルール変更で
精度が動くと CI が落ちます。内訳ドキュメントは次のコマンドで再生成します:

```console
$ go test ./internal/eval -run TestGenerateDoc -update   # docs/accuracy.md を更新
```
