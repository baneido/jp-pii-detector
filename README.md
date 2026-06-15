# jp-pii-detecter

![PII detection F1](https://img.shields.io/badge/PII検出_F1（評価データセット）-0.96-brightgreen)

日本特化の個人情報（PII）静的検出器。リポジトリに混入したマイナンバー・電話番号・住所などを
コミット前（git hook）や CI/CD（GitHub Actions）で検出します。

- **日本特化**: マイナンバー検査用数字の検証、全角・長音記号の正規化、和暦、JCB カードなどに対応
- **高速**: Go 製シングルバイナリ。pre-commit ではステージ済み差分の追加行のみを走査
- **CI フレンドリー**: 終了コード・JSON・SARIF・GitHub Actions アノテーション出力
- **二次漏えい防止**: 検出値は既定でマスク表示

## 対応している個人情報

精度の凡例 — **◎** 単体で高精度（チェックディジット等で誤検出が少ない） /
**○** 周辺の語（「TEL」「住所」など）と併用して実用的な精度 /
**△** ラベル付き（`氏名:` など）に限定して検出

「実測 F1」は同梱のラベル付き評価データセット（[internal/eval/dataset.go](internal/eval/dataset.go)）に対する
**F1 スコア**（適合率と再現率の調和平均）です。`go test ./internal/eval` で検証しており
（数値が動くと CI が落ちる）、内訳は [docs/accuracy.md](docs/accuracy.md) を参照してください。
評価データセットに対する値であり、あらゆる入力での精度を保証するものではありません。

| 種別 | 例（すべて架空のダミー） | 精度 | 実測 F1 | 検出の決め手 |
|---|---|:---:|:---:|---|
| マイナンバー（個人番号） | `1234-5678-9018` | ◎ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 12 桁 + 検査用数字（総務省令のアルゴリズム） |
| クレジットカード番号 | `4111-1111-1111-1111` | ◎ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | Luhn + ブランド判定（Visa/Master/JCB/Amex 等） |
| メールアドレス | `taro@example.jp` | ◎ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | パターン + IANA TLD 実在チェック + 予約ドメイン除外 |
| 電話番号 | `090-1234-5678` | ◎ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 携帯/IP/固定/+81 + 桁数検証 |
| 郵便番号 | `〒150-0043` | ◎ / ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 上位3桁の実在チェック。〒マーク付きは単独、なしは周辺の語が必要 |
| 住所 | `東京都渋谷区道玄坂2-10-7` | ○ | ![F1 0.89](https://img.shields.io/badge/F1-0.89-green) | 都道府県〜番地のパターン |
| 運転免許証番号 | `免許証番号: 305012345678` | ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 12 桁 + 周辺の語が必要 |
| 旅券（パスポート）番号 | `パスポート: TK1234567` | ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 英字2+数字7 + 周辺の語が必要 |
| 基礎年金番号 | `年金番号: 1234-567890` | ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 4桁-6桁 + 周辺の語が必要 |
| 在留カード番号 | `在留カード AB12345678CD` | ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 英2+数8+英2 + 周辺の語が必要 |
| 銀行口座番号 | `口座番号: 1234567` | △ | ![F1 0.86](https://img.shields.io/badge/F1-0.86-green) | 7 桁 + 周辺の語が必要 |
| 健康保険 保険者番号等 | `保険者番号: 12345678` | △ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 8 桁 + 周辺の語が必要 |
| 生年月日 | `生年月日: 1990年1月23日` | △ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | ラベル付き。西暦・和暦に対応 |
| 氏名 | `氏名: 山田 太郎` | △ | ![F1 0.75](https://img.shields.io/badge/F1-0.75-yellowgreen) | ラベル付き。**既定では非表示**（後述） |

> **既定の報告範囲**: 信頼度 `medium` 以上を報告します（`min_confidence` で変更可）。
> 氏名のような誤検出が出やすい項目は `low` 扱いで、既定では報告されません。
> 各検出は周辺キーワードの有無で `low` / `medium` / `high` に分かれます。キーワードが
> 検出の前提になっているルールでは昇格は起きず、ルール固有の信頼度
> （表の △ は `medium`、○ は `high`）で報告されます。

検出できる PII の種類と手法の詳細・設計判断は
[docs/detection-methods.md](docs/detection-methods.md) を参照してください。

## インストール

```console
$ go install github.com/baneido/jp-pii-detecter/cmd/jp-pii-detect@latest
```

## 使い方

```console
$ jp-pii-detect scan .                        # カレントディレクトリ以下をフルスキャン
$ jp-pii-detect scan --staged                 # ステージ済み変更の追加行のみ（pre-commit 用）
$ jp-pii-detect scan --diff origin/main...HEAD  # PR の追加行のみ（CI 用）
$ jp-pii-detect scan --high-recall .          # 偽陽性リスクを許容して再現率重視ルールも有効化
$ jp-pii-detect rules                         # 検出ルール一覧
```

出力例（検出値はマスクされます）:

```
users.csv:4:6   [high]  jp-phone-number 電話番号（携帯・固定・IP・国際表記）  09*********78
```

終了コード: `0` = 検出なし / `1` = 検出あり / `2` = エラー

ローカルで実際の値を確認したい場合は `--unmask` を付けます（CI では使わないでください）。

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
# 都道府県なし住所・担当者/敬称アンカー付き氏名など、偽陽性リスクの高い追加ルールを有効化
high_recall = false

[allowlist]
# 走査から除外するパス（正規表現）。フルスキャンでは走査時のパス表記に加えて
# リポジトリルートからの相対パスにも適用されるため、サブディレクトリから
# 実行しても ^testdata/ のようなルート相対の指定が機能します。
paths = ["^testdata/", "\\.lock$"]
# マッチ文字列に対する除外（正規表現）。例: 自社ドメインのメール
regexes = ["@baneido\\.com$"]
# 完全一致で除外するダミー値
stopwords = ["090-0000-0000"]
```

意図的なダミー値には行内コメントで ignore マーカーを付けられます:

```python
TEST_PHONE = "090-1234-5678"  # jp-pii-detector:ignore テスト用ダミー
```

旧マーカー `pii-allow` も互換性のため引き続き利用できます。

## ドキュメント

- [検出手法の調査と整理](docs/detection-methods.md) — 検出できる PII の種類・精度の根拠・
  チェックディジットや正規化の仕組み・対象外とした項目とその理由
- [検出精度（実測値）](docs/accuracy.md) — 評価データセットに対するルール別の適合率・再現率・F1
- [開発者向けガイド](docs/development.md) — ビルド・テスト・内部構成・検出ルールの追加方法
