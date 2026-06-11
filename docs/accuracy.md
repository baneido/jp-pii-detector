# 検出精度（評価データセットに対する実測値）

`internal/eval` のラベル付き評価データセットに対して計測した、検出ルールごとの
適合率（precision）・再現率（recall）・F1 スコアです。`go test ./internal/eval` で
検証され（[eval_test.go](../internal/eval/eval_test.go)）、`-update` で本ファイルを再生成します。

> この数値は同梱の評価データセット（陽性・陰性の代表例と、実運用での限界を表す難ケース）に
> 対する値であり、あらゆる入力での精度を保証するものではありません。データセットは
> [internal/eval/dataset.go](../internal/eval/dataset.go) にあります。

| ルール ID | F1 | 適合率 | 再現率 | TP | FP | FN |
|---|:--:|:--:|:--:|--:|--:|--:|
| `credit-card` | 1.00 | 1.00 | 1.00 | 4 | 0 | 0 |
| `email-address` | 1.00 | 1.00 | 1.00 | 4 | 0 | 0 |
| `jp-residence-card` | 1.00 | 1.00 | 1.00 | 2 | 0 | 0 |
| `jp-birthdate` | 1.00 | 1.00 | 1.00 | 3 | 0 | 0 |
| `jp-postal-code` | 1.00 | 1.00 | 1.00 | 3 | 0 | 0 |
| `jp-phone-number` | 1.00 | 1.00 | 1.00 | 7 | 0 | 0 |
| `jp-my-number` | 1.00 | 1.00 | 1.00 | 5 | 0 | 0 |
| `jp-passport` | 1.00 | 1.00 | 1.00 | 2 | 0 | 0 |
| `jp-address` | 0.89 | 1.00 | 0.80 | 4 | 0 | 1 |
| `jp-pension-number` | 0.80 | 0.67 | 1.00 | 2 | 1 | 0 |
| `jp-health-insurance` | 0.80 | 0.67 | 1.00 | 2 | 1 | 0 |
| `jp-drivers-license` | 0.80 | 0.67 | 1.00 | 2 | 1 | 0 |
| `person-name` | 0.75 | 0.60 | 1.00 | 3 | 2 | 0 |
| `jp-bank-account` | 0.67 | 0.67 | 0.67 | 2 | 1 | 1 |
| **全体（マイクロ平均）** | **0.92** | **0.88** | **0.96** | 45 | 6 | 2 |
