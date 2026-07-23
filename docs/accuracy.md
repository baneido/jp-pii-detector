# 検出精度（評価データセットに対する実測値）

`internal/eval` のラベル付き評価データセットに対して計測した、検出ルールごとの
適合率（precision）、再現率（recall）、F1 スコアです。`JP_PII_FIXTURES` を設定して
`go test ./internal/eval` で検証され（[eval_test.go](../internal/eval/eval_test.go)）、
`-update` で本ファイルを再生成します。

評価コーパスID: `private-eval-v2`（生データのハッシュや本文は公開しません）。

設定の異なるF1を混同しないよう、rule capability（low）、default operational（medium）、
high recall operationalの3プロファイルを別々に計測・CIゲートします。READMEバッジは
利用者の既定運用に対応するmediumプロファイルです。評価ケースは単一行（`line`）に加え、
複数行入力（`content`）と diff hunk（`diff`: 追加行のみを報告）も表現できます。

> この数値は、実在しうる PII を含むためリポジトリ外で管理する評価データセット
> （陽性と陰性の代表例と、実運用での限界を表す難ケース）に対する値であり、あらゆる
> 入力での精度を保証するものではありません。データセットの取得方法は
> [docs/development.md](../docs/development.md) を参照してください。

## Confidence スコアの校正

内部スコアは `low=0-39`、`medium=40-74`、`high=75-100` へ固定写像します。段階導入では既存 Confidence の帯域を越えないため、公開 JSON/SARIF と `min_confidence` の挙動は維持され、同一 Confidence の overlap だけを score で決着します。

後方互換段階の受け入れ基準は finding 単位の実測適合率で **High 97.5%以上、Medium 92%以上** です。少数標本の不確実性を隠さないため Wilson 95% 信頼区間下限も併記しますが、現時点の CI gate は実測適合率を対象とし、下限値は標本拡充の判断材料とします。issue で例示された High 99.5% / Medium 95% は stretch target として維持しますが、現行 Confidence を変更せずに満たせないことを v2 実測で確認したため、この段階の gate にはしません。

### low

| Confidence | TP | FP | 実測適合率 | Wilson 95%下限 | 基準 |
|---|--:|--:|--:|--:|:--:|
| `high` | 149 | 1 | 99.33% | 96.32% | PASS（≥97.5%） |
| `medium` | 110 | 0 | 100.00% | 96.63% | PASS（≥92.0%） |

### medium

| Confidence | TP | FP | 実測適合率 | Wilson 95%下限 | 基準 |
|---|--:|--:|--:|--:|:--:|
| `high` | 149 | 1 | 99.33% | 96.32% | PASS（≥97.5%） |
| `medium` | 110 | 0 | 100.00% | 96.63% | PASS（≥92.0%） |

### high-recall

| Confidence | TP | FP | 実測適合率 | Wilson 95%下限 | 基準 |
|---|--:|--:|--:|--:|:--:|
| `high` | 180 | 1 | 99.45% | 96.94% | PASS（≥97.5%） |
| `medium` | 145 | 0 | 100.00% | 97.42% | PASS（≥92.0%） |

## プロファイル: low

rule capability（min_confidence=low、高再現率ルール無効）。

| ルール ID | F1 | 適合率 | 再現率 | TP | FP | FN | Finding FP | Confidence miss |
|---|:--:|:--:|:--:|--:|--:|--:|--:|--:|
| `credit-card` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `email-address` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-birthdate` | 1.00 | 1.00 | 1.00 | 13 | 0 | 0 | 0 | 0 |
| `jp-drivers-license` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `jp-employment-insurance` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `jp-health-insurance` | 1.00 | 1.00 | 1.00 | 14 | 0 | 0 | 0 | 0 |
| `jp-invoice-number` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `jp-juminhyo-code` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `jp-kaigo-insurance` | 1.00 | 1.00 | 1.00 | 14 | 0 | 0 | 0 | 0 |
| `jp-my-number` | 1.00 | 1.00 | 1.00 | 14 | 0 | 0 | 0 | 0 |
| `jp-pension-number` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `jp-phone-number` | 1.00 | 1.00 | 1.00 | 17 | 0 | 0 | 0 | 0 |
| `jp-postal-code` | 1.00 | 1.00 | 1.00 | 15 | 0 | 0 | 0 | 0 |
| `jp-residence-card` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `person-name` | 1.00 | 1.00 | 1.00 | 19 | 0 | 0 | 0 | 0 |
| `jp-address` | 0.98 | 1.00 | 0.96 | 22 | 0 | 1 | 0 | 0 |
| `jp-bank-account` | 0.97 | 1.00 | 0.94 | 16 | 0 | 1 | 0 | 0 |
| `jp-passport` | 0.96 | 0.92 | 1.00 | 12 | 1 | 0 | 1 | 0 |
| `jp-yucho-account` | 0.58 | 1.00 | 0.41 | 7 | 0 | 10 | 0 | 0 |
| **全体（マイクロ平均）** | **0.98** | **1.00** | **0.96** | 255 | 1 | 12 | 1 | 0 |

陰性ケース母数: 136。

### スパン評価

exactは完全一致、containmentは検出が期待値全体を含む場合、relaxedは一部でも重なる場合です。

| ルール ID | exact F1 | containment F1 | relaxed F1 | exact TP/FP/FN | containment TP/FP/FN | relaxed TP/FP/FN |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| `credit-card` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `email-address` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-birthdate` | 1.00 | 1.00 | 1.00 | 13/0/0 | 13/0/0 | 13/0/0 |
| `jp-drivers-license` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-employment-insurance` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-health-insurance` | 1.00 | 1.00 | 1.00 | 14/0/0 | 14/0/0 | 14/0/0 |
| `jp-invoice-number` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-juminhyo-code` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-kaigo-insurance` | 1.00 | 1.00 | 1.00 | 14/0/0 | 14/0/0 | 14/0/0 |
| `jp-my-number` | 1.00 | 1.00 | 1.00 | 14/0/0 | 14/0/0 | 14/0/0 |
| `jp-pension-number` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-phone-number` | 1.00 | 1.00 | 1.00 | 18/0/0 | 18/0/0 | 18/0/0 |
| `jp-postal-code` | 1.00 | 1.00 | 1.00 | 15/0/0 | 15/0/0 | 15/0/0 |
| `jp-residence-card` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `person-name` | 1.00 | 1.00 | 1.00 | 19/0/0 | 19/0/0 | 19/0/0 |
| `jp-address` | 0.98 | 0.98 | 0.98 | 22/0/1 | 22/0/1 | 22/0/1 |
| `jp-bank-account` | 0.97 | 0.97 | 0.97 | 16/0/1 | 16/0/1 | 16/0/1 |
| `jp-passport` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-yucho-account` | 0.67 | 0.67 | 0.67 | 10/0/10 | 10/0/10 | 10/0/10 |
| **全体（マイクロ平均）** | **0.98** | **0.98** | **0.98** | 259/0/12 | 259/0/12 | 259/0/12 |

マクロ平均F1: exact 0.98 / containment 0.98 / relaxed 0.98。
## プロファイル: medium

default operational（min_confidence=medium、高再現率ルール無効）。

| ルール ID | F1 | 適合率 | 再現率 | TP | FP | FN | Finding FP | Confidence miss |
|---|:--:|:--:|:--:|--:|--:|--:|--:|--:|
| `credit-card` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `email-address` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-birthdate` | 1.00 | 1.00 | 1.00 | 13 | 0 | 0 | 0 | 0 |
| `jp-drivers-license` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `jp-employment-insurance` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `jp-health-insurance` | 1.00 | 1.00 | 1.00 | 14 | 0 | 0 | 0 | 0 |
| `jp-invoice-number` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `jp-juminhyo-code` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `jp-kaigo-insurance` | 1.00 | 1.00 | 1.00 | 14 | 0 | 0 | 0 | 0 |
| `jp-my-number` | 1.00 | 1.00 | 1.00 | 14 | 0 | 0 | 0 | 0 |
| `jp-pension-number` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `jp-phone-number` | 1.00 | 1.00 | 1.00 | 17 | 0 | 0 | 0 | 0 |
| `jp-postal-code` | 1.00 | 1.00 | 1.00 | 15 | 0 | 0 | 0 | 0 |
| `jp-residence-card` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `person-name` | 1.00 | 1.00 | 1.00 | 19 | 0 | 0 | 0 | 0 |
| `jp-address` | 0.98 | 1.00 | 0.96 | 22 | 0 | 1 | 0 | 0 |
| `jp-bank-account` | 0.97 | 1.00 | 0.94 | 16 | 0 | 1 | 0 | 0 |
| `jp-passport` | 0.96 | 0.92 | 1.00 | 12 | 1 | 0 | 1 | 0 |
| `jp-yucho-account` | 0.58 | 1.00 | 0.41 | 7 | 0 | 10 | 0 | 0 |
| **全体（マイクロ平均）** | **0.98** | **1.00** | **0.96** | 255 | 1 | 12 | 1 | 0 |

陰性ケース母数: 136。

### スパン評価

exactは完全一致、containmentは検出が期待値全体を含む場合、relaxedは一部でも重なる場合です。

| ルール ID | exact F1 | containment F1 | relaxed F1 | exact TP/FP/FN | containment TP/FP/FN | relaxed TP/FP/FN |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| `credit-card` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `email-address` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-birthdate` | 1.00 | 1.00 | 1.00 | 13/0/0 | 13/0/0 | 13/0/0 |
| `jp-drivers-license` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-employment-insurance` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-health-insurance` | 1.00 | 1.00 | 1.00 | 14/0/0 | 14/0/0 | 14/0/0 |
| `jp-invoice-number` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-juminhyo-code` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-kaigo-insurance` | 1.00 | 1.00 | 1.00 | 14/0/0 | 14/0/0 | 14/0/0 |
| `jp-my-number` | 1.00 | 1.00 | 1.00 | 14/0/0 | 14/0/0 | 14/0/0 |
| `jp-pension-number` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-phone-number` | 1.00 | 1.00 | 1.00 | 18/0/0 | 18/0/0 | 18/0/0 |
| `jp-postal-code` | 1.00 | 1.00 | 1.00 | 15/0/0 | 15/0/0 | 15/0/0 |
| `jp-residence-card` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `person-name` | 1.00 | 1.00 | 1.00 | 19/0/0 | 19/0/0 | 19/0/0 |
| `jp-address` | 0.98 | 0.98 | 0.98 | 22/0/1 | 22/0/1 | 22/0/1 |
| `jp-bank-account` | 0.97 | 0.97 | 0.97 | 16/0/1 | 16/0/1 | 16/0/1 |
| `jp-passport` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-yucho-account` | 0.67 | 0.67 | 0.67 | 10/0/10 | 10/0/10 | 10/0/10 |
| **全体（マイクロ平均）** | **0.98** | **0.98** | **0.98** | 259/0/12 | 259/0/12 | 259/0/12 |

マクロ平均F1: exact 0.98 / containment 0.98 / relaxed 0.98。
## プロファイル: high-recall

high recall operational（min_confidence=medium、高再現率ルール有効）。

| ルール ID | F1 | 適合率 | 再現率 | TP | FP | FN | Finding FP | Confidence miss |
|---|:--:|:--:|:--:|--:|--:|--:|--:|--:|
| `credit-card` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `email-address` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `email-address-confusable` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `email-address-eai` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-birthdate` | 1.00 | 1.00 | 1.00 | 13 | 0 | 0 | 0 | 0 |
| `jp-drivers-license` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `jp-employment-insurance` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `jp-health-insurance` | 1.00 | 1.00 | 1.00 | 14 | 0 | 0 | 0 | 0 |
| `jp-invoice-number` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `jp-juminhyo-code` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `jp-kaigo-insurance` | 1.00 | 1.00 | 1.00 | 14 | 0 | 0 | 0 | 0 |
| `jp-my-number` | 1.00 | 1.00 | 1.00 | 14 | 0 | 0 | 0 | 0 |
| `jp-pension-number` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `jp-phone-number` | 1.00 | 1.00 | 1.00 | 17 | 0 | 0 | 0 | 0 |
| `jp-postal-code` | 1.00 | 1.00 | 1.00 | 15 | 0 | 0 | 0 | 0 |
| `jp-residence-card` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 | 0 | 0 |
| `person-name` | 1.00 | 1.00 | 1.00 | 19 | 0 | 0 | 0 | 0 |
| `person-name-high-recall` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `person-name-romaji` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `person-name-structured` | 1.00 | 1.00 | 1.00 | 15 | 0 | 0 | 0 | 0 |
| `jp-address` | 0.98 | 1.00 | 0.96 | 22 | 0 | 1 | 0 | 0 |
| `jp-bank-account` | 0.97 | 1.00 | 0.94 | 16 | 0 | 1 | 0 | 0 |
| `jp-passport` | 0.96 | 0.92 | 1.00 | 12 | 1 | 0 | 1 | 0 |
| `jp-address-high-recall` | 0.95 | 0.91 | 1.00 | 10 | 1 | 0 | 1 | 0 |
| `jp-yucho-account` | 0.58 | 1.00 | 0.41 | 7 | 0 | 10 | 0 | 0 |
| **全体（マイクロ平均）** | **0.98** | **0.99** | **0.96** | 320 | 2 | 12 | 2 | 0 |

陰性ケース母数: 136。

### スパン評価

exactは完全一致、containmentは検出が期待値全体を含む場合、relaxedは一部でも重なる場合です。

| ルール ID | exact F1 | containment F1 | relaxed F1 | exact TP/FP/FN | containment TP/FP/FN | relaxed TP/FP/FN |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| `credit-card` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `email-address` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `email-address-confusable` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `email-address-eai` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-birthdate` | 1.00 | 1.00 | 1.00 | 13/0/0 | 13/0/0 | 13/0/0 |
| `jp-drivers-license` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-employment-insurance` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-health-insurance` | 1.00 | 1.00 | 1.00 | 14/0/0 | 14/0/0 | 14/0/0 |
| `jp-invoice-number` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-juminhyo-code` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-kaigo-insurance` | 1.00 | 1.00 | 1.00 | 14/0/0 | 14/0/0 | 14/0/0 |
| `jp-my-number` | 1.00 | 1.00 | 1.00 | 14/0/0 | 14/0/0 | 14/0/0 |
| `jp-pension-number` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-phone-number` | 1.00 | 1.00 | 1.00 | 18/0/0 | 18/0/0 | 18/0/0 |
| `jp-postal-code` | 1.00 | 1.00 | 1.00 | 15/0/0 | 15/0/0 | 15/0/0 |
| `jp-residence-card` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `person-name` | 1.00 | 1.00 | 1.00 | 19/0/0 | 19/0/0 | 19/0/0 |
| `person-name-high-recall` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `person-name-romaji` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `person-name-structured` | 1.00 | 1.00 | 1.00 | 15/0/0 | 15/0/0 | 15/0/0 |
| `jp-address` | 0.98 | 0.98 | 0.98 | 22/0/1 | 22/0/1 | 22/0/1 |
| `jp-bank-account` | 0.97 | 0.97 | 0.97 | 16/0/1 | 16/0/1 | 16/0/1 |
| `jp-passport` | 1.00 | 1.00 | 1.00 | 12/0/0 | 12/0/0 | 12/0/0 |
| `jp-address-high-recall` | 0.95 | 0.95 | 0.95 | 10/1/0 | 10/1/0 | 10/1/0 |
| `jp-yucho-account` | 0.67 | 0.67 | 0.67 | 10/0/10 | 10/0/10 | 10/0/10 |
| **全体（マイクロ平均）** | **0.98** | **0.98** | **0.98** | 324/1/12 | 324/1/12 | 324/1/12 |

マクロ平均F1: exact 0.98 / containment 0.98 / relaxed 0.98。

## データセットの統計（匿名）

評価データセットはリポジトリ外（GCS）で管理され、レビュー時に中身が見えないため、
PII やケース本文を含まない件数だけの統計をここに記録します。

- 総ケース数: 462
- 陽性ケース数: 326（うちスパン付与 326 件、付与率 100%）
- 陰性ケース数: 136

### 入力種別別ケース数

| 区分 | ケース数 |
|---|--:|
| `content` | 46 |
| `diff` | 1 |
| `line` | 415 |

### ファイル形式別ケース数

| 区分 | ケース数 |
|---|--:|
| `csv` | 11 |
| `json` | 9 |
| `sql` | 8 |
| `txt` | 5 |
| `unspecified` | 424 |
| `yaml` | 5 |

### source class別ケース数

| 区分 | ケース数 |
|---|--:|
| `curated-v2` | 268 |
| `hard-negative` | 62 |
| `legacy-curated` | 132 |

### ルール別陽性件数

| ルール ID | 陽性ケース数 |
|---|--:|
| `credit-card` | 10 |
| `email-address` | 10 |
| `email-address-confusable` | 10 |
| `email-address-eai` | 10 |
| `jp-address` | 23 |
| `jp-address-high-recall` | 10 |
| `jp-bank-account` | 17 |
| `jp-birthdate` | 13 |
| `jp-drivers-license` | 12 |
| `jp-employment-insurance` | 12 |
| `jp-health-insurance` | 14 |
| `jp-invoice-number` | 12 |
| `jp-juminhyo-code` | 12 |
| `jp-kaigo-insurance` | 14 |
| `jp-my-number` | 14 |
| `jp-passport` | 12 |
| `jp-pension-number` | 12 |
| `jp-phone-number` | 17 |
| `jp-postal-code` | 15 |
| `jp-residence-card` | 12 |
| `jp-yucho-account` | 17 |
| `person-name` | 19 |
| `person-name-high-recall` | 10 |
| `person-name-romaji` | 10 |
| `person-name-structured` | 15 |

## ケース種別別（medium）

評価ケースの入力形式（line/content/diff）別の内訳です。行レベル（Result.TP 等と同じ定義）のTP/FP/FN で、1 ケースに複数ルールの期待・検出があれば同じ種別へ合算します。

| ケース種別 | F1 | 適合率 | 再現率 | TP | FP | FN |
|---|:--:|:--:|:--:|--:|--:|--:|
| `line` | 0.97 | 1.00 | 0.95 | 229 | 1 | 12 |
| `content` | 1.00 | 1.00 | 1.00 | 25 | 0 | 0 |
| `diff` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| **全体（マイクロ平均）** | **0.98** | **1.00** | **0.96** | 255 | 1 | 12 |

## タグ別（表記ゆれ等）

評価ケースの `Case.Tags`（表記ゆれ・ラベル語彙・合成データ由来などのメタデータ。語彙は [docs/development.md](../docs/development.md) を参照）別の内訳です。タグ未設定のケースは含まれません。

| タグ | F1 | 適合率 | 再現率 | TP | FP | FN |
|---|:--:|:--:|:--:|--:|--:|--:|
| `brand:jcb` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `brand:mastercard` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `brand:visa` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `file-format:csv` | 1.00 | 1.00 | 1.00 | 6 | 0 | 0 |
| `file-format:json` | 1.00 | 1.00 | 1.00 | 3 | 0 | 0 |
| `file-format:sql` | 1.00 | 1.00 | 1.00 | 4 | 0 | 0 |
| `file-format:yaml` | 1.00 | 1.00 | 1.00 | 4 | 0 | 0 |
| `format:json` | 1.00 | 1.00 | 1.00 | 2 | 0 | 0 |
| `label:chokin` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `label:colon` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `label:counter-ken` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `label:currency-suffix` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `label:currency-yen` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `label:hihokensha-sho` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `label:invoice` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `label:jp-alt` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `label:kigou-bangou` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `label:last-first` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `label:numbering-build` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `label:numbering-denpyo` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `label:numbering-serial` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `label:numbering-version` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `label:space` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `label:surname-first-name-mixed` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `label:surname-given` | 1.00 | 1.00 | 1.00 | 3 | 0 | 0 |
| `label:touroku-bangou` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `label:tsuucho` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `label:youkaigo` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `layout:content` | 1.00 | 1.00 | 1.00 | 20 | 0 | 0 |
| `layout:cross-line-pair` | 1.00 | 1.00 | 1.00 | 5 | 0 | 0 |
| `layout:diff` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `layout:line` | 0.97 | 1.00 | 0.95 | 172 | 0 | 10 |
| `layout:single-line` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `notation:10digit` | 1.00 | 1.00 | 1.00 | 2 | 0 | 0 |
| `notation:11digit` | 1.00 | 1.00 | 1.00 | 3 | 0 | 0 |
| `notation:3-4` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:4-4-4` | 1.00 | 1.00 | 1.00 | 3 | 0 | 0 |
| `notation:4-6` | 1.00 | 1.00 | 1.00 | 2 | 0 | 0 |
| `notation:4-6-1` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:6digit-kokuho` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:8digit` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:bankcode-4-3-7` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:bankname-branch-futsu` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:cyrillic` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `notation:digits8` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:field-inline` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:field-multiline` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:fullwidth` | 1.00 | 1.00 | 1.00 | 2 | 0 | 0 |
| `notation:greek` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `notation:hiragana` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `notation:hyphen-reissue` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:intl-81` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:kanji` | 1.00 | 1.00 | 1.00 | 4 | 0 | 0 |
| `notation:kanji-banchi` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:kanji-digit` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `notation:kanji-kana` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `notation:katakana` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `notation:label-no-mark` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:label-no-prefecture` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:lowercase` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:lowercase-space` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:mixed-cyrillic-greek` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `notation:multiline-pair` | 1.00 | 1.00 | 1.00 | 2 | 0 | 0 |
| `notation:nonexistent-code` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `notation:nonexistent-municipality` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `notation:parens-areacode` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:quoted-json` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:space-separated` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:uppercase` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:uppercase-nospace` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:wareki-abbrev-reiwa` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:wareki-showa` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `notation:with-building` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `polarity:negative` | 0.00 | 0.00 | 0.00 | 0 | 1 | 0 |
| `polarity:positive` | 0.98 | 1.00 | 0.95 | 198 | 0 | 10 |
| `rule:credit-card` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 |
| `rule:email-address` | 1.00 | 1.00 | 1.00 | 6 | 0 | 0 |
| `rule:email-address-confusable` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `rule:email-address-eai` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `rule:jp-address` | 1.00 | 1.00 | 1.00 | 8 | 0 | 0 |
| `rule:jp-address-high-recall` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 |
| `rule:jp-bank-account` | 1.00 | 1.00 | 1.00 | 13 | 0 | 0 |
| `rule:jp-birthdate` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 |
| `rule:jp-drivers-license` | 1.00 | 1.00 | 1.00 | 9 | 0 | 0 |
| `rule:jp-employment-insurance` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 |
| `rule:jp-health-insurance` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 |
| `rule:jp-invoice-number` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 |
| `rule:jp-juminhyo-code` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 |
| `rule:jp-kaigo-insurance` | 1.00 | 1.00 | 1.00 | 14 | 0 | 0 |
| `rule:jp-my-number` | 1.00 | 1.00 | 1.00 | 9 | 0 | 0 |
| `rule:jp-passport` | 1.00 | 1.00 | 1.00 | 9 | 0 | 0 |
| `rule:jp-pension-number` | 1.00 | 1.00 | 1.00 | 9 | 0 | 0 |
| `rule:jp-phone-number` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 |
| `rule:jp-postal-code` | 1.00 | 1.00 | 1.00 | 12 | 0 | 0 |
| `rule:jp-residence-card` | 1.00 | 1.00 | 1.00 | 9 | 0 | 0 |
| `rule:jp-yucho-account` | 0.58 | 1.00 | 0.41 | 7 | 0 | 10 |
| `rule:person-name` | 1.00 | 1.00 | 1.00 | 5 | 0 | 0 |
| `rule:person-name-high-recall` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `rule:person-name-romaji` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `rule:person-name-structured` | 1.00 | 1.00 | 1.00 | 5 | 0 | 0 |
| `scenario:csv-column-context` | 1.00 | 1.00 | 1.00 | 6 | 0 | 0 |
| `scenario:csv-column-context-negative` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:domain-japanese` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-account-like` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-address-like` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-business-id` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-count` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-date` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-insurance-like` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-invoice-like` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-lot` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-model` | 0.00 | 0.00 | 0.00 | 0 | 1 | 0 |
| `scenario:hard-negative-money` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-name-like` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-phone-like` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-postal-like` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-reserved-email` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-revision` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-test-pan` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:homoglyph-domain` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:homoglyph-local` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:homoglyph-multi` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:homoglyph-tld` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hyphen-reissue-checksum-invalid` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:json-object-scope` | 1.00 | 1.00 | 1.00 | 2 | 0 | 0 |
| `scenario:known-test-pan` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:local-and-domain-japanese` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:local-japanese` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:multiline-pair-checksum-invalid` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:out-of-dictionary` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:placeholder-surname` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:reissue-division-two-digit` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:reserved-domain` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:reserved-skeleton` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:space-separated-checksum-invalid` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:sql-insert-column` | 1.00 | 1.00 | 1.00 | 4 | 0 | 0 |
| `scenario:sql-insert-column-negative` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:tld-japanese` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:unregistered-tld` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:yaml-object-scope` | 1.00 | 1.00 | 1.00 | 4 | 0 | 0 |
| `scenario:yaml-object-scope-negative` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `sep:dot` | 1.00 | 1.00 | 1.00 | 3 | 0 | 0 |
| `sep:hyphen` | 1.00 | 1.00 | 1.00 | 8 | 0 | 0 |
| `sep:none` | 1.00 | 1.00 | 1.00 | 4 | 0 | 0 |
| `sep:slash` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `sep:space` | 1.00 | 1.00 | 1.00 | 4 | 0 | 0 |
| `sep:touten` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `source:curated-v2` | 0.97 | 1.00 | 0.94 | 155 | 0 | 10 |
| `source:hard-negative` | 0.00 | 0.00 | 0.00 | 0 | 1 | 0 |
| `source:legacy-curated` | 0.98 | 1.00 | 0.97 | 57 | 0 | 2 |
| `type:landline` | 1.00 | 1.00 | 1.00 | 2 | 0 | 0 |
| `type:mobile` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| **全体（マイクロ平均）** | **0.98** | **1.00** | **0.96** | 930 | 3 | 42 |
