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
| `high` | 120 | 3 | 97.56% | 93.07% | PASS（≥97.5%） |
| `medium` | 73 | 6 | 92.41% | 84.40% | PASS（≥92.0%） |

### medium

| Confidence | TP | FP | 実測適合率 | Wilson 95%下限 | 基準 |
|---|--:|--:|--:|--:|:--:|
| `high` | 120 | 3 | 97.56% | 93.07% | PASS（≥97.5%） |
| `medium` | 73 | 6 | 92.41% | 84.40% | PASS（≥92.0%） |

### high-recall

| Confidence | TP | FP | 実測適合率 | Wilson 95%下限 | 基準 |
|---|--:|--:|--:|--:|:--:|
| `high` | 131 | 3 | 97.76% | 93.62% | PASS（≥97.5%） |
| `medium` | 103 | 6 | 94.50% | 88.51% | PASS（≥92.0%） |

## プロファイル: low

rule capability（min_confidence=low、高再現率ルール無効）。

| ルール ID | F1 | 適合率 | 再現率 | TP | FP | FN | Finding FP | Confidence miss |
|---|:--:|:--:|:--:|--:|--:|--:|--:|--:|
| `credit-card` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `email-address` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-birthdate` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-drivers-license` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-employment-insurance` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-health-insurance` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-invoice-number` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-juminhyo-code` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-kaigo-insurance` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-pension-number` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-residence-card` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-yucho-account` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `person-name` | 1.00 | 1.00 | 1.00 | 14 | 0 | 0 | 0 | 0 |
| `jp-passport` | 0.95 | 0.91 | 1.00 | 10 | 1 | 0 | 1 | 0 |
| `jp-address` | 0.95 | 1.00 | 0.90 | 9 | 0 | 1 | 0 | 0 |
| `jp-bank-account` | 0.95 | 1.00 | 0.90 | 9 | 0 | 1 | 0 | 0 |
| `jp-phone-number` | 0.91 | 0.83 | 1.00 | 10 | 2 | 0 | 2 | 0 |
| `jp-postal-code` | 0.91 | 0.83 | 1.00 | 10 | 2 | 0 | 2 | 0 |
| `jp-my-number` | 0.83 | 0.71 | 1.00 | 10 | 4 | 0 | 4 | 0 |
| **全体（マイクロ平均）** | **0.97** | **0.96** | **0.99** | 192 | 9 | 2 | 9 | 0 |

陰性ケース母数: 114。

### スパン評価

exactは完全一致、containmentは検出が期待値全体を含む場合、relaxedは一部でも重なる場合です。

| ルール ID | exact F1 | containment F1 | relaxed F1 | exact TP/FP/FN | containment TP/FP/FN | relaxed TP/FP/FN |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| `credit-card` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `email-address` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-birthdate` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-drivers-license` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-employment-insurance` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-health-insurance` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-invoice-number` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-juminhyo-code` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-kaigo-insurance` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-pension-number` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-residence-card` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-yucho-account` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `person-name` | 1.00 | 1.00 | 1.00 | 14/0/0 | 14/0/0 | 14/0/0 |
| `jp-passport` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-address` | 0.95 | 0.95 | 0.95 | 9/0/1 | 9/0/1 | 9/0/1 |
| `jp-bank-account` | 0.95 | 0.95 | 0.95 | 9/0/1 | 9/0/1 | 9/0/1 |
| `jp-phone-number` | 1.00 | 1.00 | 1.00 | 11/0/0 | 11/0/0 | 11/0/0 |
| `jp-postal-code` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-my-number` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| **全体（マイクロ平均）** | **0.99** | **0.99** | **0.99** | 193/0/2 | 193/0/2 | 193/0/2 |

マクロ平均F1: exact 0.99 / containment 0.99 / relaxed 0.99。
## プロファイル: medium

default operational（min_confidence=medium、高再現率ルール無効）。

| ルール ID | F1 | 適合率 | 再現率 | TP | FP | FN | Finding FP | Confidence miss |
|---|:--:|:--:|:--:|--:|--:|--:|--:|--:|
| `credit-card` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `email-address` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-birthdate` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-drivers-license` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-employment-insurance` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-health-insurance` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-invoice-number` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-juminhyo-code` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-kaigo-insurance` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-pension-number` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-residence-card` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-yucho-account` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `person-name` | 1.00 | 1.00 | 1.00 | 14 | 0 | 0 | 0 | 0 |
| `jp-passport` | 0.95 | 0.91 | 1.00 | 10 | 1 | 0 | 1 | 0 |
| `jp-address` | 0.95 | 1.00 | 0.90 | 9 | 0 | 1 | 0 | 0 |
| `jp-bank-account` | 0.95 | 1.00 | 0.90 | 9 | 0 | 1 | 0 | 0 |
| `jp-phone-number` | 0.91 | 0.83 | 1.00 | 10 | 2 | 0 | 2 | 0 |
| `jp-postal-code` | 0.91 | 0.83 | 1.00 | 10 | 2 | 0 | 2 | 0 |
| `jp-my-number` | 0.83 | 0.71 | 1.00 | 10 | 4 | 0 | 4 | 0 |
| **全体（マイクロ平均）** | **0.97** | **0.96** | **0.99** | 192 | 9 | 2 | 9 | 0 |

陰性ケース母数: 114。

### スパン評価

exactは完全一致、containmentは検出が期待値全体を含む場合、relaxedは一部でも重なる場合です。

| ルール ID | exact F1 | containment F1 | relaxed F1 | exact TP/FP/FN | containment TP/FP/FN | relaxed TP/FP/FN |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| `credit-card` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `email-address` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-birthdate` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-drivers-license` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-employment-insurance` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-health-insurance` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-invoice-number` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-juminhyo-code` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-kaigo-insurance` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-pension-number` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-residence-card` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-yucho-account` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `person-name` | 1.00 | 1.00 | 1.00 | 14/0/0 | 14/0/0 | 14/0/0 |
| `jp-passport` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-address` | 0.95 | 0.95 | 0.95 | 9/0/1 | 9/0/1 | 9/0/1 |
| `jp-bank-account` | 0.95 | 0.95 | 0.95 | 9/0/1 | 9/0/1 | 9/0/1 |
| `jp-phone-number` | 1.00 | 1.00 | 1.00 | 11/0/0 | 11/0/0 | 11/0/0 |
| `jp-postal-code` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-my-number` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| **全体（マイクロ平均）** | **0.99** | **0.99** | **0.99** | 193/0/2 | 193/0/2 | 193/0/2 |

マクロ平均F1: exact 0.99 / containment 0.99 / relaxed 0.99。
## プロファイル: high-recall

high recall operational（min_confidence=medium、高再現率ルール有効）。

| ルール ID | F1 | 適合率 | 再現率 | TP | FP | FN | Finding FP | Confidence miss |
|---|:--:|:--:|:--:|--:|--:|--:|--:|--:|
| `credit-card` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `email-address` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-birthdate` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-drivers-license` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-employment-insurance` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-health-insurance` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-invoice-number` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-juminhyo-code` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-kaigo-insurance` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-pension-number` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-residence-card` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-yucho-account` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `person-name` | 1.00 | 1.00 | 1.00 | 14 | 0 | 0 | 0 | 0 |
| `person-name-high-recall` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `person-name-romaji` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `person-name-structured` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 | 0 | 0 |
| `jp-address-high-recall` | 0.95 | 0.91 | 1.00 | 10 | 1 | 0 | 1 | 0 |
| `jp-passport` | 0.95 | 0.91 | 1.00 | 10 | 1 | 0 | 1 | 0 |
| `jp-address` | 0.95 | 1.00 | 0.90 | 9 | 0 | 1 | 0 | 0 |
| `jp-bank-account` | 0.95 | 1.00 | 0.90 | 9 | 0 | 1 | 0 | 0 |
| `jp-phone-number` | 0.91 | 0.83 | 1.00 | 10 | 2 | 0 | 2 | 0 |
| `jp-postal-code` | 0.91 | 0.83 | 1.00 | 10 | 2 | 0 | 2 | 0 |
| `jp-my-number` | 0.83 | 0.71 | 1.00 | 10 | 4 | 0 | 4 | 0 |
| **全体（マイクロ平均）** | **0.97** | **0.96** | **0.99** | 232 | 10 | 2 | 10 | 0 |

陰性ケース母数: 114。

### スパン評価

exactは完全一致、containmentは検出が期待値全体を含む場合、relaxedは一部でも重なる場合です。

| ルール ID | exact F1 | containment F1 | relaxed F1 | exact TP/FP/FN | containment TP/FP/FN | relaxed TP/FP/FN |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| `credit-card` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `email-address` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-birthdate` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-drivers-license` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-employment-insurance` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-health-insurance` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-invoice-number` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-juminhyo-code` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-kaigo-insurance` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-pension-number` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-residence-card` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-yucho-account` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `person-name` | 1.00 | 1.00 | 1.00 | 14/0/0 | 14/0/0 | 14/0/0 |
| `person-name-high-recall` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `person-name-romaji` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `person-name-structured` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-address-high-recall` | 0.95 | 0.95 | 0.95 | 10/1/0 | 10/1/0 | 10/1/0 |
| `jp-passport` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-address` | 0.95 | 0.95 | 0.95 | 9/0/1 | 9/0/1 | 9/0/1 |
| `jp-bank-account` | 0.95 | 0.95 | 0.95 | 9/0/1 | 9/0/1 | 9/0/1 |
| `jp-phone-number` | 1.00 | 1.00 | 1.00 | 11/0/0 | 11/0/0 | 11/0/0 |
| `jp-postal-code` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| `jp-my-number` | 1.00 | 1.00 | 1.00 | 10/0/0 | 10/0/0 | 10/0/0 |
| **全体（マイクロ平均）** | **0.99** | **0.99** | **0.99** | 233/1/2 | 233/1/2 | 233/1/2 |

マクロ平均F1: exact 0.99 / containment 0.99 / relaxed 0.99。

## データセットの統計（匿名）

評価データセットはリポジトリ外（GCS）で管理され、レビュー時に中身が見えないため、
PII やケース本文を含まない件数だけの統計をここに記録します。

- 総ケース数: 347
- 陽性ケース数: 233（うちスパン付与 233 件、付与率 100%）
- 陰性ケース数: 114

### 入力種別別ケース数

| 区分 | ケース数 |
|---|--:|
| `content` | 15 |
| `diff` | 1 |
| `line` | 331 |

### ファイル形式別ケース数

| 区分 | ケース数 |
|---|--:|
| `csv` | 3 |
| `json` | 5 |
| `sql` | 3 |
| `txt` | 5 |
| `unspecified` | 331 |

### source class別ケース数

| 区分 | ケース数 |
|---|--:|
| `curated-v2` | 175 |
| `hard-negative` | 40 |
| `legacy-curated` | 132 |

### ルール別陽性件数

| ルール ID | 陽性ケース数 |
|---|--:|
| `credit-card` | 10 |
| `email-address` | 10 |
| `jp-address` | 10 |
| `jp-address-high-recall` | 10 |
| `jp-bank-account` | 10 |
| `jp-birthdate` | 10 |
| `jp-drivers-license` | 10 |
| `jp-employment-insurance` | 10 |
| `jp-health-insurance` | 10 |
| `jp-invoice-number` | 10 |
| `jp-juminhyo-code` | 10 |
| `jp-kaigo-insurance` | 10 |
| `jp-my-number` | 10 |
| `jp-passport` | 10 |
| `jp-pension-number` | 10 |
| `jp-phone-number` | 10 |
| `jp-postal-code` | 10 |
| `jp-residence-card` | 10 |
| `jp-yucho-account` | 10 |
| `person-name` | 14 |
| `person-name-high-recall` | 10 |
| `person-name-romaji` | 10 |
| `person-name-structured` | 10 |

## ケース種別別（medium）

評価ケースの入力形式（line/content/diff）別の内訳です。行レベル（Result.TP 等と同じ定義）のTP/FP/FN で、1 ケースに複数ルールの期待・検出があれば同じ種別へ合算します。

| ケース種別 | F1 | 適合率 | 再現率 | TP | FP | FN |
|---|:--:|:--:|:--:|--:|--:|--:|
| `line` | 0.97 | 0.95 | 0.99 | 190 | 9 | 2 |
| `content` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `diff` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| **全体（マイクロ平均）** | **0.97** | **0.96** | **0.99** | 192 | 9 | 2 |

## タグ別（表記ゆれ等）

評価ケースの `Case.Tags`（表記ゆれ・ラベル語彙・合成データ由来などのメタデータ。語彙は [docs/development.md](../docs/development.md) を参照）別の内訳です。タグ未設定のケースは含まれません。

| タグ | F1 | 適合率 | 再現率 | TP | FP | FN |
|---|:--:|:--:|:--:|--:|--:|--:|
| `file-format:csv` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `file-format:json` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `file-format:sql` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `layout:content` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `layout:diff` | 1.00 | 1.00 | 1.00 | 1 | 0 | 0 |
| `layout:line` | 1.00 | 1.00 | 1.00 | 133 | 0 | 0 |
| `polarity:negative` | 0.00 | 0.00 | 0.00 | 0 | 9 | 0 |
| `polarity:positive` | 1.00 | 1.00 | 1.00 | 135 | 0 | 0 |
| `rule:credit-card` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 |
| `rule:email-address` | 1.00 | 1.00 | 1.00 | 6 | 0 | 0 |
| `rule:jp-address` | 1.00 | 1.00 | 1.00 | 5 | 0 | 0 |
| `rule:jp-address-high-recall` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `rule:jp-bank-account` | 1.00 | 1.00 | 1.00 | 6 | 0 | 0 |
| `rule:jp-birthdate` | 1.00 | 1.00 | 1.00 | 7 | 0 | 0 |
| `rule:jp-drivers-license` | 1.00 | 1.00 | 1.00 | 7 | 0 | 0 |
| `rule:jp-employment-insurance` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 |
| `rule:jp-health-insurance` | 1.00 | 1.00 | 1.00 | 8 | 0 | 0 |
| `rule:jp-invoice-number` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 |
| `rule:jp-juminhyo-code` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 |
| `rule:jp-kaigo-insurance` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 |
| `rule:jp-my-number` | 1.00 | 1.00 | 1.00 | 5 | 0 | 0 |
| `rule:jp-passport` | 1.00 | 1.00 | 1.00 | 7 | 0 | 0 |
| `rule:jp-pension-number` | 1.00 | 1.00 | 1.00 | 7 | 0 | 0 |
| `rule:jp-phone-number` | 1.00 | 1.00 | 1.00 | 3 | 0 | 0 |
| `rule:jp-postal-code` | 1.00 | 1.00 | 1.00 | 7 | 0 | 0 |
| `rule:jp-residence-card` | 1.00 | 1.00 | 1.00 | 7 | 0 | 0 |
| `rule:jp-yucho-account` | 1.00 | 1.00 | 1.00 | 10 | 0 | 0 |
| `rule:person-name-high-recall` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `rule:person-name-romaji` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `rule:person-name-structured` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-account-like` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-address-like` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-business-id` | 0.00 | 0.00 | 0.00 | 0 | 4 | 0 |
| `scenario:hard-negative-count` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-date` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-insurance-like` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-invoice-like` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-lot` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-model` | 0.00 | 0.00 | 0.00 | 0 | 1 | 0 |
| `scenario:hard-negative-money` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-name-like` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-phone-like` | 0.00 | 0.00 | 0.00 | 0 | 2 | 0 |
| `scenario:hard-negative-postal-like` | 0.00 | 0.00 | 0.00 | 0 | 2 | 0 |
| `scenario:hard-negative-reserved-email` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-revision` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:hard-negative-test-pan` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `scenario:known-test-pan` | 0.00 | 0.00 | 0.00 | 0 | 0 | 0 |
| `source:curated-v2` | 1.00 | 1.00 | 1.00 | 135 | 0 | 0 |
| `source:hard-negative` | 0.00 | 0.00 | 0.00 | 0 | 9 | 0 |
| `source:legacy-curated` | 0.98 | 1.00 | 0.97 | 57 | 0 | 2 |
| **全体（マイクロ平均）** | **0.98** | **0.96** | **1.00** | 598 | 27 | 2 |
