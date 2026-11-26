# jp-pii-detector

![PII detection F1](https://img.shields.io/badge/PII検出_F1（評価データセット）-1.00-brightgreen)

[English](README.en.md) | 日本語

日本特化の個人情報（PII）静的検出器。リポジトリに混入したマイナンバーや電話番号、住所などを
コミット前（git hook）や CI/CD（GitHub Actions）で検出します。

- 日本に特化し、マイナンバー検査用数字の検証、全角や長音記号の正規化、和暦、JCB カードなどに対応
- 高速に動作する Go 製シングルバイナリ（利用時に Go は不要）。pre-commit ではステージ済み差分の追加行だけをスキャン
- 終了コード、JSON、SARIF、GitHub Actions アノテーション出力により CI に組み込みやすい
- 二次漏えいを防ぐため、検出値は既定でマスク表示

gitleaks / trufflehog / secretlint などのシークレット検出ツールは、マイナンバー・住所・氏名といった
日本語の個人情報を基本的に対象にしていません。jp-pii-detect はこれらの置き換えではなく、
併用して日本語 PII の検出を補完することを想定しています（[docs/comparison.md](docs/comparison.md)）。

## インストール

### Option 1. Homebrew（macOS / Linux）

```sh
brew install baneido/tap/jp-pii-detect
```

### Option 2. mise（macOS / Linux）

```sh
mise use -g github:baneido/jp-pii-detector@v0.10.0
```

プロジェクトでバージョンを固定する場合は `mise.toml` に次を追加して `mise install` を実行します。

```toml
[tools]
"github:baneido/jp-pii-detector" = "v0.10.0"
```

### Option 3. インストールスクリプト

```sh
curl -fsSL https://raw.githubusercontent.com/baneido/jp-pii-detector/v0.10.0/scripts/install.sh | JP_PII_DETECT_VERSION=v0.10.0 sh
```

インストール先は既定で `$HOME/.local/bin` です。変更する場合は `JP_PII_DETECT_INSTALL_DIR=/path/to/bin` を指定してください。

### Option 4. Go install

```sh
go install github.com/baneido/jp-pii-detector/cmd/jp-pii-detect@latest
```

### Option 5. Docker

```sh
docker run --rm -v "$PWD:/scan" ghcr.io/baneido/jp-pii-detector:v0.10.0
```

### Sumi モデル同梱ビルド

次のリリースから、install.sh、pre-commit フック、GitHub Actions は既定で Sumi モデル同梱ビルドを入れます。
組み込みルールに加えて、ローカルで動く推論モデル [sumi-ja-pii-nemotron-ft](https://huggingface.co/baneido/sumi-ja-pii-nemotron-ft) でも検出するビルドです。
このモデルは、PII 抽出モデル [Sumi](https://huggingface.co/NagaYu/sumi-ja-pii) を Nemotron-PII-Japan で追加学習し、
ラベルや敬称のない氏名（ログ、ソースコード、ヘッダのない CSV の中の氏名など）も検出できるようにしたものです。
スキャンはルールだけの場合より大幅に遅く、1 ワーカーあたり数百 MB のメモリを使うため、差分のスキャンに向いています。
組み込みルールだけの軽量版を使う場合は `JP_PII_DETECT_MODEL=false`（GitHub Actions では `with.model: false`）を指定してください。

同梱のモデルは Apache License 2.0 で、Sumi（Apache License 2.0、Sumi contributors）の重みを追加学習で変更したものです。
追加学習には NVIDIA の合成データセット [Nemotron-PII-Japan](https://huggingface.co/datasets/nvidia/Nemotron-PII-Japan)（CC BY 4.0）を、
元の Sumi は合成データセット [NagaYu/sumi-ja-pii-corpus](https://huggingface.co/datasets/NagaYu/sumi-ja-pii-corpus)（CC BY-SA 4.0）を使っています。
Sumi の作者が明記しているとおり、Sumi はコンプライアンスを保証する仕組みではなく（"Sumi is not a compliance control."）、
見逃しは必ず起きます。追加学習したモデルも同じです。
同梱物、対応プラットフォーム、ライセンスと帰属表示は [docs/model-bundle.md](docs/model-bundle.md) を参照してください。

## 使い方

```sh
$ jp-pii-detect scan .                          # カレントディレクトリ以下をフルスキャン
$ jp-pii-detect scan --staged                   # ステージ済み変更の追加行のみ（pre-commit 用）
$ jp-pii-detect scan --diff origin/main...HEAD  # PR の追加行のみ（CI 用）
$ jp-pii-detect rules                           # 検出ルール一覧
```

出力例（検出値はマスクされます）:

```
users.csv:4:6   [high]  jp-phone-number 電話番号（携帯・固定・IP・国際表記）  09*********XX
```

ローカルで実際の値を確認したい場合は `--unmask` を付けます（CI では使わないでください）。

終了コードは `0`（検出なし）、`1`（検出あり）、`2`（スキャンや設定のエラー）です。
検出された値にはその中身に応じて次のように対処します。

- 実データが混入していた場合は、削除するか架空の値に置き換えます。
- 意図して置いたダミー値なら、その行に `jp-pii-detector:ignore` を書くか、allowlist に登録します。
- 導入前から残っている検出をまとめて保留したい場合は、[ベースライン](docs/configuration.md#ベースライン)に記録します。

なぜ検出されたかは `--explain` を付けて実行すると確認できます。
全コマンドとフラグは [docs/cli.md](docs/cli.md) にあります。

### pre-commit

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/baneido/jp-pii-detector
    rev: v0.10.0
    hooks:
      - id: jp-pii-detect
```

フックはステージ済みの差分だけをスキャンします。リポジトリ全体をスキャンするフックや、
lefthook / husky などほかの git hook マネージャでの使い方は [docs/integrations.md](docs/integrations.md) を参照してください。

### GitHub Actions

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
      - uses: baneido/jp-pii-detector@v0.10.0
        with:
          # jp-pii-detect のバイナリ版を固定
          version: v0.10.0
          args: scan --diff origin/${{ github.base_ref }}...HEAD --format github
```

`--format github` を指定すると、検出箇所が PR の該当行にアノテーションとして表示されます。
Action の参照と、ダウンロードするバイナリのバージョンは独立しています。再現性が必要な場合は、
上記のように `uses:` のタグと `with.version` を同じ値で明示してください。
`--fail-on` による失敗条件の指定、SARIF の取り込み、GitLab CI などほかの CI での使い方は
[docs/integrations.md](docs/integrations.md) を参照してください。

## 対応している個人情報

| 種別 | 実測 F1 | 検出方法 |
|---|:---:|---|
| マイナンバー（個人番号） | **1.00** | 12 桁 + 検査用数字（総務省令のアルゴリズム） |
| クレジットカード番号 | **1.00** | Luhn + ブランド判定 + 公開されているテスト用カード番号を除外 |
| メールアドレス | **1.00** | パターン + IANA TLD 実在チェック + 予約ドメイン除外 |
| 電話番号 | **1.00** | 携帯/IP/固定/+81 + 桁数検証 |
| 郵便番号 | **1.00** | 7 桁完全一致の実在チェック（〒なしは周辺のキーワードが必要） |
| 住所 | **0.99** | 都道府県〜番地のパターン |
| 運転免許証番号 | - | 12 桁 + 周辺のキーワードが必要 |
| 旅券（パスポート）番号 | - | 英字2+数字7 + 周辺のキーワードが必要 |
| 基礎年金番号 | - | 4桁-6桁 + 周辺のキーワードが必要 |
| 在留カード番号 | - | 英2+数8+英2 + 周辺のキーワードが必要 |
| 銀行口座番号 | **0.99** | 7 桁 + 周辺のキーワードが必要 |
| ゆうちょ銀行 記号番号 | - | 記号4桁目の検査数字 + 番号との相関 + ゆうちょ固有のキーワードが必要 |
| 健康保険 保険者番号等 | **1.00** | 8 桁 + 周辺のキーワード、またはラベルに隣接する国保の 6 桁の保険者番号・被保険者証の記号・番号 |
| 雇用保険被保険者番号 | - | 4桁-6桁-1桁 + 周辺のキーワードが必要 |
| 介護保険被保険者番号 | - | 10 桁 + 周辺のキーワードが必要 |
| 住民票コード | - | 11 桁 + 周辺のキーワードが必要（全桁同一は除外） |
| インボイス登録番号 | - | T + 13 桁 + 法人番号の検査用数字 |
| 生年月日 | **1.00** | ラベル付き。西暦・和暦・区切りなし8桁に対応 |
| 氏名 | **1.00** | ラベル（`氏名:` 等）、帳票の見出し（`患者情報` 等）の次の行、契約書の当事者欄 + 姓名辞書照合 |
| 氏名（担当者・宛名ラベル） | - | ラベル（`担当:`、`宛名:` 等）+ 姓名辞書照合 |

既定では信頼度 `medium` 以上の検出だけを報告します。信頼度の決まり方と変え方は
[docs/configuration.md](docs/configuration.md#信頼度) を参照してください。

「実測 F1」は、公開データセット [Nemotron-PII-Japan](https://huggingface.co/datasets/nvidia/Nemotron-PII-Japan)（NVIDIA、[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)）から抽出した約 1 万件の合成文書に対し、既定の設定で測った F1 スコアです。
評価データセットでの値なので、どんな入力でも同じ精度が出ることを保証するものではありません。
データセットに正解ラベルがない種別は「-」と表示しています。
ルール別の適合率と再現率、計測方法は [docs/accuracy.md](docs/accuracy.md)、検出手法の詳細は
[docs/detection-methods.md](docs/detection-methods.md) にあります。

## 設定

リポジトリルートに `.jp-pii.toml` を置くと自動で読み込まれます。

```toml
# 報告する最小信頼度: low | medium | high（デフォルト: medium）
min_confidence = "medium"

[rules]
# 無効化するルール ID（`jp-pii-detect rules` で一覧表示）
disabled = ["person-name"]

[allowlist]
# スキャン対象から除外するパス（glob または正規表現）
paths = ["^testdata/"]
# 完全一致で除外するダミー値
stopwords = ["090-XXXX-XXXX"]
```

全項目、ignore マーカー、ベースライン、外部レコグナイザ連携は
[docs/configuration.md](docs/configuration.md) を参照してください。

## ドキュメント

- [CLI リファレンス](docs/cli.md)：全コマンド・全フラグの詳細、スキャンモード、終了コード
- [設定と検出の抑制](docs/configuration.md)：`.jp-pii.toml` の全項目、信頼度、ignore マーカー、ベースライン、外部レコグナイザ連携
- [CI/CD・開発環境への組み込み](docs/integrations.md)：pre-commit、コンテナイメージ、GitLab CI /
  CircleCI / Bitbucket / Jenkins、lefthook / husky、mise、Dev Containers のレシピ
- [検出手法の調査と整理](docs/detection-methods.md)：検出できる PII の種類、精度の根拠、
  チェックディジットや正規化の仕組み、対象外とした項目とその理由
- [検出精度（実測値）](docs/accuracy.md)：評価データセットに対するルール別の適合率、再現率、F1
- [Sumi モデル同梱ビルド](docs/model-bundle.md)：同梱物、ビルド手順、バージョンの固定とライセンス表示
- [誤検出・見逃しのフィードバック](docs/feedback.md)：Issue での報告の仕方（ダミー値のみ）、
  ignore / allowlist の利用状況をルール別に集計する `jp-pii-suppressions`
- [開発者向けガイド](docs/development.md)：ビルド、テスト、内部構成、検出ルールの追加方法
- [他ツールとの比較](docs/comparison.md)：gitleaks / trufflehog / secretlint 等との違いと併用方針
- [ロードマップ](docs/roadmap.md)：v1.0 に向けた対応予定と方針

## ライセンス

[MIT License](LICENSE) の下で配布しています。同梱・依存するサードパーティ成果物の
ライセンス表記は [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) を参照してください。
Sumi モデル同梱ビルドの同梱物（sumi-ja-pii-nemotron-ft と Sumi：Apache-2.0、ModernBERT-Ja-130M：MIT、
ONNX Runtime：MIT）の表記は [third_party/model-bundle/NOTICE.md](third_party/model-bundle/NOTICE.md) にあり、
アーカイブにも同梱しています。
