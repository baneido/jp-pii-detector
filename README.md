# jp-pii-detector

![PII detection F1](https://img.shields.io/badge/PII検出_F1（評価データセット）-0.97-brightgreen)

[English](README.en.md) | 日本語

日本特化の個人情報（PII）静的検出器。リポジトリに混入したマイナンバーや電話番号、住所などを
コミット前（git hook）や CI/CD（GitHub Actions）で検出します。

- **日本特化**: マイナンバー検査用数字の検証、全角や長音記号の正規化、和暦、JCB カードなどに対応
- **高速**: Go 製シングルバイナリ（利用時に Go は不要）。pre-commit ではステージ済み差分の追加行のみを走査
- **CI フレンドリー**: 終了コード、JSON、SARIF、GitHub Actions アノテーション出力
- **二次漏えい防止**: 検出値は既定でマスク表示

## gitleaks 等シークレット検出ツールとの違い

gitleaks / trufflehog / secretlint は API キーやトークンなどの**シークレット**検出が
主目的で、マイナンバー・住所・氏名といった日本語の個人情報（PII）は基本的に対象外です。
jp-pii-detect はこれらの置き換えではなく、シークレット検出ツールと**併用**して日本語 PII の
検出を補完することを想定しています。詳細は [docs/comparison.md](docs/comparison.md) を参照してください。

## まず試す

```sh
brew install baneido/tap/jp-pii-detect
jp-pii-detect version
jp-pii-detect scan .
```

終了コードは `0`（検出なし）、`1`（検出あり）、`2`（走査・設定エラー）です。
検出された値は、実データなら削除・置換し、意図したダミー値なら
`jp-pii-detector:ignore` または allowlist、既存データなら baseline を利用してください。
判定理由は `--explain` で確認できます。

## 対応している個人情報

精度の凡例：**◎** 単体で高精度（チェックディジット等で誤検出が少ない） /
**○** 周辺の語（「TEL」「住所」など）と併用して実用的な精度 /
**△** ラベル付き（`氏名:` など）に限定して検出

| 種別 | 例（すべて架空のダミー） | 精度 | 実測 F1 | 検出の決め手 |
|---|---|:---:|:---:|---|
| マイナンバー（個人番号） | `1234-5678-9018` | ◎ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 12 桁 + 検査用数字（総務省令のアルゴリズム） |
| クレジットカード番号 | `4000-0012-3456-7899` | ◎ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | Luhn + ブランド判定（Visa/Master/JCB/Amex 等）+ 公知テストPAN除外 |
| メールアドレス | `taro@example.jp` | ◎ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | パターン + IANA TLD 実在チェック + 予約ドメイン除外（高再現率では日本語 EAI / 限定 confusable も対象） |
| 電話番号 | `090-XXXX-XXXX` | ◎ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 携帯/IP/固定/+81 + 桁数検証 |
| 郵便番号 | `〒150-0043` | ◎ / ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 7 桁完全一致の実在チェック（〒付きは単独、なしは周辺の語が必要） |
| 住所 | `東京都渋谷区道玄坂2-10-7` | ○ | ![F1 0.97](https://img.shields.io/badge/F1-0.97-brightgreen) | 都道府県〜番地のパターン |
| 運転免許証番号 | `免許証番号: 305012345678` | ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 12 桁 + 周辺の語が必要 |
| 旅券（パスポート）番号 | `パスポート: TK1234567` | ○ | ![F1 0.95](https://img.shields.io/badge/F1-0.95-brightgreen) | 英字2+数字7 + 周辺の語が必要 |
| 基礎年金番号 | `年金番号: 1234-567890` | ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 4桁-6桁 + 周辺の語が必要 |
| 在留カード番号 | `在留カード AB12345678CD` | ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 英2+数8+英2 + 周辺の語が必要 |
| 銀行口座番号 | `口座番号: 1234567` | △ | ![F1 0.95](https://img.shields.io/badge/F1-0.95-brightgreen) | 7 桁 + 周辺の語が必要 |
| ゆうちょ銀行 記号番号 | `記号 1XX?0 / 番号 XXXXXX1` | ○ | ![F1 0.00](https://img.shields.io/badge/F1-0.00-red) | 記号4桁目の検査数字 + 番号との相関 + ゆうちょ固有の周辺語が必要 |
| 健康保険 保険者番号等 | `保険者番号: 12345678` | △ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 8 桁 + 周辺の語、または強ラベル直結の国保6桁保険者番号 |
| 雇用保険被保険者番号 | `XXXX-XXXXXX-X` | ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 4桁-6桁-1桁 + 周辺の語が必要 |
| 介護保険被保険者番号 | `XXXXXXXXXX` | △ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 10 桁 + 周辺の語が必要 |
| 住民票コード | `XXXXXXXXXXX` | ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 11 桁 + 周辺の語が必要（全桁同一は除外） |
| インボイス登録番号 | `TXXXXXXXXXXXXX` | ◎ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | T + 13 桁 + 法人番号の検査用数字 |
| 生年月日 | `生年月日: 1990年1月23日` | △ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | ラベル付き。西暦・和暦・区切りなし8桁に対応（詳細は docs/detection-methods.md） |
| 氏名 | `氏名: 山田 太郎` | △ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | ラベル付き（`氏名:` 等）+ 姓名辞書照合。辞書一致は `medium`（既定で報告）、不一致は `low`（既定非表示、詳細は docs/detection-methods.md） |

> **既定で報告される範囲**: 信頼度 `medium` 以上のみを報告します（`min_confidence` で変更可）。
> 氏名は姓名辞書に一致すれば `medium`（既定でも報告）、一致しない収録外の実在人名は
> 誤検出リスクが高いため `low`（既定では非表示）のままです。
> 信頼度は周辺キーワードの有無で `low` / `medium` / `high` に分かれますが、キーワードが
> 検出の前提条件になっているルール（表の △ は `medium`、○ は `high`）では昇格せず、
> ルール固有の基準信頼度のまま報告されます。
> `[rules] cooccurrence_boost = true` を opt-in すると、単独では `low` のまま
> 非表示になる氏名も、同一ファイル内の近傍（±5 行）に電話番号・マイナンバー等の
> 検証済み高信頼 PII があるときだけ 1 段昇格して報告されます（詳細は後述）。

「実測 F1」はラベル付き評価データセットに対する F1 スコア（適合率と再現率の調和平均）です。
データセットは実在しうる PII を含むためリポジトリ外で管理しており、取得方法は
[docs/development.md](docs/development.md) を参照してください。バッジは利用者の既定運用に対応する
`min_confidence=medium`・高再現率ルール無効で計測しています。low / medium / high-recall の
3プロファイルはそれぞれ独立して公開・CIゲートしています。評価データセットに対する
値であり、あらゆる入力での精度を保証するものではありません。ルール別の内訳は [docs/accuracy.md](docs/accuracy.md)、数値の検証・
更新は `JP_PII_FIXTURES` を設定した `go test ./internal/eval`（CI ゲート）で行います。
通常の `go test -race ./...` は認証不要で、非公開評価だけは `go run ./cmd/pii-fixture eval` で明示実行します。

検出できる PII の種類、手法の詳細、設計判断は
[docs/detection-methods.md](docs/detection-methods.md) を参照してください。

## インストール

### Option 1. Homebrew（macOS / Linux）

```sh
brew install baneido/tap/jp-pii-detect
```

`baneido/tap` を一度 tap すれば、以後は `brew install jp-pii-detect` /
`brew upgrade jp-pii-detect` で更新できます。formula はリリースごとに自動更新されます。

### Option 2. mise（macOS / Linux）

[mise](https://mise.jdx.dev/) の GitHub backend で GitHub Releases のビルド済みバイナリをインストールできます。
利用側の環境に Go は不要です。

```sh
mise use -g github:baneido/jp-pii-detector@v0.4.2
```

プロジェクトローカルでバージョンを固定したい場合は `mise.toml` に以下を追加して `mise install` を実行します。

```toml
[tools]
"github:baneido/jp-pii-detector" = "v0.4.2"
```

### Option 3. バイナリをインストール

GitHub Releases のビルド済みバイナリを取得してインストールするには以下のコマンドを実行します。
インストール先は既定で `$HOME/.local/bin` です。変更する場合は `JP_PII_DETECT_INSTALL_DIR=/path/to/bin` を指定してください。

```sh
curl -fsSL https://raw.githubusercontent.com/baneido/jp-pii-detector/v0.4.2/scripts/install.sh | JP_PII_DETECT_VERSION=v0.4.2 sh
```

### Option 4. Go install

```sh
 go install github.com/baneido/jp-pii-detector/cmd/jp-pii-detect@latest
```

### Option 5. Docker / コンテナ

リリースごとに `ghcr.io/baneido/jp-pii-detector` へマルチアーキテクチャ
（linux/amd64, linux/arm64）イメージを公開しています。インストール不要で実行できるほか、
GitLab CI などのジョブイメージとしてそのまま使えます（[docs/integrations.md](docs/integrations.md)）。

```sh
docker run --rm -v "$PWD:/scan" ghcr.io/baneido/jp-pii-detector:v0.4.2
```

## 使い方

### 1. CLI として利用

```sh
$ jp-pii-detect scan .                        # カレントディレクトリ以下をフルスキャン
$ jp-pii-detect scan --staged                 # ステージ済み変更の追加行のみ（pre-commit 用）
$ jp-pii-detect scan --diff origin/main...HEAD  # PR の追加行のみ（CI 用）
$ jp-pii-detect scan --high-recall .          # 偽陽性リスクを許容して再現率重視ルールも有効化
$ jp-pii-detect rules                         # 検出ルール一覧
```

全コマンド・フラグの詳細は [docs/cli.md](docs/cli.md) を参照してください。

出力例（検出値はマスクされます）:

```
users.csv:4:6   [high]  jp-phone-number 電話番号（携帯・固定・IP・国際表記）  09*********XX
```

ローカルで実際の値を確認したい場合は `--unmask` を付けます（CI では使わないでください）。

### 2. git commit hook での利用

#### pre-commit フレームワーク

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/baneido/jp-pii-detector
    rev: v0.4.2
    hooks:
      - id: jp-pii-detect
```

```sh
pre-commit install
pre-commit run jp-pii-detect
```

フックは GitHub Releases のビルド済みバイナリを `~/.cache/jp-pii-detector/pre-commit/`
配下にキャッシュして実行するため、利用側の環境に Go は不要です。通常は `rev` に指定した
タグと同じバージョンのバイナリを使います。既定フックは常にステージ済み差分だけを走査するため、
`--all-files` は pre-commit 側の対象選択だけを変え、走査範囲は全体になりません。導入時に
リポジトリ全体を確認するには、フック ID を `jp-pii-detect-full` に変更して
`pre-commit run jp-pii-detect-full --all-files` を実行してください。

#### git hook

`.git/hooks/pre-commit`:

```sh
#!/bin/sh
exec jp-pii-detect scan --staged
```

### 3. GitHub Actions

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
      - uses: baneido/jp-pii-detector@v0.4.2
        with:
          # jp-pii-detect のバイナリ版を固定
          version: v0.4.2
          args: scan --diff origin/${{ github.base_ref }}...HEAD --format github
```

Action の参照とダウンロードするバイナリ版は独立しています。再現性が必要な場合は、
上記のように `uses:` のタグと `with.version` を同じ値で明示してください。

> 次回リリース以降はムービングメジャータグ `v0` も利用でき、`baneido/jp-pii-detector@v0` で最新の v0 系を追従できます。

`--format github` を指定すると、検出箇所が PR の該当行にアノテーション表示されます。
アノテーションは信頼度に応じて `error` / `warning` / `notice` になります。たとえば
Medium 以上を表示しつつ High の検出だけで CI を失敗させるには、次のように指定します。

```yaml
      - uses: baneido/jp-pii-detector@v0.4.2
        with:
          # jp-pii-detect のバイナリ版を固定
          version: v0.4.2
          args: scan --diff origin/${{ github.base_ref }}...HEAD --format github --min-confidence medium --fail-on high
```

`--fail-on` を省略した場合は従来どおり、報告対象の検出が 1 件でもあれば終了コード 1 です。
`--format sarif` の出力は GitHub Code Scanning に取り込めます
（アップロード例は [docs/integrations.md](docs/integrations.md)）。

現在の設定で各ルールが有効か、また高再現率ルールかを確認するには
`jp-pii-detect rules` を実行します。`rules --high-recall` や
`rules --config <path>` も scan と同じ設定を反映します。

### 4. その他の CI/CD・開発環境

GitLab CI / CircleCI / Bitbucket Pipelines / Jenkins などコンテナが使える CI、
lefthook / husky などの git hook マネージャ、mise でのバイナリ管理、Dev Containers
（VS Code / Codespaces）への組み込みレシピは
[docs/integrations.md](docs/integrations.md) を参照してください。

## 設定（.jp-pii.toml）

リポジトリルートに `.jp-pii.toml` を置くと自動で読み込まれます。探索はカレントディレクトリから
親方向にリポジトリルート（`.git` のあるディレクトリ）まで行うため、サブディレクトリからの実行でも
ルートの設定が使われます（`--config` で明示指定も可能）。

```toml
# 報告する最小信頼度: low | medium | high（デフォルト: medium）
min_confidence = "medium"

[rules]
# 無効化するルール ID（`jp-pii-detect rules` で一覧表示）
disabled = ["person-name"]
# 都道府県なし住所・担当者/敬称アンカー付き氏名・ラベルと値が別行の氏名（フォーム形式）など、
# 偽陽性リスクの高い追加ルールを有効化
high_recall = false
# 氏名系ルール（person-name / person-name-high-recall）の low / medium 候補を、
# 同一ファイル内の近傍（±5行）に電話番号・郵便番号・マイナンバー等の検証済み高信頼 PII が
# あるときだけ 1 段昇格（low→medium、まれに medium→high）させる。CSV/DB ダンプ監査など、
# 強めの検出をしたい場合のみ opt-in する（既定では既存の出力に影響しない）
cooccurrence_boost = false
# ルール横断の下位種別（Reason.kind）のうち、指定した種別を検出結果から除外する（既定は未設定＝
# 全種別検出）。電話番号ルール（jp-phone-number）は service=フリーダイヤル等・ip・mobile・fixed・
# international、インボイス登録番号ルール（jp-invoice-number）は国税庁公表の公開情報であることを示す
# public-business を付与する。詳細は docs/detection-methods.md の「電話番号の下位種別分類」を参照
exclude_kinds = ["service"]

[allowlist]
# スキャン対象から除外するパス（glob または正規表現）。glob の * は 1 階層、
# ** は 0 階層以上にマッチします。フルスキャンでは走査時のパス表記に加えて
# リポジトリルートからの相対パスにも適用されるため、サブディレクトリから
# 実行しても ^testdata/ や path/to/*.txt のようなルート相対の指定が機能します。
paths = ["path/to/*.txt", "path/to/**/target", "^testdata/", "\\.lock$"]
# マッチ文字列に対する除外（正規表現）。例: 自社ドメインのメール
regexes = ["@baneido\\.com$"]
# 完全一致で除外するダミー値
stopwords = ["090-XXXX-XXXX"]
```

意図的なダミー値には行内コメントで ignore マーカーを付けられます:

```python
TEST_PHONE = "090-XXXX-XXXX"  # jp-pii-detector:ignore テスト用ダミー
```

旧マーカー `pii-allow` も互換性のため引き続き利用できます。

### 外部レコグナイザ連携（`external_recognizer`、opt-in）

軽量 NER（GiNZA/BERT 等）による氏名検出などを、Go バイナリに依存を足さずに接続できます。
既定は未設定＝完全に無効です:

```toml
[external_recognizer]
command = ["python3", "my_ner.py"]  # argv 配列。シェル解釈はしない
timeout_seconds = 30                # 既定 30
max_findings = 1000                 # 既定 1000
```

プロトコル仕様・動くデモ（[integrations/external-recognizer/](integrations/external-recognizer/)）・
**セキュリティ上の注意**（設定ファイルに書かれた任意コマンドを実行する機能のため、
リポジトリ内の `.jp-pii.toml` を信用できない環境では使わないこと等）は
[docs/detection-methods.md の「4.8 外部レコグナイザ連携」](docs/detection-methods.md#48-外部レコグナイザ連携external_recognizeropt-in)
を参照してください。

## ベースライン（既存の検出を凍結して新規のみ fail させる）

既存リポジトリに導入すると、過去に混入済みの PII やダミー値が一斉に検出されて CI が
通らなくなることがあります。gitleaks の `--baseline-path` や detect-secrets の
`.secrets.baseline` と同様に、ベースラインファイルへ既知の検出を記録しておくと、
以降のスキャンでは新規追加分だけを fail させられます。

```sh
# 導入時: 現在の検出内容でベースラインファイルを作成（以後は --baseline とセットで使う）
$ jp-pii-detect scan --baseline .jp-pii-baseline.json --update-baseline .

# 通常運用: ベースライン記録済みの検出は結果・終了コードから除外される
$ jp-pii-detect scan --baseline .jp-pii-baseline.json .

# 除外された検出も参考表示したい場合（終了コードには影響しない）
$ jp-pii-detect scan --baseline .jp-pii-baseline.json --show-baseline .
```

`--baseline` / `--update-baseline` / `--show-baseline` は `--staged` / `--diff` / フルスキャンの
いずれのモードでも同じロジックで動作します。記録は salt 付き HMAC-SHA256 の
**値ハッシュ（fingerprint）** で行うため、ファイル内で行が前後に移動しても再検出されませんが、
ルール ID・ファイルパス・検出値のいずれかが変わると別の fingerprint として再度検出されます。

**セキュリティ上の注意**: salt 付きハッシュは複数リポジトリ間でのレインボーテーブル使い回しを
防ぐものであり、ベースラインファイル自体を入手した第三者による低エントロピーな値
（7 桁の口座番号など）への総当たり照合を防ぐものではありません。ベースラインファイルは
元のソース履歴と同程度の機密度で扱ってください（公開リポジトリにコミットしない、
アクセス制御された場所で管理する、など）。

## ドキュメント

- [CLI リファレンス](docs/cli.md)：全コマンド・全フラグの詳細、走査モード、終了コード
- [CI/CD・開発環境への組み込み](docs/integrations.md)：コンテナイメージ、GitLab CI /
  CircleCI / Bitbucket / Jenkins、lefthook / husky、mise、Dev Containers のレシピ
- [検出手法の調査と整理](docs/detection-methods.md)：検出できる PII の種類、精度の根拠、
  チェックディジットや正規化の仕組み、対象外とした項目とその理由
- [検出精度（実測値）](docs/accuracy.md)：評価データセットに対するルール別の適合率、再現率、F1
- [開発者向けガイド](docs/development.md)：ビルド、テスト、内部構成、検出ルールの追加方法
- [他ツールとの比較](docs/comparison.md)：gitleaks / trufflehog / secretlint 等との違いと併用方針
- [ロードマップ](docs/roadmap.md)：v1.0 に向けた対応予定と方針

## ライセンス

[MIT License](LICENSE) の下で配布しています。同梱・依存するサードパーティ成果物の
ライセンス表記は [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) を参照してください。
