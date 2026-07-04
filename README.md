# jp-pii-detector

![PII detection F1](https://img.shields.io/badge/PII検出_F1（評価データセット）-0.98-brightgreen)

日本特化の個人情報（PII）静的検出器。リポジトリに混入したマイナンバーや電話番号、住所などを
コミット前（git hook）や CI/CD（GitHub Actions）で検出します。

- **日本特化**: マイナンバー検査用数字の検証、全角や長音記号の正規化、和暦、JCB カードなどに対応
- **高速**: Go 製シングルバイナリ（利用時に Go は不要）。pre-commit ではステージ済み差分の追加行のみを走査
- **CI フレンドリー**: 終了コード、JSON、SARIF、GitHub Actions アノテーション出力
- **二次漏えい防止**: 検出値は既定でマスク表示

## 対応している個人情報

精度の凡例：**◎** 単体で高精度（チェックディジット等で誤検出が少ない） /
**○** 周辺の語（「TEL」「住所」など）と併用して実用的な精度 /
**△** ラベル付き（`氏名:` など）に限定して検出

「実測 F1」はラベル付き評価データセット（実在しうる PII を含むためリポジトリ外で管理。取得は
[docs/development.md](docs/development.md)）に対する
**F1 スコア**（適合率と再現率の調和平均）です。`JP_PII_FIXTURES` を設定して `go test ./internal/eval` で検証しており
（数値が動くと CI が落ちる）、内訳は [docs/accuracy.md](docs/accuracy.md) を参照してください。
バッジはルール自体の検出能力を見るため `min_confidence=low`、高再現率ルール無効で計測しています。
評価データセットに対する値であり、あらゆる入力での精度を保証するものではありません。

| 種別 | 例（すべて架空のダミー） | 精度 | 実測 F1 | 検出の決め手 |
|---|---|:---:|:---:|---|
| マイナンバー（個人番号） | `1234-5678-9018` | ◎ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 12 桁 + 検査用数字（総務省令のアルゴリズム） |
| クレジットカード番号 | `4111-1111-1111-1111` | ◎ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | Luhn + ブランド判定（Visa/Master/JCB/Amex 等） |
| メールアドレス | `taro@example.jp` | ◎ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | パターン + IANA TLD 実在チェック + 予約ドメイン除外 |
| 電話番号 | `090-XXXX-XXXX` | ◎ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 携帯/IP/固定/+81 + 桁数検証 |
| 郵便番号 | `〒150-0043` | ◎ / ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 7桁完全一致の実在チェック。〒マーク付きは単独、なしは周辺の語が必要 |
| 住所 | `東京都渋谷区道玄坂2-10-7` | ○ | ![F1 0.89](https://img.shields.io/badge/F1-0.89-green) | 都道府県〜番地のパターン |
| 運転免許証番号 | `免許証番号: 305012345678` | ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 12 桁 + 周辺の語が必要 |
| 旅券（パスポート）番号 | `パスポート: TK1234567` | ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 英字2+数字7 + 周辺の語が必要 |
| 基礎年金番号 | `年金番号: 1234-567890` | ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 4桁-6桁 + 周辺の語が必要 |
| 在留カード番号 | `在留カード AB12345678CD` | ○ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 英2+数8+英2 + 周辺の語が必要 |
| 銀行口座番号 | `口座番号: 1234567` | △ | ![F1 0.86](https://img.shields.io/badge/F1-0.86-green) | 7 桁 + 周辺の語が必要 |
| 健康保険 保険者番号等 | `保険者番号: 12345678` | △ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | 8 桁 + 周辺の語が必要 |
| 生年月日 | `生年月日: 1990年1月23日` | △ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | ラベル付き（日本語・英語ラベル対応）。西暦・和暦（元号略記・元年含む）・区切りなし8桁に対応 |
| 氏名 | `氏名: 山田 太郎` | △ | ![F1 1.00](https://img.shields.io/badge/F1-1.00-brightgreen) | ラベル付き（`氏名:`/`お名前:`/`customer_name:` 等）+ プレースホルダ・非人物キー除外。値が姓名辞書に一致すれば `medium` で**既定でも報告**。`姓:`/`名:` 等の弱いラベルは姓名辞書で検証済みのため常に `medium`。辞書に一致しない収録外の実在人名は `low` のまま既定では非表示（後述） |

> **既定の報告範囲**: 信頼度 `medium` 以上を報告します（`min_confidence` で変更可）。
> 氏名は値が姓名辞書に一致すれば `medium` で既定でも報告されますが、辞書に一致しない
> 収録外の実在人名は誤検出が出やすいため `low` 扱いで、既定では報告されません。
> 各検出は周辺キーワードの有無で `low` / `medium` / `high` に分かれます。キーワードが
> 検出の前提になっているルールでは昇格は起きず、ルール固有の信頼度
> （表の △ は `medium`、○ は `high`）で報告されます。
> `[rules] cooccurrence_boost = true` を opt-in すると、単独では `low` のまま
> 非表示の氏名が、同一ファイル内の近傍（±5 行）に電話番号・マイナンバー等の
> 検証済み高信頼 PII があるときだけ 1 段昇格して報告されます（詳細は後述）。

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
mise use -g github:baneido/jp-pii-detector@v0.1.8
```

プロジェクトローカルでバージョンを固定したい場合は `mise.toml` に以下を追加して `mise install` を実行します。

```toml
[tools]
"github:baneido/jp-pii-detector" = "v0.1.8"
```

### Option 3. バイナリをインストール

GitHub Releases のビルド済みバイナリを取得してインストールするには以下のコマンドを実行します。
インストール先は既定で `$HOME/.local/bin` です。変更する場合は `JP_PII_DETECT_INSTALL_DIR=/path/to/bin` を指定してください。

```sh
curl -fsSL https://raw.githubusercontent.com/baneido/jp-pii-detector/v0.1.8/scripts/install.sh | JP_PII_DETECT_VERSION=v0.1.8 sh
```

### Option 4. Go install

```sh
 go install github.com/baneido/jp-pii-detector/cmd/jp-pii-detect@latest
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
    rev: v0.1.8
    hooks:
      - id: jp-pii-detect
```

フックは GitHub Releases のビルド済みバイナリを `~/.cache/jp-pii-detector/pre-commit/`
配下にキャッシュして実行するため、利用側の環境に Go は不要です。通常は `rev` に指定した
タグと同じバージョンのバイナリを使います。`latest` を指定した場合は、古いキャッシュを
使い続けないよう毎回 Release asset を取得し直します。

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
      - uses: baneido/jp-pii-detector@main
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
# 報告する最小信頼度: low | medium | high（デフォルト: medium）
min_confidence = "medium"

[rules]
# 無効化するルール ID（`jp-pii-detect rules` で一覧表示）
disabled = ["person-name"]
# 都道府県なし住所・担当者/敬称アンカー付き氏名・ラベルと値が別行の氏名（フォーム形式）など、
# 偽陽性リスクの高い追加ルールを有効化
high_recall = false
# 単独では low のまま報告されない氏名系ルール（person-name / person-name-high-recall）を、
# 同一ファイル内の近傍（±5行）に電話番号・郵便番号・マイナンバー等の検証済み高信頼 PII が
# あるときだけ 1 段昇格（low→medium、まれに medium→high）させる。CSV/DB ダンプ監査など、
# 強めの検出をしたい場合のみ opt-in する（既定では既存の出力に影響しない）
cooccurrence_boost = false

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

- [検出手法の調査と整理](docs/detection-methods.md)：検出できる PII の種類、精度の根拠、
  チェックディジットや正規化の仕組み、対象外とした項目とその理由
- [検出精度（実測値）](docs/accuracy.md)：評価データセットに対するルール別の適合率、再現率、F1
- [開発者向けガイド](docs/development.md)：ビルド、テスト、内部構成、検出ルールの追加方法
