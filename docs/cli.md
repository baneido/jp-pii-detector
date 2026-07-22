# CLI リファレンス

jp-pii-detect を CLI や CI から使う方向けの、全コマンド・全フラグのリファレンスです。
インストール方法や典型的な使い方は [README](../README.md) を、
CI/CD への組み込みレシピは [docs/integrations.md](integrations.md) を参照してください。

> **対応バージョン**: 本リファレンスはリポジトリの最新実装に追従します。
> インストール済みのバージョンとフラグの有無が異なる場合は、
> `jp-pii-detect version` で確認のうえ `jp-pii-detect help` の出力も参照してください。

## 目次

- [コマンド一覧](#コマンド一覧)
- [scan: 走査モード](#scan-走査モード)
  - [パスとフラグの順序](#パスとフラグの順序)
  - [`--stdin` の座標系](#--stdin-の座標系)
- [scan: フラグリファレンス](#scan-フラグリファレンス)
  - [`--min-confidence` と `--fail-on`](#--min-confidence-と---fail-on)
  - [baseline 系フラグの組み合わせ制約](#baseline-系フラグの組み合わせ制約)
  - [`--summary` と `--quiet`](#--summary-と---quiet)
  - [`--exit-zero` と読み取りエラー](#--exit-zero-と読み取りエラー)
- [出力形式](#出力形式)
- [終了コード](#終了コード)
- [rules サブコマンド](#rules-サブコマンド)
- [version サブコマンド](#version-サブコマンド)
- [関連ドキュメント](#関連ドキュメント)

## コマンド一覧

| コマンド | 説明 |
|---|---|
| `jp-pii-detect scan [flags] [path...]` | PII を走査する（本ツールの主機能） |
| `jp-pii-detect rules [--config <path>] [--high-recall]` | 実効ルール一覧を表示する |
| `jp-pii-detect version` \| `--version` \| `-version` | バージョンを表示する |
| `jp-pii-detect help` \| `-h` \| `--help` | usage を表示する |

引数なしで起動した場合は usage を stderr に出力して終了コード `2` を返します。
未知のサブコマンドを指定した場合も同様に終了コード `2` です。

`scan -h` / `scan --help`、`rules -h` / `rules --help` のように、各サブコマンドに
`-h` / `--help` を付けても usage を表示できます（この場合は終了コード `0`）。

## scan: 走査モード

`scan` には次の 5 つの走査モードがあります。モードを指定する 4 つのフラグ
（`--full` / `--staged` / `--diff` / `--stdin`）は**互いに排他**で、2 つ以上
同時に指定するとエラーになります。位置引数パスとの併用可否はフラグごとに
異なります（下記）。

| モード | 指定方法 | 用途 |
|---|---|---|
| フルスキャン（位置引数） | `scan [path...]`（既定はカレントディレクトリ `.`） | 通常のフルスキャン |
| フルスキャン（固定ルート） | `scan --full` | pre-commit の full フック用。カレントディレクトリを固定で走査 |
| ステージ済み差分 | `scan --staged` | pre-commit フック用。`git diff --staged` の追加行のみ |
| diff 範囲 | `scan --diff <range>` | CI（PR）用。指定リビジョン範囲の追加行のみ |
| 標準入力 | `scan --stdin` | 外部連携用。標準入力のテキスト 1 本を走査 |

- `--full` は位置引数のパスと併用するとエラーになります
  （`--full` は「カレントディレクトリ固定」を表すため、パスとの併用は矛盾する指定として拒否されます）。
- `--staged` / `--diff` / `--stdin` は位置引数のパスがあっても**黙って無視**します。
  pre-commit の `pass_filenames: true` のようにファイル名がフックへ渡される既存設定との
  後方互換のためです。走査範囲を変えたい場合はパスではなく `--diff` の範囲指定などを使ってください。
- 位置引数パスだけを指定する（4 フラグをどれも使わない）通常のフルスキャンは、
  この排他制約の対象外です。

### パスとフラグの順序

フラグと位置引数（パス）の順序は自由です。次の 2 つは同じ意味になります。

```console
$ jp-pii-detect scan . --high-recall
$ jp-pii-detect scan --high-recall .
```

`--` 以降のトークンは常にパスとして扱われます。`-` から始まるパスを渡す場合は
`--` の後ろに置いてください。

```console
$ jp-pii-detect scan -- -weird-filename.txt
```

### `--stdin` の座標系

`--stdin` は標準入力を 1 本のテキストとして走査し、`json` 出力の各検出に
`offset` / `end_offset` を付与します。Microsoft Presidio など文字オフセット基準で
連携するツール向けです。

- `offset` / `end_offset` は**テキスト先頭からのルーン単位の半開区間**です
  （UTF-8 のバイト位置ではありません）。
- 入力に JSON の `\uXXXX` エスケープ（`json.dumps(ensure_ascii=True)` の出力など）が
  含まれる場合、復号済みのビューに対して走査します。`offset` / `end_offset` も
  **復号後のテキスト**上のルーンオフセットになります。復号を無効化するフラグはありません。

## scan: フラグリファレンス

| フラグ | 既定値 | 説明 |
|---|---|---|
| `--format <fmt>` | `text` | 出力形式: `text` \| `json` \| `sarif` \| `github` |
| `--config <path>` | 上方探索 | 設定ファイルのパス（既定は `.jp-pii.toml` をリポジトリルートまで上方探索） |
| `--min-confidence <lvl>` | 設定ファイル値 or `medium` | 報告する最小信頼度: `low` \| `medium` \| `high` |
| `--fail-on <lvl>` | 未指定 | 終了コードを `1` にする最小信頼度: `low` \| `medium` \| `high` |
| `--unmask` | 無効 | 検出値をマスクせず出力する（ローカル限定） |
| `--explain` | 無効 | 検出理由（コンテキスト昇格・検証有無など）を text/json 出力に追加する |
| `--explain-dropped` | 無効 | 検出候補がどの段階で棄却されたかを text/json 出力に追加する（FN 分析用。`json` 出力の `dropped` 配列に検出値そのものは含まれません） |
| `--high-recall` | 無効 | 偽陽性リスクの高い再現率重視ルールを有効化する |
| `--exit-zero` | 無効 | 検出があっても終了コード `0` を返す |
| `--baseline <path>` | 未指定 | ベースラインファイルを読み込み、記録済みの検出を結果と終了コードから除外する |
| `--update-baseline` | 無効 | 現在の検出内容でベースラインファイルを作成・追記して終了する |
| `--show-baseline` | 無効 | ベースラインで除外された検出も参考表示する |
| `--summary` | 無効 | 走査の要約を stderr に表示する |
| `--quiet` | 無効 | 端末での自動要約表示を抑止する |

### `--min-confidence` と `--fail-on`

この 2 つのフラグは役割が異なります。

- `--min-confidence`: **報告閾値**。text/json/sarif/github の出力に載せる検出の
  最小信頼度を決めます。設定ファイルの `min_confidence` を上書きします。
- `--fail-on`: **終了判定閾値**。終了コードを `1` にするかどうかだけを判定する
  独立の閾値です。未指定の場合は従来どおり「報告対象の検出が 1 件でもあれば
  終了コード `1`」という挙動になります。

`--fail-on` を `--min-confidence` より低い値にすると、報告されない信頼度の検出でも
終了コードには反映されます。その場合、該当件数と対処方法（`--min-confidence` を
下げて詳細を見る）を stderr に通知します。

この分離により、「medium 以上を PR に可視化しつつ、CI を落とすのは high の
検出だけ」といった運用ができます（GitHub Actions での例は
[docs/integrations.md](integrations.md) を参照）。

### baseline 系フラグの組み合わせ制約

- `--update-baseline` と `--show-baseline` は、どちらも `--baseline <path>` の
  指定が必須です。単独では使えません。
- `--update-baseline` と `--show-baseline` は同時に指定できません。
- `--update-baseline` 指定時は `--format` の値を無視します
  （ベースライン更新は出力レンダラを経由しないため）。
- `--update-baseline` は、走査中に警告（一部ファイルが読み取れなかった等）が
  あった場合、ベースラインの更新を**拒否**します。不完全な走査結果を
  ベースラインとして固定してしまうのを防ぐためです。
- `--update-baseline` は、ファイルへの書き込みに成功すれば検出件数によらず
  常に終了コード `0` で終了します（gitleaks の `--baseline-path` や
  detect-secrets の baseline 更新運用と同様です）。走査・書き込み自体が
  失敗した場合のみ `2` を返します。

運用例やベースラインの設計思想は README の
[「ベースライン」節](../README.md#ベースライン既存の検出を凍結して新規のみ-fail-させる)、
および [docs/detection-methods.md 4.7 節](detection-methods.md#47-ベースライン方式既存検出の凍結)
を参照してください。

### `--summary` と `--quiet`

`--summary` と `--quiet` は同時に指定できません。

`--summary` は走査モード・走査件数・除外件数・検出件数の要約を stderr に表示します。
`text` 形式で stderr が端末（TTY）に接続されている場合は、指定しなくても
自動で要約が表示されます。CI のようにパイプ・リダイレクトされる環境では
自動表示されないため、要約が必要なら明示的に `--summary` を付けてください。
逆に、端末での自動表示が不要な場合は `--quiet` で抑止できます。

### `--exit-zero` と読み取りエラー

`--exit-zero` を指定していても、走査中に一部ファイルが読み取れないなどの警告が
発生した場合は終了コード `2` になります。走査が不完全なまま「検出なし」を
装う事態を避けるための挙動です。収集済みの検出は通常どおり出力されます。

## 出力形式

| 形式 | 用途 |
|---|---|
| `text` | 人が読む形式。ローカル実行や CI ログでの確認向け |
| `json` | 機械処理向け。外部ツールとの連携や `fingerprint` の取得に使う |
| `sarif` | GitHub Code Scanning への取り込み向け |
| `github` | GitHub Actions の PR アノテーション向け（信頼度に応じて `error`/`warning`/`notice`） |

検出値は既定でマスクして出力します。`--unmask` はマスクを解除しますが、
CI のログに実データが残るリスクがあるため**ローカル調査限定**での利用を
想定しています。

出力例や SARIF アップロードの具体的な手順は重複を避けるため、
README の [「1. CLI として利用」](../README.md#1-cli-として利用)、
[docs/integrations.md の「SARIF を GitHub Code Scanning に取り込む」](integrations.md#sarif-を-github-code-scanning-に取り込む)
を参照してください。

## 終了コード

| コード | 意味 |
|---|---|
| `0` | 検出なし（または `--exit-zero` 指定時） |
| `1` | 報告対象の検出あり（`--fail-on` 指定時はその閾値以上の検出あり） |
| `2` | 走査・設定エラー |

一部ファイルが読み取れなかった場合、収集済みの検出結果は通常どおり出力した
うえで終了コード `2` を返します。`--exit-zero` を指定していても上書きされません
（[「`--exit-zero` と読み取りエラー」](#--exit-zero-と読み取りエラー)を参照）。

## rules サブコマンド

```console
$ jp-pii-detect rules [--config <path>] [--high-recall]
```

`--config` / `--high-recall` を反映した**実効ルール一覧**を表示します。
`scan` が実際に使うルール集合と同じ合成ロジック（builtin + カスタムルール）を
経由するため、`scan` に指定するのと同じフラグ・設定ファイルを渡せば、
本番の走査で有効になるルールをそのまま確認できます。

- 設定ファイルで無効化したルールも一覧からは外れず、状態タグで「無効」と
  表示されます。
- 状態タグは「有効」または「無効」、加えて高再現率ルールには「高再現率」が
  付きます。
- コンテキストキーワードが検出の前提条件になっているルールには
  「(コンテキストキーワード必須)」の注記が付きます。
- `.jp-pii.toml` のカスタムルールも一覧に含まれます。
- 位置引数は受け付けません。指定するとエラーになります。

## version サブコマンド

```console
$ jp-pii-detect version
$ jp-pii-detect --version   # -version でも可
```

バージョン文字列は次の優先順位で決まります。

1. ビルド時の `-ldflags "-X main.version=..."` による明示指定
   （リリースビルドで使われます）
2. `go install module@vX.Y.Z` でインストールした場合に埋め込まれる
   モジュールバージョン
3. ローカルビルド（`go build`）時は、埋め込まれた VCS リビジョン
   （コミットハッシュ先頭 12 文字、作業ツリーが変更されていれば `-dirty` 付き）
4. いずれの情報もなければ `dev`

## 関連ドキュメント

- 設定ファイル（`.jp-pii.toml`）の全項目: README の
  [「設定（.jp-pii.toml）」節](../README.md#設定jp-piitoml)
- CI/CD・開発環境への組み込みレシピ: [docs/integrations.md](integrations.md)
- 検出手法・信頼度の仕組み: [docs/detection-methods.md](detection-methods.md)
- ベースラインの設計判断: [docs/detection-methods.md 4.7 節](detection-methods.md#47-ベースライン方式既存検出の凍結)
