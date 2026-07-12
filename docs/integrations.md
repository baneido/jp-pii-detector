# CI/CD・開発環境への組み込み

jp-pii-detect を各種 CI/CD サービスや開発環境に組み込むためのレシピ集です。
基本のインストール方法（Homebrew / バイナリ / `go install`）と GitHub Actions の
最小構成は [README](../README.md) を参照してください。

どの CI でも考え方は同じです:

- **終了コード**: `0`=検出なし / `1`=検出あり / `2`=エラー。検出ありでジョブを
  落とすだけなら追加設定は不要です。
- **出力形式**: `--format text|json|sarif|github`（いずれも標準出力）。機械処理には
  `json`、GitHub Code Scanning には `sarif`、PR アノテーションには `github` を使います。
- **スキャン範囲**: フルスキャン（`scan .`）か、変更行のみ（`scan --diff <range>`）。
  PR/MR ゲートには `--diff` が高速で、既存コードの検出結果に埋もれません。
  `--diff` は git の履歴が必要なので、shallow clone の CI では履歴を取得してください。

## コンテナイメージ（GHCR）

リリースごとに `ghcr.io/baneido/jp-pii-detector` へマルチアーキテクチャ
（linux/amd64, linux/arm64）イメージを公開しています。タグは `v0.4.0` のような
バージョンと `latest` です。CI での再現性のため、バージョンタグの利用を推奨します。

イメージには `git` と shell（alpine ベース）が入っているため、そのまま CI の
ジョブコンテナとして使えます。`ENTRYPOINT` は `jp-pii-detect`、作業ディレクトリは
`/scan`、既定コマンドは `scan .` です:

```sh
# カレントディレクトリをフルスキャン
docker run --rm -v "$PWD:/scan" ghcr.io/baneido/jp-pii-detector:v0.4.0

# 引数はそのまま jp-pii-detect に渡る
docker run --rm -v "$PWD:/scan" ghcr.io/baneido/jp-pii-detector:v0.4.0 scan --format json /scan
```

## GitHub Actions

最小構成（README 再掲）:

```yaml
name: pii-check
on: pull_request

jobs:
  pii-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # --diff に完全な履歴が必要
      - uses: baneido/jp-pii-detector@main
        with:
          args: scan --diff origin/${{ github.base_ref }}...HEAD --format github
```

Medium の候補は PR 上に `warning` として表示し、High の検出があるときだけジョブを
失敗させる場合は、報告閾値と失敗閾値を分けて指定します。

```yaml
      - uses: baneido/jp-pii-detector@main
        with:
          args: scan --diff origin/${{ github.base_ref }}...HEAD --format github --min-confidence medium --fail-on high
```

`--fail-on` の指定がない場合は後方互換のため、報告された検出が 1 件でもあれば終了コード 1 です。
High / Medium / Low の GitHub アノテーションは、それぞれ `error` / `warning` / `notice` になります。

### SARIF を GitHub Code Scanning に取り込む

検出結果を PR の Security タブ / Code Scanning アラートとして管理したい場合は
`--format sarif` の出力をアップロードします:

```yaml
jobs:
  pii-check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # SARIF アップロードに必要
    steps:
      - uses: actions/checkout@v4
      - name: Install jp-pii-detect
        run: |
          curl -fsSL https://raw.githubusercontent.com/baneido/jp-pii-detector/v0.4.0/scripts/install.sh \
            | JP_PII_DETECT_VERSION=v0.4.0 sh
      - name: Scan
        run: ~/.local/bin/jp-pii-detect scan --format sarif . > jp-pii.sarif
        # 検出あり（終了コード 1）でもアップロードまで進め、判定は Code Scanning に任せる
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: jp-pii.sarif
```

## GitLab CI

コンテナイメージをジョブイメージとして使います。`ENTRYPOINT` が設定されているため
`entrypoint: [""]` の上書きが必要です。

```yaml
# .gitlab-ci.yml
pii-check:
  image:
    name: ghcr.io/baneido/jp-pii-detector:v0.4.0
    entrypoint: [""] # script を実行できるよう ENTRYPOINT を無効化する
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  variables:
    GIT_DEPTH: "0" # --diff の merge-base 解決に完全な履歴が必要
  script:
    - git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
    - jp-pii-detect scan --diff "origin/${CI_MERGE_REQUEST_TARGET_BRANCH_NAME}...HEAD"
```

MR 以外も含めて常にリポジトリ全体を見るなら `script` を `jp-pii-detect scan .` に、
検出結果を成果物として残すなら `jp-pii-detect scan --format json . > jp-pii.json` と
`artifacts` を組み合わせてください。

## CircleCI

イメージには CircleCI の `checkout` ステップが要求する `git` と `ssh` が
含まれているため、プライマリコンテナとしてそのまま使えます。

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  pii-check:
    docker:
      - image: ghcr.io/baneido/jp-pii-detector:v0.4.0
    steps:
      - checkout
      - run: jp-pii-detect scan .

workflows:
  pii:
    jobs:
      - pii-check
```

## Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
pipelines:
  pull-requests:
    '**':
      - step:
          name: pii-check
          image: ghcr.io/baneido/jp-pii-detector:v0.4.0
          clone:
            depth: full # --diff の merge-base 解決に完全な履歴が必要
          script:
            - git fetch origin "$BITBUCKET_PR_DESTINATION_BRANCH"
            - jp-pii-detect scan --diff "origin/${BITBUCKET_PR_DESTINATION_BRANCH}...HEAD"
```

## Jenkins

Docker Pipeline プラグインのエージェントとして使います。Jenkins はイメージの
`ENTRYPOINT` を前提にしないため、空の entrypoint を指定してください。

```groovy
// Jenkinsfile
pipeline {
  agent {
    docker {
      image 'ghcr.io/baneido/jp-pii-detector:v0.4.0'
      args '--entrypoint='
    }
  }
  stages {
    stage('pii-check') {
      steps {
        sh 'jp-pii-detect scan .'
      }
    }
  }
}
```

## git hook マネージャ

コミット前のチェックには `scan --staged`（ステージ済み変更の追加行のみ）を使います。
[pre-commit フレームワーク](https://pre-commit.com)を使う場合はバイナリの用意が不要です
（README 参照）。それ以外のマネージャでは、開発者のマシンに jp-pii-detect が
インストールされている前提になります（Homebrew / install.sh / mise など）。

### lefthook

```yaml
# lefthook.yml
pre-commit:
  commands:
    jp-pii-detect:
      run: jp-pii-detect scan --staged
```

### husky

```sh
# .husky/pre-commit
jp-pii-detect scan --staged
```

### 素の git hook

```sh
# .git/hooks/pre-commit
#!/bin/sh
exec jp-pii-detect scan --staged
```

## mise（旧 rtx）でのツール管理

[mise](https://mise.jdx.dev) の ubi バックエンドで GitHub Releases のバイナリを
そのまま管理できます（Go 不要）:

```sh
mise use "ubi:baneido/jp-pii-detector[exe=jp-pii-detect]@0.1.8"
```

`mise.toml` に直接書く場合:

```toml
[tools]
"ubi:baneido/jp-pii-detector" = { version = "0.1.8", exe = "jp-pii-detect" }
```

## Dev Containers（VS Code / GitHub Codespaces）

`postCreateCommand` でインストールしておくと、コンテナ内のターミナルや
git hook からすぐ使えます:

```json
{
  "postCreateCommand": "curl -fsSL https://raw.githubusercontent.com/baneido/jp-pii-detector/v0.4.0/scripts/install.sh | JP_PII_DETECT_VERSION=v0.4.0 JP_PII_DETECT_INSTALL_DIR=/usr/local/bin sh"
}
```

## AI コーディングエージェント

Claude Code などの AI コーディングエージェントは、新しい PII 混入経路を生みます。
会話に貼り付けた本番データがそのままテストフィクスチャへ転写されたり、実在しうる氏名や
住所が「ダミー」として生成されコミットされたりします。エージェントがファイルを書き込む
直前に走査するフックへ `scan --stdin`（標準入力のテキストを 1 本として走査）を組み込むと、
こうした混入を書き込み前に止められます。

### Claude Code hooks

`Write` / `Edit` ツールの実行直前（`PreToolUse`）にフックで内容を検査し、検出があれば
ブロックします。フックには書き込み内容が JSON で標準入力に渡されるため、`jq` で本文を
取り出して `scan --stdin` に流します。

`.claude/hooks/jp-pii-check.sh`:

```sh
#!/bin/sh
# フック入力 JSON から書き込み内容（Write は .tool_input.content、Edit は
# .tool_input.new_string）を取り出して走査する
content=$(jq -r '.tool_input.content // .tool_input.new_string // empty')
[ -z "$content" ] && exit 0
# jp-pii-detect は検出時に終了コード 1 を返す。Claude Code はフックの終了コード 2 を
# 「ツール実行のブロック」として扱うため、|| exit 2 で 1 を 2 に変換する
printf '%s' "$content" | jp-pii-detect scan --stdin || exit 2
```

`.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          { "type": "command", "command": "sh .claude/hooks/jp-pii-check.sh" }
        ]
      }
    ]
  }
}
```

### 汎用パターン（任意のエージェント / パイプライン）

エージェントの種類を問わず、書き込み予定のテキストを標準入力へ渡して判定できます:

```sh
printf '%s' "$TEXT" | jp-pii-detect scan --stdin --format json
# 終了コード: 0=検出なし / 1=検出あり / 2=エラー。1 を検知したらパイプラインを止める
```

`--format json` は検出内容（ルール ID・行・列・マスク済みの値など）を機械処理しやすい
形で返すため、エージェント側でのブロック判断や理由表示に使えます。

## その他の CI

上記以外でも、コンテナが使える CI（Azure Pipelines, Drone, Woodpecker, Buildkite,
AWS CodeBuild など）なら `ghcr.io/baneido/jp-pii-detector` をジョブイメージに指定するか、
任意の Linux 環境で `scripts/install.sh`（タグ固定を推奨）でバイナリを取得すれば
同じように動きます。判定は終了コード、機械処理は `--format json|sarif` が基本です。
