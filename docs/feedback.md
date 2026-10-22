# 誤検出・見逃しのフィードバック

検出精度の改善に最も役立つのは、実際のコードベースでの誤検出（false positive）と
見逃し（false negative）の報告です。このページは、報告の仕方と、ノイズの多いルールを
見つけるための集計ツール `jp-pii-suppressions` を説明します。

## 報告の前に：実データを貼らない

Issue は公開され、編集・削除しても履歴や通知メールに残ります。**実在する個人の情報は、
本文・ログ・スクリーンショットのいずれにも含めないでください。**

- 値は **桁数・区切り・全角/半角・表記ゆれが同じダミー値** に置き換えるか、マスクします
  （例: `090-XXXX-XXXX`、`山田 太郎` → `架空 太郎`）。
- 判定は値そのものより **周辺の文脈**（キー名・列名・ラベル・ファイル種別）に左右されます。
  文脈はできるだけそのまま残してください。
- チェックディジットを持つ番号（マイナンバー・クレジットカード等）で検査を通るダミー値が
  必要な場合は、「チェックディジットあり」とだけ書いてください。保守者が合成します。
- `--unmask` の出力は貼らないでください。既定の出力（マスク済み）でも、貼る前に値を確認してください。

## Issue テンプレート

[Issue の新規作成](https://github.com/baneido/jp-pii-detector/issues/new/choose)から選びます。

| テンプレート | 用途 | 主な記入項目 |
|---|---|---|
| 誤検出の報告（False positive） | PII ではない値が検出される | ルール ID、検出モード、ダミー化した再現テキスト、ファイル種別、抑制の利用状況（任意） |
| 見逃しの報告（False negative） | 検出されるべき PII が検出されない | PII の種別、検出モード、ダミー化した例、`--explain-dropped` の結果（任意） |

どちらのテンプレートも「ダミー値またはマスク済みの値だけを含む」ことの確認を必須にしています。

役に立つ補助情報:

- `jp-pii-detect scan --explain <path>`：検出の根拠（検証の有無・文脈キーワード等）。
- `jp-pii-detect scan --explain-dropped <path>`：候補になったが除外された理由（見逃しの分析用）。
  値は出力されませんが、ファイルパスは含まれます。

## 抑制の利用状況を集計する（jp-pii-suppressions）

誤検出は Issue になる前に、行内の ignore マーカー（`jp-pii-detector:ignore` / 旧 `pii-allow`）や
`.jp-pii.toml` の `[allowlist]` で黙らされていることが多くあります。`jp-pii-suppressions` は、
走査対象のツリーでそれらが **どのルールの検出をどれだけ抑制しているか** を集計します。
抑制率の高いルールは、利用現場でノイズになっているルールの有力な手がかりです。

配布バイナリには含まれない補助ツールで、Go があれば次のように実行できます
（リポジトリのルートで実行すると、`.jp-pii.toml` が自動で読み込まれます）。

```console
$ go run github.com/baneido/jp-pii-detector/cmd/jp-pii-suppressions@latest
$ go run github.com/baneido/jp-pii-detector/cmd/jp-pii-suppressions@latest --format json src/
```

| フラグ | 説明 |
|---|---|
| `--config <path>` | 設定ファイル（既定はカレントから上方向に `.jp-pii.toml` を探索） |
| `--format markdown\|json` | 出力形式（既定は markdown。Issue にそのまま貼れる） |
| `--high-recall` / `--name-roster` / `--min-confidence` | `scan` と同じ検出設定で集計する |
| `--files` | マーカー行の多いファイルのパスも出力する |

### 何を数えるか

- **報告**：通常の `jp-pii-detect scan` で報告される件数。
- **ignore マーカー**：マーカーを空白に置き換えて再走査したとき、マーカー行に現れる検出の件数。
  マーカーを外しても何も検出されない行は「不要になった可能性がある行」として別に数えます
  （ルール改善で不要になった ignore の掃除の目安）。
- **allowlist paths / regexes / stopwords**：`[allowlist]` を外して走査したときに増える検出を、
  抑制した要素へ帰属させた件数。どの要素にも直接は一致しない差分（重複解決の結果が
  変わったもの等）は「その他」に数えます。
- **抑制率**：抑制 /（抑制 + 報告）。

### 出力に含まれるもの・含まれないもの

- 含む：ルール ID、件数、`[allowlist].paths` のパターン、`regexes` / `stopwords` の **要素番号**
  （`stopwords[0]` 等。値そのものは個人情報を含みうるため出しません）、`--files` 指定時のファイルパス。
- 含まない：マッチ値（生値もマスク値も）。

ファイルパスや allowlist のパスパターンに社外秘の情報が含まれる場合は、貼る前に伏せてください。

### 制限

- ignore マーカーの集計は UTF-8 のファイルを前提とします。Shift_JIS 等のファイルはマーカー行を
  数えますがルールへの帰属が不正確になることがあり、UTF-16 のファイルのマーカーは数えません。
  `[allowlist]` の集計は `scan` と同じ読み込み経路（文字コードの自動判定を含む）を使います。
- フルスキャンだけが対象です（`--staged` / `--diff` の差分走査には対応していません）。

### CI で定期的に見る

自分のリポジトリで傾向を追うなら、GitHub Actions のジョブサマリへ出すのが手軽です
（権限は読み取りのみで足ります）。

```yaml
- uses: actions/setup-go@v5
  with:
    go-version: stable
- run: go run github.com/baneido/jp-pii-detector/cmd/jp-pii-suppressions@latest >> "$GITHUB_STEP_SUMMARY"
```

（`@latest` の代わりにリリースタグ（例: `@v0.8.1`）を指定すると、検出設定のバージョンを固定できます。
`actions/setup-go` はコミット SHA でのピン留めを推奨します。）
