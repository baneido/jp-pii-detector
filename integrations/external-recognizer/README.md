# jp-pii-detect 外部レコグナイザ連携（`external_recognizer`）

`jp-pii-detect` に、**ユーザーが指定した任意の外部コマンド**を検出候補の生成器として
接続する opt-in の仕組みです。軽量 NER（GiNZA/BERT 等）による氏名検出は Go バイナリに
ML ランタイムを同梱すると commit hook としての起動速度・配布容易性（単一バイナリ）を
損なうため、本体には一切依存を足さず、この「接続点」だけを提供します。**NER モデル本体は
このリポジトリに含まれません。** 実運用では GiNZA/BERT 等を使った自前のレコグナイザを
用意し、下記プロトコルで接続してください。

このディレクトリには、プロトコルの形だけを示す最小デモ（[`demo_recognizer.py`](demo_recognizer.py)、
固定の 1 語をハードコードした辞書として返すだけ）が入っています。実用的な検出精度は
持ちません。

## 仕組み

```
jp-pii-detect scan .
        │  [external_recognizer] が設定されていれば、1 回の走査につき子プロセスを 1 つ起動
        ▼
外部コマンド（例: python3 demo_recognizer.py）
        │  stdin: 走査対象ファイルの {file, text} を JSONL で受信
        │  stdout: 検出候補 {file, rule_id, line, column, length, confidence} を JSONL で送信
        ▼
jp-pii-detect が候補を検証（rule_id 接尾辞・範囲・allowlist・ignore マーカー・min_confidence）
        │  し、既存の findings と重複解決したうえで統合
        ▼
通常の findings と同じく report 層でマスクされて出力される
```

詳細なプロトコル仕様・失敗時の扱い（タイムアウト・異常終了・不正 JSON 行はすべて
「その走査回の候補を丸ごと破棄」）・セキュリティ上の注意は
[docs/detection-methods.md の「4.8 外部レコグナイザ連携」](../../docs/detection-methods.md#48-外部レコグナイザ連携external_recognizeropt-in)
を参照してください。実装は [`internal/external`](../../internal/external/external.go) の
パッケージコメントにあります。

## セットアップ

```console
# 1) jp-pii-detect 本体（Go バイナリ）をビルド
go build -o jp-pii-detect ./cmd/jp-pii-detect

# 2) デモ用の走査対象ファイルを用意
mkdir -p /tmp/demo && printf 'これはサンプル太郎さんのメモです。\n' > /tmp/demo/note.txt

# 3) このディレクトリの demo_recognizer.py を external_recognizer として指定した
#    設定ファイルでスキャン（sample.jp-pii.toml は説明用。実際に使う場合は
#    自分のリポジトリの .jp-pii.toml へ [external_recognizer] を追加する）
./jp-pii-detect scan --config integrations/external-recognizer/sample.jp-pii.toml \
  --format json --unmask /tmp/demo
```

`sample.jp-pii.toml` の内容:

```toml
[external_recognizer]
command = ["python3", "integrations/external-recognizer/demo_recognizer.py"]
timeout_seconds = 30
max_findings = 1000
```

出力イメージ（`rule_id` が `-external` 接尾辞を持つ点に注目。組み込みルールと同じ
`report` 層でマスクされる）:

```json
{
  "findings": [
    {
      "rule_id": "person-name-external",
      "description": "外部レコグナイザによる検出（person-name）",
      "file": ".../note.txt",
      "line": 1,
      "column": 4,
      "match": "サンプル太郎",
      "confidence": "medium"
    }
  ],
  "count": 1
}
```

## 自前のレコグナイザを実装する場合

`demo_recognizer.py` を参考に、以下を満たす実行ファイル（言語は問わない。argv で
起動できれば Python 以外でもよい）を用意してください:

1. 標準入力から `{"version":1,"file":"<path>","text":"<全文>"}` を 1 行 1 JSON（JSONL）で
   読み、EOF まで受信する。
2. 検出した候補ごとに `{"file":..,"rule_id":"<name>-external","line":..,"column":..,"length":..,"confidence":".."}`
   を標準出力へ 1 行 1 JSON で書く。
   - `rule_id` は **`-external` で終わる必要があります**（組み込みルール ID の偽装を防ぐため。
     この接尾辞がない候補は破棄されます）。
   - `line`/`column`/`length` は **1 始まりのルーン（Unicode コードポイント）単位**です
     （UTF-8 のバイト位置ではありません）。Python の `str` はコードポイント列なので、
     `len()`/`str.find()` の結果をそのまま使えます（`demo_recognizer.py` 参照）。
   - 検出値そのもの（マッチ文字列）は送る必要はありません。jp-pii-detect 側が
     `text` から `line`/`column`/`length` で切り出します。
3. 正常終了時は終了コード 0 で終了する。標準エラーは自由に使ってよい（ログ扱いになり、
   レポートには出力されません）。

## セキュリティ上の注意

`[external_recognizer].command` は**設定ファイルに書かれた任意のコマンドを実行する**
機能です。

- **リポジトリ内の `.jp-pii.toml` を信用できない環境では使わないでください**（fork からの
  PR を未レビューで CI 実行するような構成では、悪意あるコマンドが紛れ込む余地があります）。
- 可能な限り `--config <path>` で明示指定した設定ファイルでのみ有効化し、リポジトリルートの
  `.jp-pii.toml` の自動探索に外部コマンド実行の可否を委ねないことを推奨します。
- jp-pii-detect は環境変数や自動探索ではコマンドを拾いません。`[external_recognizer].command`
  を設定ファイルへ明示的に書いた場合のみ有効になります。
- 子プロセスは走査対象ファイルの**全文**を受け取ります。子プロセス自体・その依存関係
  （PyPI パッケージ等）の信頼性は利用者の責任範囲です。

このリポジトリ自身の `.jp-pii.toml` には `external_recognizer` を意図的に追加していません
（CI のドッグフーディングで任意コマンドを実行したくないため）。
