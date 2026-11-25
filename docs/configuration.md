# 設定と検出の抑制

`.jp-pii.toml` の全項目、信頼度、ignore マーカー、ベースライン、外部レコグナイザ連携をまとめています。
最小の設定例は [README](../README.md#設定) にあります。

## 設定ファイル（.jp-pii.toml）

リポジトリルートに `.jp-pii.toml` を置くと自動で読み込まれます。カレントディレクトリから
親ディレクトリをたどってリポジトリルート（`.git` のあるディレクトリ）まで探すため、サブディレクトリから実行しても
ルートの設定が使われます（`--config` で明示的に指定することもできます）。

```toml
# 報告する最小信頼度: low | medium | high（デフォルト: medium）
min_confidence = "medium"

[rules]
# 無効化するルール ID（`jp-pii-detect rules` で一覧表示）
disabled = ["person-name"]
# 都道府県なし住所・敬称アンカー付き氏名・ラベルと値が別行の氏名（フォーム形式）など、
# 偽陽性リスクの高い追加ルールを有効化
high_recall = false
# ラベルも敬称も無く氏名だけが改行区切りで並ぶ名簿ファイルの判定（person-name-roster）を有効化。
# 行単位の手がかりを一切使わずファイル全体の統計だけで判断するため、high_recall とは別の opt-in
name_roster = false
# 氏名系ルール（person-name / person-name-role-label / person-name-high-recall）の low / medium 候補を、
# 同一ファイル内の近傍（±5行）に電話番号・郵便番号・マイナンバー等の検証済み高信頼 PII が
# あるときだけ 1 段昇格（low→medium、まれに medium→high）させる。CSV/DB ダンプ監査など、
# 強めの検出をしたい場合のみ opt-in する（既定では既存の出力に影響しない）
cooccurrence_boost = false
# ルール横断の下位種別（Reason.kind）のうち、指定した種別を検出結果から除外する（既定は未設定＝
# 全種別検出）。電話番号ルール（jp-phone-number）は service=フリーダイヤル等・ip・mobile・fixed・
# international、インボイス登録番号ルール（jp-invoice-number）は国税庁公表の公開情報であることを示す
# public-business を付与する。詳細は docs/detection-methods.md の「電話番号の下位種別分類」を参照
exclude_kinds = ["service"]

[scan]
# フルスキャンで .gitignore 等に無視された未追跡ファイルを走査しない（既定: true）。
# 追跡済みファイルは対象のまま。--no-gitignore で一時的に無効化できます
respect_gitignore = true

[allowlist]
# スキャン対象から除外するパス（glob または正規表現）。glob の * は 1 階層、
# ** は 0 階層以上にマッチします。フルスキャンでは走査時のパス表記に加えて
# リポジトリルートからの相対パスにも適用されるため、サブディレクトリから
# 実行しても ^testdata/ や path/to/*.txt のようなルート相対の指定が機能します。
# パターンは祖先ディレクトリにも評価されるため、"**/generated" のような
# ディレクトリ指定はフルスキャン・--staged・--diff のどれでも配下全体を除外します。
paths = ["path/to/*.txt", "path/to/**/target", "^testdata/", "\\.lock$"]
# マッチ文字列に対する除外（正規表現）。例: 自社ドメインのメール
regexes = ["@baneido\\.com$"]
# 完全一致で除外するダミー値
stopwords = ["090-XXXX-XXXX"]
```

`high_recall` と `name_roster` はそれぞれ `--high-recall`、`--name-roster` で実行時に有効にすることもできます。
現在の設定で各ルールが有効か、また高再現率ルールかを確認するには `jp-pii-detect rules` を実行します。
`rules --high-recall` や `rules --config <path>` も scan と同じ設定を反映します。

## ignore マーカー

意図的なダミー値は、同じ行のコメントに ignore マーカーを書くと除外できます。

```python
TEST_PHONE = "090-XXXX-XXXX"  # jp-pii-detector:ignore テスト用ダミー
```

旧マーカー `pii-allow` も互換性のため引き続き利用できます。

## 信頼度

既定では信頼度 `medium` 以上の検出だけを報告します（`min_confidence` で変更できます）。

信頼度は値の近くに「TEL」「住所」などのキーワードがあるかどうかで `low` / `medium` / `high` に分かれます。
ただし、キーワードがないと検出しないルールでは、キーワードがあっても信頼度は上がらず、ルールごとに決めた信頼度で報告します。
運転免許証番号、旅券番号、基礎年金番号、在留カード番号、ゆうちょ銀行の記号番号、雇用保険被保険者番号、
住民票コードは `high`、銀行口座番号、健康保険の保険者番号等、介護保険被保険者番号、生年月日、氏名は `medium` です。

氏名は姓名辞書に一致するか、空白で区切られた「姓 名」のうち姓か名の片側が辞書にあれば `medium` になり、既定でも報告します。
姓も名も辞書に載っていない値は誤検出の可能性が高いため `low` とし、既定では表示しません。
担当者・宛名ラベル（`担当:`/`担当者:`/`宛名:`/`連絡先:`/`代表者:`）の氏名は、姓と名の両方が辞書に一致すれば `medium`、
姓だけが一致すれば `low` です（`person-name-role-label`）。
`[rules] cooccurrence_boost = true` を設定すると、この `low` の氏名も、同じファイルの前後 5 行以内に
電話番号やマイナンバーなど検証済みで信頼度の高い PII があるときに限り、信頼度を 1 段上げて報告します。

## ベースライン

既存リポジトリに導入すると、過去に混入済みの PII やダミー値が一斉に検出されて CI が
通らなくなることがあります。gitleaks の `--baseline-path` や detect-secrets の
`.secrets.baseline` と同様に、ベースラインファイルへ既知の検出を記録しておくと、
以降のスキャンでは新しく追加された検出だけで fail させられます。

```sh
# 導入時: 現在の検出内容でベースラインファイルを作成（以後は --baseline とセットで使う）
$ jp-pii-detect scan --baseline .jp-pii-baseline.json --update-baseline .

# 通常運用: ベースライン記録済みの検出は結果・終了コードから除外される
$ jp-pii-detect scan --baseline .jp-pii-baseline.json .

# 除外された検出も参考表示したい場合（終了コードには影響しない）
$ jp-pii-detect scan --baseline .jp-pii-baseline.json --show-baseline .
```

`--baseline` / `--update-baseline` / `--show-baseline` は、`--staged`、`--diff`、フルスキャンの
どのモードでも同じように動作します。フラグの組み合わせの制約は
[CLI リファレンス](cli.md#baseline-系フラグの組み合わせ制約)を参照してください。

ベースラインには検出値を salt 付き HMAC-SHA256 で計算した **値ハッシュ（fingerprint）** を記録します。
行の位置は fingerprint に影響しないので、ファイル内で行が前後に移動しても再検出されません。
一方、ルール ID、ファイルパス、検出値のどれかが変わると別の fingerprint になり、再び検出されます。
ファイルパスはリポジトリルートからの相対パスにそろえて照合するので、
サブディレクトリからのフルスキャンで作った baseline も、`--staged` や `--diff`、別のディレクトリからの実行で同じように一致します。

**セキュリティ上の注意**: salt 付きハッシュは複数リポジトリ間でのレインボーテーブルの使い回しを
防ぐものであり、ベースラインファイル自体を入手した第三者による低エントロピーな値
（7 桁の口座番号など）への総当たり照合を防ぐものではありません。ベースラインファイルは
元のソース履歴と同程度の機密度で扱ってください（公開リポジトリにコミットしない、
アクセス制御された場所で管理する、など）。

## 外部レコグナイザ連携（`external_recognizer`、opt-in）

軽量 NER（GiNZA や BERT など）による氏名検出などを、Go バイナリの依存関係を増やさずに組み込めます。
既定は未設定で、完全に無効です。

```toml
[external_recognizer]
command = ["python3", "my_ner.py"]  # argv 配列。シェル解釈はしない
timeout_seconds = 30                # 既定 30
max_findings = 1000                 # 既定 1000
```

プロトコル仕様、動作するデモ（[integrations/external-recognizer/](../integrations/external-recognizer/)）、
**セキュリティ上の注意**は
[docs/detection-methods.md の「4.8 外部レコグナイザ連携」](detection-methods.md#48-外部レコグナイザ連携external_recognizeropt-in)
を参照してください。特に、この機能は設定ファイルに書かれた任意コマンドを実行するため、
リポジトリ内の `.jp-pii.toml` を信用できない環境では使わないでください。
