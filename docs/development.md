# 開発者向けガイド

jp-pii-detect のビルド、テスト、内部構成と、検出ルールの追加方法をまとめます。
利用方法は [README](../README.md)、検出手法の調査と設計判断は
[detection-methods.md](detection-methods.md) を参照してください。

## 目次

- [日常の開発](#日常の開発)
  - [ビルドとテスト](#ビルドとテスト)
  - [ベンチマーク](#ベンチマーク)
- [検出精度の計測と評価データセット](#検出精度の計測と評価データセット)
  - [検出精度の計測](#検出精度の計測)
    - [プロファイル別評価（low / medium / high-recall）](#プロファイル別評価low--medium--high-recall)
    - [陰性母数・検出単位 FP・want_confidence](#陰性母数検出単位-fpwant_confidence)
  - [評価データセット・テストフィクスチャの取得](#評価データセットテストフィクスチャの取得)
    - [ケースのタグ（表記ゆれ等の層化評価）](#ケースのタグ表記ゆれ等の層化評価)
  - [合成評価ケースジェネレータ（fixturegen）](#合成評価ケースジェネレータfixturegen)
  - [OSS コーパスでの偽陽性率計測（fp-corpus-report）](#oss-コーパスでの偽陽性率計測fp-corpus-report)
- [拡張と運用](#拡張と運用)
  - [プロジェクト構成](#プロジェクト構成)
    - [検出パイプライン](#検出パイプライン)
    - [テスト経路の信頼度降格（path demotion）](#テスト経路の信頼度降格path-demotion)
  - [検出ルールの追加](#検出ルールの追加)
    - [コード変更なしでルールを追加する（`.jp-pii.toml` のカスタムルール）](#コード変更なしでルールを追加するjp-piitoml-のカスタムルール)
    - [埋め込み辞書の更新](#埋め込み辞書の更新)
  - [リリース](#リリース)

## 日常の開発

### ビルドとテスト

```console
$ go test ./...                      # 全テスト
$ go test -race ./...                # データ競合の検査（並列スキャンの回帰防止）
$ go vet ./...                       # 静的解析
$ go build ./cmd/jp-pii-detect       # バイナリのビルド
```

バージョン文字列はビルド時に埋め込めます:

```console
$ go build -ldflags "-X main.version=v0.1.0" ./cmd/jp-pii-detect
```

### ベンチマーク

`normalize.Line` と `detect.ScanLine` にベンチマークがあります。
ホットパスを変更したら計測してください。

```console
$ go test -bench . -benchmem ./internal/normalize/ ./internal/detect/
```

純 ASCII 行（ソースコードの大半）に加え、変換対象（全角英数字・全角スペース・
ハイフン類・数字隣接の長音記号）を含まない通常の日本語行も、`normalize.Line` の
ファストパスでアロケーションが発生しない（0 allocs/op）ことが回帰テストで
保証されています。変換が必要な行でも `[]rune` は 1 本だけ確保します
（旧実装は漢字・かなを含むほぼ全ての日本語行が遅いパスへ入り 2 本確保していました）。

## 検出精度の計測と評価データセット

### 検出精度の計測

`internal/eval` にルールごとの陽性と陰性のケースを集めたラベル付き評価データセットと、
適合率、再現率、F1 を計測するハーネスがあります。

データセットは実在しうる PII を含むためリポジトリにはコミットせず、外部ストレージ
（GCS）で管理して `JP_PII_FIXTURES` 経由で読み込みます（取得手順は
「[評価データセット・テストフィクスチャの取得](#評価データセットテストフィクスチャの取得)」
を参照してください）。

README の検出精度バッジと [accuracy.md](accuracy.md) は、ルール自体の検出能力を見るため
`min_confidence=low`、高再現率ルール無効のプロファイルで測った実測値です。
`EvaluateWithOptions` / `EvaluateCasesWithOptions` を使うと、既定 CLI 相当
（`min_confidence=medium`）や高再現率ルール有効時も同じハーネスで評価できます。

`JP_PII_FIXTURES` が未設定の環境では eval 系テストは `t.Skip` され、ローカル/オフラインでも
`go test ./...` は緑のままになります。

```console
$ export JP_PII_FIXTURES=$PWD/pii-fixtures.json   # GCS から取得（取得手順は後述）
$ go test ./internal/eval            # 実測 F1 と wantF1・README バッジの一致を検証
$ go test ./internal/eval -update    # docs/accuracy.md と README のバッジを実測値で再生成
```

`eval_test.go` の `TestAccuracy` は実測 F1 が `wantF1` と一致するか、
`readme_test.go` の `TestReadmeBadges` は README の総合バッジとルール別バッジが
実測値と一致するかを検証します。

ルールやデータセットを変えて精度が動くと CI が落ちるので、**`wantF1` を更新し、
`-update` で README のバッジと `docs/accuracy.md` を再生成**してください。

#### プロファイル別評価（low / medium / high-recall）

`TestAccuracy` はテーブル駆動で 3 プロファイルを並行評価します（issue #43）。

| プロファイル | `Options` | ゴールデン値 | ゲート |
|---|---|---|---|
| `low` | `{MinConfidence: "low"}` | `wantF1`（既存・不動） | あり（README バッジ・`docs/accuracy.md` の根拠） |
| `medium` | `{MinConfidence: "medium"}` | `wantF1Medium` | あり |
| `high-recall` | `{MinConfidence: "low", HighRecall: true}` | なし | 計測・ログ出力のみ |

`medium` は CLI の既定設定（`internal/config` の既定値）に相当し、`person-name`
のように既定設定では黙って検出されなくなるルールを公式数値として可視化します
（`internal/rule/builtin.go` の person-name は全パターン `Base: Low` かつ
ルールレベルの `Context` が無く、`internal/detect` の信頼度昇格
（Context 一致で Low→High、中間の Medium 昇格経路は無い）が働かないため、
`min_confidence=medium` で常に除外されます）。`high-recall` プロファイルは、
対応する評価データセットのケース（`jp-address-high-recall` /
`person-name-high-recall` / `person-name-structured`）がまだ無いため、当面は
サブテストの `t.Logf` 出力のみでゲートしません。データセットにケースを追加した
後、`wantF1HighRecall` を追加してゲート化してください。

#### 陰性母数・検出単位 FP・want_confidence

`Result` には行レベルの `TP`/`FP`/`FN`（`wantF1` の算出に使う既存の集計。挙動は
変えていません）に加え、次のフィールドがあります。

- `Negatives`: データセット全体で `want`/`spans` が両方とも空の「陰性ケース」の
  総数（全ルール共通の母数）。FP を正規化した偽陽性率などに使えます。
- `FindingFP`: 期待されていないルールについて、ケース内で実際に検出された
  finding の総数。既存の `FP` はケースにつき最大 1 件（複数誤検出があっても 1
  と数える）ですが、`FindingFP` は同一ケース内の多重誤検出を過小評価しません。
- `ConfidenceMiss`: `spans` に任意項目 `want_confidence`（`"low"|"medium"|"high"`）
  を指定したケースで、検出はできた（span exact 一致）ものの実際の最終信頼度が
  期待未満だった件数。既定設定で黙って埋もれる「実質検出漏れ」を表します。

`want_confidence` は `piifixtures.Span` の任意項目（`omitempty`）で、既存の
データセット JSON には無いためコード先行でデプロイしても全テストが green の
まま動きます（`encoding/json` は未知フィールドを無視するため、逆に新しい JSON
を旧コードで読んでも安全です）。

これら 3 フィールドは現時点では `docs/accuracy.md` に出力しておらず、CI の
`TestGenerateDoc -update && git diff --exit-code docs/accuracy.md` ゲートの対象
にもしていません（`JP_PII_FIXTURES` が無いと実際のデータセットに対する値を
確認できないため）。`internal/eval/eval_test.go` には合成データ（フィクスチャ
不要）によるユニットテストがあります。

実データセットでの数値を `docs/accuracy.md` に反映する作業と、ドロップ候補記録
（negative-context / allowlist / overlap-lost / below-min-confidence 起因の FN
分析）は今後の課題です（issue #43 の段階 4・任意）。

### 評価データセット・テストフィクスチャの取得

評価データセットと各テストのフィクスチャは、実在しうる PII（電話番号・氏名・住所など）を含むため
リポジトリにコミットせず、非公開の GCS バケットで管理します。テスト時は環境変数 `JP_PII_FIXTURES`
にローカル JSON のパスを渡し、[`internal/piifixtures`](../internal/piifixtures/piifixtures.go) が
読み込みます。

未設定・取得不可なら依存テストは `t.Skip` され、ビルド・dogfooding・その他のテストは通ります。

ローカル開発（GCS への閲覧権限が必要）:

```console
$ gcloud auth application-default login
$ gcloud storage cp gs://<bucket>/pii-fixtures.json ./pii-fixtures.json
$ export JP_PII_FIXTURES=$PWD/pii-fixtures.json
$ go test ./...
```

`pii-fixtures.json` は `.gitignore` 済みでコミットされません。

JSON スキーマは
`{ "strings": { "<key>": "<値>" }, "dataset": [ { "file", "line", "content", "diff", "want", "spans", "tags" } ] }` で、
`line` / `content` / `diff` のいずれか 1 つを入力として指定します。`want` または `spans` が
あるケースでは入力指定漏れをエラーにします。`line` は単一行の `ScanLine`、`content` は複数行の `ScanContent`、`diff` は `{ "text", "added" }` の配列で
`ScanDiffHunk`（追加行だけを報告）を評価します。

`spans` は `{ "rule_id", "line", "start", "end", "want_confidence", "tags" }`
で、`line` は 1 始まり、`start` / `end` はその行内の 0 始まりルーンオフセットです
（`line` 省略時は後方互換のため 1 行目）。

`want_confidence`（`"low"|"medium"|"high"`）は
任意項目で、指定すると検出の最終信頼度が期待未満のとき `Result.ConfidenceMiss` に
計上されます（省略時はチェック対象外・既存データセットとの後方互換）。

`file` は任意で、`.go` や `.ts` などファイル名依存の
ソースコード文脈を評価したいケースだけ指定します。未指定時は従来どおり `dataset` として走査します。

詳細は `internal/piifixtures/piifixtures.go` の
コメントに定義があります。値を編集したら GCS に再アップロードします。

CI（GitHub Actions）は GitHub OIDC → GCP Workload Identity Federation で認証し、サービスアカウントの
鍵を持たずに取得します。リポジトリ変数 `JP_PII_FIXTURES_PROVIDER`（プロバイダのリソース名）・
`JP_PII_FIXTURES_SA`（サービスアカウントのメール）・`JP_PII_FIXTURES_BUCKET`（バケット名）を設定すると
`.github/workflows/ci.yml` が取得します。

未設定なら取得をスキップし、eval 系テストは Skip されます。

#### ケースのタグ（表記ゆれ等の層化評価）

`Case.Tags`（`Span.Tags` と同じ位置づけ。どちらも `[]string`、`omitempty`）は、表記ゆれ・
ラベル語彙・ケースの由来などでケースを層別集計するためのメタデータで、検出結果そのものには
影響しません。`internal/eval` の `EvaluateCasesStratifiedWithOptions` / `EvaluateStratified` が
`Stratified{Results, Tags, Kinds}` を返し、`Tags` はケースの `Tags` ごと、`Kinds` は入力形式
（`line` / `content` / `diff`）ごとの行レベル Score（1 ケースに複数ルールの期待・検出があれば
同じバケツへ合算）を持ちます。`docs/accuracy.md` の「タグ別」「ケース種別別」表は
`go test ./internal/eval -update`（`TestGenerateDoc`）が自動生成します。`Kinds` はデータセットの
`line`/`content`/`diff` の内訳から自動導出されるため、既存データセットにタグを追加しなくても
表に現れます。「タグ別」表は `Case.Tags` を付けたケースがあるときだけ現れます。

既知のタグ語彙（プレフィックス方式。`eval_test.go` の `knownCaseTagPrefixes` と揃える）:

| プレフィックス | 意味 | 例 |
|---|---|---|
| `notation:` | 全角/半角などの表記 | `notation:fullwidth` / `notation:halfwidth` |
| `sep:` | 数字グループの区切り種別 | `sep:none` / `sep:hyphen` / `sep:space` |
| `format:` | ラベル・値の形式 | `format:mark`（〒 記号）/ `format:word`（日本語ラベル語）/ `format:bare`（ラベルなし） |
| `label:` | ラベル語彙・強弱 | `label:jp-strong` / `label:weak-surname` / `label:ascii` |
| `layout:` | ラベルと値の位置関係 | `layout:cross-line`（ラベルと値が別行） |
| `source:` | ケースの由来 | `source:synthetic`（internal/fixturegen による計算合成） |
| `polarity:` | 期待検出の極性 | `polarity:negative`（陰性ケースであることの明示） |
| `rule:` | 対象ルール ID（タグ内で自己文書化） | `rule:jp-my-number` |

`easy` / `hard`（プレフィックスなし）は既存の `Span.Tags` の慣用タグとして許容します。
未知のタグ（typo で層が分裂する等）は `eval_test.go` の `TestCaseTagsAreKnown` が検出しますが、
フェーズ1では CI を落とさない非致命的な警告（`t.Logf`）に留めています。新しい層化軸が必要になったら
このタグ表と `knownCaseTagPrefixes` の両方を更新してください。

### 合成評価ケースジェネレータ（fixturegen）

[`internal/fixturegen`](../internal/fixturegen/fixturegen.go) は、「ルール × 表記ゆれ」の
マトリクス（ラベル語彙・区切り種別・全角/半角・ラベル位置など）に沿った評価ケースを計算合成します。
値はすべて `internal/checksum` のチェックディジット算出ロジックや `internal/dict` の実在辞書
（姓名辞書・郵便番号ビットセット）から逆算・抽出したもので、リテラルの実在 PII はソースに
一切書きません（ドッグフード CI 対策。値をコメント等に書き写す例示もしないこと）。対応ルールは、
値を計算合成できるものに限定しています: `jp-my-number`（`checksum.MyNumber` の検査式を逆算）、
`credit-card`（`checksum.Luhn` を逆算 + ブランドプレフィックス）、`jp-postal-code`
（`dict.SamplePostalCodes` で実在番号を抽出。郵便番号自体はチェックディジットを持たないため
実在性でしか合成できないが、`postal_codes.bitset` は既にコミット済みで新規の秘匿情報ではない）、
`person-name`（`dict.SurnameSample` / `dict.GivenNameSample` で辞書から実在の姓・名を抽出）。

生成したケースはすべて `source:synthetic` タグを持ち、実採取データと区別できます（層別集計・
マクロ平均でウェイトを分けられる）。`internal/fixturegen/integration_test.go` は生成したケース
全件を `internal/eval.EvaluateCases` に通し、対象 4 ルールの FN・FP が 0 であることを検証する
自己完結の回帰テストで、`JP_PII_FIXTURES` は不要です（表記ゆれへのルールの頑健性を、外部データセット
なしでも継続的に確認できる）。

`cmd/pii-dataset-gen` は `internal/fixturegen.Generate()` を `internal/piifixtures` 互換の JSON
として書き出す CLI です:

```console
$ go run ./cmd/pii-dataset-gen -output /path/outside/repo/synthetic-cases.json
```

出力先は必ずこのリポジトリの管理外のパスにしてください。生成物はレビューのうえ、既存の外部評価
データセット（`pii-fixtures.json`。GCS 管理）へ人手でマージし、GCS へ再アップロードする運用を
想定しており、この CLI 自体は GCS への書き込みを行いません。マージすると `TestAccuracy` の
`wantF1`・README バッジ・`docs/accuracy.md` が実測値からずれるため、
「[検出精度の計測](#検出精度の計測)」節の手順で `wantF1` を更新し `-update` で再生成してください。
生成件数はルールあたり数十件規模に抑えています
（Issue #70 のフェーズ2方針: 段階的に増やし、マイクロ平均への影響と `wantF1` の安定性を見ながら
判断します）。

### OSS コーパスでの偽陽性率計測（fp-corpus-report）

`internal/eval` の適合率・再現率は自リポジトリの外部フィクスチャ（ラベル付きデータセット）で
測っていますが、実運用の偽陽性率（findings/MLoC）を測る仕組みは自リポジトリの dogfooding
（`ci.yml`、既定で 0 件期待）しかありません。小さな自リポジトリ 1 つでは陰性母数が不足し、
`NegativeContext` 追加や allowlist 追加のような偽陽性削減施策の効果を測る場がないため、
[`.github/workflows/fp-corpus-report.yml`](../.github/workflows/fp-corpus-report.yml) が
大規模公開 OSS コーパスに対して定期的に jp-pii-detect を走らせ、findings/MLoC を
トレンド指標として記録します。**このワークフローは `ci.yml` の test job（wantF1・README
バッジ・ドッグフードのゲート）とは完全に独立しており、成否が PR CI に影響することはありません。**
非ゲートのトレンド指標であり、現時点で CI を落とす仕組みにはしていません。

集計は [`scripts/fp-corpus-report.sh`](../scripts/fp-corpus-report.sh) が担います。
`jp-pii-detect scan --format json --exit-zero <corpus-dir>` の出力（マスク済み値のみ）を
`rule_id` ごとの件数に集計し、`<corpus-dir>` 配下の物理行数（`find <dir> -type f | xargs wc -l`
相当）で割った `findings/MLoC` を計算します。マスク済みの `match` 値すら出力に含めません
（件数集計のみ）。

**コーパス選定基準**: 大規模かつ長期間・広く第三者に精査されている著名 OSS（標準ライブラリ・
ビルドツール等）に限定します。自治体オープンデータ処理系のように実 PII を扱う蓋然性が高い
カテゴリは対象外です。日本語コメントを含む対象を追加する場合は、個人ブログ的なサンプル
データを含まない、企業がメンテする本体コードに限定してください。

**コーパスの追加・更新手順（初回 1 回、手動レビュー必須）**:

1. 対象リポジトリの安定版タグに対応するコミット SHA を確認します
   （`git ls-remote --tags <url>` など。ワークフロー再実行時に upstream の変更で
   トレンドがノイズ化しないよう、コミットを固定します）。
2. ローカルでそのコミットを浅く取得し、`jp-pii-detect scan --format text --unmask <dir>`
   を実行します。報告される findings の大半は JAN コード・型番・テスト用カード番号・
   スコア/日付が住所形式に一致した、といった偽陽性のはずです。目視で内容を確認し、
   実在しうる PII が含まれていないことを確認します。
3. 問題がなければ `.github/workflows/fp-corpus-report.yml` のコーパス一覧
   （`name|git-url|commit-sha` 形式）にコミット SHA を固定して登録します。

**結果の保存先**: 集計結果はリポジトリの公開 `docs/` には置かず、既存の PII フィクスチャと
同じ非公開 GCS バケット（`JP_PII_FIXTURES_BUCKET` と同じバケット、OIDC 経路も再利用し
新たな長期認証情報は追加しない）に `fp-corpus-report/` プレフィックスで JSON/Markdown
スナップショットを保存します。コーパス名付きの内訳（`detail.json`）は非公開バケットにのみ
保存し、ワークフローのログや `GITHUB_STEP_SUMMARY`、および公開する場合はコーパス名を伏せた
ルール別合計のみの `summary.json`/`summary.md` に限定します
（実リポジトリ名と findings 内訳の組を公開の場に出さないための責任ある開示上の配慮）。

**運用フェーズ**: 初期運用は `workflow_dispatch` のみです。数回分の手動実行でノイズ
（コーパスの dead link・想定外の実 PII 混入）がないことを確認できたら、ワークフロー内の
`schedule` のコメントアウトを外して週次 cron に昇格してください。

## 拡張と運用

### プロジェクト構成

```
cmd/jp-pii-detect/   CLI エントリポイント（引数解析・出力フォーマットの振り分け・終了コード）
cmd/pii-dataset-gen/ fixturegen の合成ケースを piifixtures 互換 JSON へ書き出す CLI
internal/
  config/    .jp-pii.toml の読み込み（リポジトリルートまでの上方探索）
  source/    走査対象の列挙: ファイルツリー（並列）/ git diff の追加行
  detect/    行単位の検出エンジン（ScanLine/ScanContent・ソースコード文脈・重複解決）
  normalize/ 日本語テキストの正規化（全角→半角・ハイフン類・長音記号）
  rule/      検出ルールの型定義と組み込みルール一覧
  checksum/  チェックディジット検証（マイナンバー・Luhn・カードブランド）
  dict/      IANA TLD などの埋め込み辞書
  report/    出力フォーマット（text/json/sarif/github）とマスキング
  piifixtures/ 実在しうる PII を含む外部フィクスチャ（JP_PII_FIXTURES の JSON）のローダ
  eval/      ラベル付き評価データセットと検出精度（適合率・再現率・F1・タグ/ケース種別の層別）の計測
  fixturegen/ ルール×表記ゆれのマトリクスを計算合成する評価ケースジェネレータ
```

#### 検出パイプライン

1. **source** が走査対象を列挙します。
   - フルスキャン: ファイルツリーを walk し、バイナリ（先頭 8KB に NUL）、5MB 超、
     `node_modules` 等の依存ディレクトリを除外します。
   - git モード: `git diff -U3` で文脈行付きの差分を取得し、`detect.ScanDiffHunk` で
     走査します。検出値が**追加行に乗っているもののみ**を報告し、文脈行（未変更行）上の
     既存 PII は報告しません。
   - ラベルが**直前・直後の未変更行**にあり値だけを追加したケースでも、コンテキスト必須
     ルールが発火します（行をまたぐ相関は隣接 ±1 行のみ。ScanContent の 2 行ウィンドウに
     準ずる）。
   - 文脈行は正のコンテキスト補完にのみ使い、抑制（ignore マーカー・負コンテキスト）の
     駆動には使わないため、追加行の新規 PII を既存行の都合で取りこぼしません。
2. **detect.ScanLine** が 1 行ごとに処理します。
   - **normalize.Line** で全角英数字、ハイフン類、数字隣接の長音記号を半角化します。
     変換はルーン単位の 1:1 に限定しているため、正規化後の位置がそのまま元テキストの
     位置になり、列番号の報告に逆引きが不要です。
   - ルールの `Prefilter`（数字、`@`、日本語などの必須文字種）を含まない行は
     正規表現マッチ自体をスキップします。大半のルールは数字必須のため、
     数字を含まないコード行がほぼ無コストになります。
   - `.go`、`.ts`、`.py`、`.json`、`.yaml`、`.env` など既知のソースコード/設定ファイルでは、
     変数名・キー名・代入/key-value 構造を軽量な source context として抽出します。
     source context は文脈判定にだけ使い、正規表現は従来どおり正規化済みの元行だけを走査します。
     statement の値範囲は正規化済み行の byte offset で持ち、候補マッチがその範囲内にある場合だけ
     `PositiveText` / `NegativeText` を適用します。AST 解析や言語別 parser は使いません。
   - 各ルールのパターンを正規表現でマッチし、`Validate`（チェックディジット等）と
     allowlist で絞り込みます。
     - 同一行にコンテキストキーワードがあれば信頼度を High に昇格し、`RequireContext`
       のルールはキーワードがなければ破棄します。`RequireContextWindow` が設定された
       ルールでは、キーワードをマッチ前後の指定ルーン数以内に限定します。
     - ASCII キーワードは英数字の単語境界つきで照合し、`tel` が `hotel` の一部で成立する
       ような誤昇格を避けます。単語境界で見つからない場合は、行中の識別子を camelCase /
       snake_case / kebab-case の構成語に分割して照合するため、`account_no` が
       `bankAccountNo` を、`phone` が `phoneNumber` を拾えます（`smartphone` のように
       語の途中に埋もれた場合は成立しません）。source context 由来の `bankAccountNo` なども
       同じトークン照合でコンテキストになります。
     - `NegativeContext` が近傍にある場合は、金額、数量、連番 ID とみなして検出を棄却します。
       コード内の `orderId`、`version`、`count` などは source context 由来のコード限定
       `NegativeText` として、該当 statement の値だけを抑制します。
     - `RequireContext` のパターンはキーワードの存在が前提のため昇格せず、`Base` の
       信頼度のまま報告します。
   - **resolveOverlaps** で範囲が重なる検出を信頼度（同率なら長い方）で 1 件に集約します。
   - **detect.ScanContent** は通常の行単位検出に加え、隣接 2 行を結合した仮想ウィンドウを
     `RequireContext` ルールに限定して走査します。検出位置は元の行と列へマップし直します。
     ソースコード文脈では、`bankAccountNo:` の次行に値があるような key/value 分離も
     logical context として値行に付与します。diff では文脈行由来の source context は正の
     コンテキスト補完にだけ使い、文脈行由来の負コンテキストでは追加行を抑制しません。
     隣接 2 行の仮想ウィンドウで得た finding も、元の値行へ戻した後にその行の source
     `NegativeText` を評価し、コード限定の負コンテキストを迂回しません。
3. **report** が `min_confidence` で絞った結果を指定フォーマットで出力します。
   検出値は既定でマスクされます。JSON 出力では `--explain` 指定時のみ `reason` を含めます。

#### テスト経路の信頼度降格（path demotion）

`internal/detect/path_profile.go` の `isTestPath` は、`testdata/`・`fixtures/`・
`__tests__/`・`spec/`・`mocks/`・`seed(s)/` のいずれかのディレクトリ成分、または
`_test.go` / `.spec.` / `.test.` を含むファイル名を「ダミーデータが集中しやすいテスト
経路」と判定します。`Detector.ScanContent` / `ScanDiffHunk` は Finding 確定後・重複解決前に、
このパスシグナルを使って **`RequireContext: true` かつ `Base` が Medium のパターン**
（`jp-postal-code` の桁のみパターン・`jp-bank-account`・`jp-health-insurance` が該当）に
限り信頼度を Medium→Low に 1 段階だけ落とします（`DetectReason.PathDemoted` が true になる）。

- **降格であって除外ではない**。既定の `min_confidence = "medium"` 運用だと Low は
  表示されなくなりますが、`--min-confidence low` を指定すれば降格後も見えます。テストデータに
  本物の PII が誤って貼られても完全に不可視にはなりません。
- **対象は Base Medium の RequireContext ルールのみ**。`credit-card` や `jp-my-number`、
  `jp-drivers-license`（Base High）のように、Base が High 固定、または `RequireContext`
  を使わないルールは対象外です。実データがテスト経路に混入した場合の検出力を落とさないための
  意図的な線引きです。
- `[rules] path_demotion = false` で機能全体を無効化できます（既定は有効）。
- allowlist（`.jp-pii.toml` の `paths` / 行末 `jp-pii-detector:ignore`）とは独立した
  補助的な信頼度シグナルであり、置き換えるものではありません。High 固定ルールが
  `*_test.go` 等で大量に誤検出する場合は、引き続き allowlist での除外や行単位の
  ignore マーカーが必要になります（本リポジトリの `.jp-pii.toml` の `_test\.go$` は
  この理由で残しています）。

### 検出ルールの追加

ルールは [`internal/rule/builtin.go`](../internal/rule/builtin.go) の `Builtin()` に
`rule.Rule` を追加するだけで有効になります。

```go
{
    ID:          "jp-example",
    Description: "説明（rules コマンドと検出結果に表示される）",
    Context:              []string{"キーワード"}, // 小文字で定義。昇格・RequireContext 判定に使う
    NegativeContext:      []string{"円", "件"}, // 近傍にあれば棄却する語（任意）
    RequireContextWindow: 40,          // 0 なら行全体、正数なら前後ルーン数で近接判定
    Prefilter:            PrefilterDigit, // 数字を含む行のみ走査（性能最適化。既定は常に走査）
    Validate: func(m string) bool {   // 追加検証（任意）。引数は正規化済みのマッチ文字列
        return checksum.Something(m)
    },
    Patterns: []Pattern{
        // 数字エンティティは dg() で前後の数字境界をガードする。
        // グループ 1 が検出対象になる（境界ガードはグループ外）。
        {Re: dg(`\d{10}`), Base: rule.Medium, RequireContext: true},
    },
},
```

ポイント:

- **境界ガード**: 長い数字列の部分一致を防ぐため、数字は `dg()`、英数字は `ag()` で囲みます。
  これらはキャプチャグループ 1 に本体を入れるので、`ScanLine` はグループ 1 を検出対象にします。
- **信頼度の設計**: 桁数しか手がかりがないルールは `RequireContext: true` にして
  偽陽性を抑えます。検証だけで十分な精度なら `Base: High`。`RequireContext` の
  パターンはコンテキストによる昇格が起きないため、`Base` がそのまま報告される
  信頼度になります。
- **コンテキストの設計**: ASCII キーワードは単語境界つき、加えて camelCase /
  snake_case / kebab-case の識別子を構成語に分割して照合されます（`account_no` ⇔
  `bankAccountNo`）。ソースコード/設定ファイルでは、変数名やキー名も同じ仕組みで
  source context として使われます。桁数だけのルールは
  `RequireContextWindow` で肯定語を近接必須にし、金額、数量、連番 ID と衝突しやすい場合は
  `NegativeContext` を設定します。`id`、`version`、`count` などコード特有のノイズは、
  通常テキストにも効く `NegativeContext` へ安易に追加せず、source context 側の
  コード限定 `NegativeText` として扱います。
- **Prefilter**: パターンが特定の文字種（数字、`@`、日本語）なしにマッチし得ない
  場合は `Prefilter` を設定します。該当文字を含まない行の走査が丸ごと省けます。
  迷ったら未設定（常に走査）が安全です。
- **検証ロジック**: チェックディジットなどは `internal/checksum` に置き、独立にテストします。
  実在性確認に使う小さな静的辞書は `internal/dict` に置き、`//go:embed` で同梱します。
- **高再現率ルール**: 偽陽性リスクが高いルールは `internal/rule/high_recall.go` の
  `HighRecallRuleIDs()` に追加し、既定では `[rules] high_recall = true` または
  `--high-recall` が指定されたときだけ有効になるようにします。
- **テスト**: 検出と非検出の両方を [`internal/detect/detect_test.go`](../internal/detect/detect_test.go) に追加します。
  特に「隣接する複数件」「コンテキスト有無での信頼度」「長い数字列の一部は対象外」を確認してください。

新ルールは `jp-pii-detect rules` に自動で表示されます。

#### コード変更なしでルールを追加する（`.jp-pii.toml` のカスタムルール）

学籍番号・社員番号・診察券番号など、組織ごとに形式が異なる ID は builtin ルールでは
原理的にカバーできません。`.jp-pii.toml` の `[[rules.custom]]` で、コードを変更せずに
利用者定義の検出ルールを追加できます。

例: 学籍番号（`S` + 8 桁数字、例 `S12345678`）を組織固有 ID として追加する。

```toml
[[rules.custom]]
id = "student-id"                    # 必須。builtin ルールおよび他の custom ルールと重複不可
description = "学籍番号"              # rules コマンド・検出結果に表示される説明
pattern = 'S\d{8}'                   # Go の RE2 正規表現。TOML はリテラル文字列（'...'）が
                                      # バックスラッシュをそのまま渡せて書きやすい
context = ["学籍番号", "student_id"]  # 信頼度昇格・require_context 判定に使うキーワード
negative_context = ["サンプル"]       # 近傍にあれば棄却する語（任意）
require_context = true               # true ならキーワードが無い検出を破棄する
require_context_window = 20          # require_context のキーワード探索をマッチ前後
                                      # 20 ルーンに限定（0 または省略なら行全体）
base_confidence = "high"             # low|medium|high。省略時は medium
digit_boundary = true                # true なら builtin の dg() と同じ境界ガード
                                      # `(?:^|[^0-9])(pattern)(?:[^0-9]|$)` で包み、
                                      # より長い数字列の一部を誤検出しないようにする
```

ポイントと制約:

- **境界ガード**: 数字エンティティは `digit_boundary = true` を使うと、builtin の `dg()` と
  同じ規約でグループ 1 が検出対象になります。`false`（既定）の場合、パターン自身に
  キャプチャグループがあればグループ 1、無ければマッチ全体を検出値として使います。
- **id の重複はエラー**: builtin ルール ID や他の custom ルール ID と衝突する場合、
  正規表現のコンパイルに失敗する場合はいずれも `.jp-pii.toml` のロード時にエラー
  （exit code 2）になります。パニックはしません。
- **Prefilter が効かない**: builtin ルールと異なり custom ルールには `Prefilter` の
  最適化が無いため、行ごとに必ず正規表現を評価します。パターンが広すぎたり `.` を
  多用するとスキャン性能が落ちうるので、可能な限り具体的なパターンにしてください。
- **精度は自動計測されない**: `internal/eval` は builtin ルールのみを対象にした
  固定プロファイルで測っており、`.jp-pii.toml` の custom ルールは評価対象外
  （README バッジ・`docs/accuracy.md` には影響しません）。誤検出の調整は
  `negative_context` / `require_context` / `require_context_window` で行い、
  実際の検出結果で確認してください。
- `jp-pii-detect rules [--config <path>]` で、有効化されている builtin + custom の
  実効ルール一覧（`rules.disabled` を反映済み）を確認できます。

#### 埋め込み辞書の更新

IANA TLD 一覧は公式の `https://data.iana.org/TLD/tlds-alpha-by-domain.txt` を
[`internal/dict/tlds-alpha-by-domain.txt`](../internal/dict/tlds-alpha-by-domain.txt) に保存しています。

更新は通常 [`.github/workflows/tld-update.yml`](../.github/workflows/tld-update.yml) が
毎月 1 日に自動で行います（新規委任 TLD の見落としによる偽陰性、廃止 TLD が辞書に残り続けることによる
偽陽性の温床化を防ぐため）。gTLD/ccTLD の削除は極めて稀なため、削除が 1 件でも検出された場合は
PR タイトルに `[要レビュー]` を付与し、本文に削除された TLD 一覧を明記するので、マージ前に必ず
目視でレビューしてください。手動で更新する場合は同 URL から取得して
`internal/dict/tlds-alpha-by-domain.txt` を置き換え、
`go test ./internal/dict ./internal/detect ./internal/eval` で検証します。

郵便番号は日本郵便の UTF-8 版「住所の郵便番号」全データと、事業所の個別郵便番号
（大口事業所向け、jigyosyo）データを合わせて 7 桁の実在集合をビットセット化し、
[`internal/dict/postal_codes.bitset`](../internal/dict/postal_codes.bitset)
（10,000,000 ビット = 1,250,000 バイト）に保存して `//go:embed` で取り込みます。
`dict.ValidPostalCode` はこのビットセットで **7 桁完全一致**を判定します（上位 3 桁ではなく
7 桁すべてで実在を確認するため、`150-9999` のように上位 3 桁は実在しても 7 桁としては
未割当の番号は棄却されます）。インデックスのエンコーディングとサイズ定数は `internal/dict` 側で
公開し、ジェネレータと共有します（両者が無言で乖離しないため）。

更新は通常 [`.github/workflows/postal-update.yml`](../.github/workflows/postal-update.yml) が
毎月 1 日に自動で行います。手動で更新する場合は次の 2 つのデータを取得し、コマンドでビットセットを
再生成してから `go test ./internal/dict ./internal/dict/gen ./internal/detect ./internal/eval` で検証します。

- 住所の郵便番号（UTF-8）: `https://www.post.japanpost.jp/zipcode/dl/utf-zip.html`
  （`utf_ken_all.zip` / `KEN_ALL.CSV`）
- 事業所の個別郵便番号（Shift_JIS）: `https://www.post.japanpost.jp/zipcode/dl/jigyosyo/index-zip.html`
  （`jigyosyo.zip` / `JIGYOSYO.CSV`）

```console
$ go run ./internal/dict/gen \
    -ken-all-input /path/to/utf_ken_all.zip \
    -jigyosyo-input /path/to/jigyosyo.zip \
    -output internal/dict/postal_codes.bitset
```

`-ken-all-input` / `-jigyosyo-input` はどちらか片方だけでも、両方指定してもよいです
（両方指定時はマージされ、重複コードは自動的に排除されます）。それぞれ展開済みの CSV
（前者は UTF-8、後者は Shift_JIS）も直接指定できます。列インデックス（ken_all は郵便番号が
3 列目、jigyosyo は 8 列目）はフォーマットごとに固定なので、`-ken-all-input` と
`-jigyosyo-input` を取り違えないでください（取り違えると実質ゼロ件取り込みになります）。
郵便番号の増減で `jp-postal-code` の精度数値が動くことがあるため、新しいビットセットを
コミットしたら eval / バッジの再生成も行ってください。

固定電話の市外局番は総務省の電気通信番号指定状況（「市外局番の一覧」）由来の実在集合を
[`internal/dict/area_codes.txt`](../internal/dict/area_codes.txt) にテキストで保存して
`//go:embed` で取り込みます。`dict.ValidAreaCode` は電話番号の先頭から**最長一致**する
市外局番を探し、`validPhone`（`internal/rule/builtin.go`）が区切りなし固定電話 10 桁の
実在性検証に使います。市外局番はほぼ変化しないため、郵便番号のような月次自動更新ワークフローは
設けていません。

> **既知の制限（#56 時点）**: `area_codes.txt` は総務省の公式データそのものではなく、
> 都道府県庁所在地・政令指定都市クラスの市外局番（46 件、2〜3 桁のみ）に絞った
> **代表的なシードデータ**です。総務省が公開する市外局番は全国で約 500 件（4〜5 桁の
> 中小都市分を含む）あり、このシードはそのごく一部にすぎません。未収録の実在市外局番を使う
> 固定電話番号は誤って未検出（false negative）になります。総務省の公式データを取得できる環境で、
> 市外局番列を抽出した CSV（1 列目が市外局番。ヘッダ行や他の列があっても無視される）を用意し、
> 次のコマンドで完全な一覧に差し替えてください。

```console
$ go run ./internal/dict/gen -phone \
    -input /path/to/area_codes_raw.csv \
    -output internal/dict/area_codes.txt
```

差し替え後は `go test ./internal/dict ./internal/detect ./internal/rule` に加えて、
`JP_PII_FIXTURES=<path> go test ./internal/eval` で `jp-phone-number` の F1 を再測定し、
必要なら `wantF1` を更新のうえ `-update` で README バッジと `docs/accuracy.md` を
再生成してください（区切りなし固定電話 10 桁の正例・未割当プレフィックスの負例を
評価データセットに追加した場合は特に必要です）。

新ルールは `jp-pii-detect rules` に自動で表示されます。

### リリース

`v*` タグを push すると `.github/workflows/release.yml` が Linux runner 上で
`linux/darwin/windows` × `amd64/arm64` のビルド済みバイナリを作成し、
GitHub Release に `jp-pii-detect_<goos>_<goarch>.tar.gz` と `checksums.txt` を添付します。
release job は asset 作成前に `go test ./...` を実行し、tagged commit がテストを通った場合だけ
publish します。

GitHub Action と pre-commit フックはこの Release asset を取得して実行するため、
利用側の環境に Go は不要です。installer は `checksums.txt` で SHA-256 を検証してから
展開します。Windows 向け asset も POSIX shell から扱えるよう `.tar.gz` に統一しています。
Go が入っている開発環境向けには
`go install github.com/baneido/jp-pii-detector/cmd/jp-pii-detect@<version>` も引き続き使えます。

README と action.yml の例で参照しているバージョン（`rev: v0.1.0` 等）も合わせて更新してください。
