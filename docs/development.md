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
  - [非公開評価コーパスの取得](#非公開評価コーパスの取得)
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
「[非公開評価コーパスの取得](#非公開評価コーパスの取得)」
を参照してください）。

README の検出精度バッジ、[accuracy.md](accuracy.md)、`docs/accuracy.json`
（ゴールデンファイル）は、ルール自体の検出能力を見るため `min_confidence=low`、
高再現率ルール無効のプロファイルで測った実測値です。
`EvaluateWithOptions` / `EvaluateCasesWithOptions` を使うと、既定 CLI 相当
（`min_confidence=medium`）や高再現率ルール有効時も同じハーネスで評価できます。

`JP_PII_FIXTURES` が未設定の環境では eval 系テストは `t.Skip` され、ローカル/オフラインでも
`go test ./...` は緑のままになります。

```console
$ export JP_PII_FIXTURES=$PWD/pii-fixtures.json   # GCS から取得（取得手順は後述）
$ go test ./internal/eval                                      # 実測値と docs/accuracy.json・README バッジの一致を検証
$ go test ./internal/eval -run 'TestGenerateDoc|TestReadmeBadges' -update  # docs/accuracy.md・docs/accuracy.json・README のバッジを実測値で再生成
```

`internal/eval/golden.go` が定義する `docs/accuracy.json` が、検出精度に関する
単一の情報源（ゴールデンファイル）です。`eval_test.go` の `TestAccuracy` は実測結果を
`BuildGolden` で組み立て、コミット済み `docs/accuracy.json` と `DiffGolden` で完全一致
比較します（許容誤差なし）。`readme_test.go` の `TestReadmeBadges` は README の総合
バッジとルール別バッジが実測値と一致するかを検証します。`dataset_quality_test.go` の
`TestDatasetQuality` は、F1 の一致だけでは検出できないデータセット自体の劣化
（`want`/`spans` の未知のルール ID・完全重複ケース・期待スパン付与の後退）を検証します。
ルールやデータセットを変えて精度が動くと CI が落ちるので、**`go test ./internal/eval -run
'TestGenerateDoc|TestReadmeBadges' -update` で `docs/accuracy.md`・`docs/accuracy.json`・
README のバッジをまとめて再生成してコミット**してください（手動での数値編集は不要です）。

#### プロファイル別評価（low / medium / high-recall）

`TestAccuracy` は low プロファイルをコミット済み `docs/accuracy.json`（ゴールデン
ファイル、`BuildGolden`/`DiffGolden`）との完全一致で検証したうえで、medium /
high-recall の 2 プロファイルをテーブル駆動で並行評価します（issue #43）。

| プロファイル | `Options` | ゴールデン値 | ゲート |
|---|---|---|---|
| `low` | `{MinConfidence: "low"}` | `docs/accuracy.json`（`DiffGolden`、許容誤差なし） | あり（README バッジ・`docs/accuracy.md` の根拠） |
| `medium` | `{MinConfidence: "medium"}` | `wantF1Medium`（許容誤差 0.005） | あり |
| `high-recall` | `{MinConfidence: "low", HighRecall: true}` | なし | 計測・ログ出力のみ |

`medium` は CLI の既定設定（`internal/config` の既定値）に相当します。`person-name` は
辞書検証済みの強いマッチが `Base: Medium` のため既定設定でも残る一方、辞書検証を伴わない
フォールバックは `Base: Low` のまま除外され、low プロファイルより F1 が下がります。
`high-recall` プロファイルは、
対応する評価データセットのケース（`jp-address-high-recall` /
`person-name-high-recall` / `person-name-structured`）がまだ無いため、当面は
サブテストの `t.Logf` 出力のみでゲートしません。データセットにケースを追加した
後、`wantF1HighRecall` を追加してゲート化してください。

#### 陰性母数・検出単位 FP・want_confidence

`Result` には行レベルの `TP`/`FP`/`FN`（low プロファイルのゴールデン値に使う
既存の集計。挙動は変えていません）に加え、次のフィールドがあります。

- `Negatives`: データセット全体で `want`/`spans` が両方とも空の「陰性ケース」の
  総数（全ルール共通の母数）。FP を正規化した偽陽性率などに使えます。
- `FindingFP`: 期待されていないルールについて、ケース内で実際に検出された
  finding の総数。既存の `FP` はケースにつき最大 1 件（複数誤検出があっても 1
  と数える）ですが、`FindingFP` は同一ケース内の多重誤検出を過小評価しません。
- `ConfidenceMiss`: `spans` に任意項目 `want_confidence`（`"low"|"medium"|"high"`）
  を指定したケースで、検出はできた（span exact 一致）ものの実際の最終信頼度が
  期待未満だった件数。既定設定で黙って埋もれる「実質検出漏れ」を表します。

`want_confidence` は `evalcase.Span` の任意項目（`omitempty`）で、既存の
データセット JSON には無いためコード先行でデプロイしても全テストが green の
まま動きます（`encoding/json` は未知フィールドを無視するため、逆に新しい JSON
を旧コードで読んでも安全です）。

これら 3 フィールドは現時点では `docs/accuracy.md` / `docs/accuracy.json` に出力しておらず、
ゴールデンの比較対象にもしていません（`JP_PII_FIXTURES` が無いと実際のデータセットに対する値を
確認できないため）。`internal/eval/eval_test.go` には合成データ（フィクスチャ不要）による
ユニットテストがあります。

実データセットでの数値を `docs/accuracy.md` に反映する作業は今後の課題です。

ドロップ候補記録（`--explain-dropped`、issue #43 段階4）は実装済みです。「検出候補が
どの段階で棄却されたか」を opt-in で記録・出力し、FN（見逃し）分析を容易にします。
棄却理由は次の固定語彙のいずれかです: `require-context-missing`
（RequireContext 不成立）・`negative-context`（同一行の負文脈）・
`cross-line-negative-context`（論理隣接行の負文脈）・`validate-failed`
（Rule/Pattern の Validate 不成立。チェックサム等）・`validate-line-failed`
（ValidateLine 不成立）・`allowlisted`（stopword / 正規表現 allowlist）・
`kind-excluded`（`[rules] exclude_kinds`）・`below-min-confidence`
（`min_confidence` 未満で破棄。cooccurrence_boost で保持に回った候補が
最終的に昇格しなかった場合を含む）・`overlap-lost`（resolveOverlaps で
負けた）・`path-demotion-below-min`（パス降格後に `min_confidence` 未満）・
`uuid-token`（UUID 内部の部分一致）。

既定では完全に無効で、性能・挙動・出力のいずれにも影響しません。
`detect.Detector` に `CollectDropped(true)` を呼んだ場合のみ、`ScanContent` /
`ScanLine` / `ScanDiffHunk` の走査中に `DroppedCandidate`（ルール ID・ファイル・
行・列・棄却理由・パターンの基準信頼度のみ。生のマッチ値は一切保持しません）を
蓄積し、`TakeDropped()` で回収します（drain 方式。内部の蓄積はクリアされる）。
1 回の走査（`TakeDropped` で回収するまでの累積）あたり 1000 件の上限があり、
超過時は黙って捨てず `DroppedTruncated()` で打ち切りの有無を確認できます。
`internal/source` の並列フルスキャンで同一 `Detector` の `ScanContent` が
複数ゴルーチンから呼ばれても安全なように、記録は mutex で保護しています。

CLI からは `scan` の `--explain-dropped` で有効化します。text 出力では通常の
findings の後に「棄却候補」セクションが、json 出力では `dropped` 配列
（`rule_id`/`file`/`line`/`column`/`reason`/`base_confidence`。生値は含みません）が
追加されます。フラグ未指定時は出力スキーマも従来と 1 バイトも変わりません。

```console
$ echo '口座番号: 1234567 (手数料300円)' | jp-pii-detect scan --stdin --format json --explain-dropped
```

上記の例では `1234567` が `jp-bank-account`（コンテキスト「口座」）として
Medium で検出される一方、同じ 7 桁は `jp-postal-code` の裸 7 桁パターンの
候補にもなりますが、郵便番号のコンテキスト語（「郵便」「〒」等）が無いため
`require-context-missing` として `dropped` に記録されます。

### 非公開評価コーパスの取得

通常の単体・結合テストは [`internal/testfixtures`](../internal/testfixtures/testfixtures.go) の
公開合成値で完結します。採取由来または実在空間と衝突しうる値を含む評価コーパスだけを
非公開GCSで管理し、[`internal/privatecorpus`](../internal/privatecorpus/privatecorpus.go) が読み込みます。

未設定ならprivate evalだけが `t.Skip` されます。環境変数を設定したのに、ファイルが読めない、
JSON・schema・dataset IDが不正、datasetが空の場合はSkipせず失敗します。

日常開発は認証不要です:

```console
$ go test -race ./...
```

非公開精度評価（GCSへの閲覧権限と `gcloud auth login` が必要）:

```console
$ gcloud auth login
$ export JP_PII_FIXTURES_BUCKET=<bucket>
$ go run ./cmd/pii-fixture eval          # 一時取得し、終了後に削除
$ go run ./cmd/pii-fixture eval -cache   # 明示した場合だけユーザーキャッシュへ保存
$ go run ./cmd/pii-fixture status
$ go run ./cmd/pii-fixture purge
```

既に安全なローカルコピーがある場合は、従来どおり `JP_PII_FIXTURES=<path>` を設定できます。
キャッシュは `os.UserCacheDir()` 配下、ディレクトリ0700・ファイル0600で管理します。

新しいJSONスキーマは
`{ "schema_version": 1, "dataset_id": "<opaque-id>", "dataset": [ { "id", "source_class", "file", "line", "content", "diff", "want", "spans", "tags" } ] }` です。
旧 `strings` は移行中だけ読み取り互換を残し、新しい単体テストからは参照しません。
`id` は失敗時に生値を出さずケースを特定する安定識別子です。
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

詳細は `internal/evalcase` と `internal/privatecorpus` のコメントに定義されています。

CIは公開 `test` jobと、main pushまたは保守者の明示実行専用の `private-eval` jobを分離します。private jobだけが
GitHub OIDC → GCP Workload Identity Federationで認証します。リポジトリ変数
`JP_PII_FIXTURES_PROVIDER`・`JP_PII_FIXTURES_SA`・`JP_PII_FIXTURES_BUCKET`に加え、
GCS object generationを固定する `JP_PII_FIXTURES_GENERATION` を設定してください。
WIF側もrepository ID・workflow・`refs/heads/main`へattribute conditionを絞り、SAには対象objectの
readだけを許可します。PRのマージ前評価が必要な場合は、main上のworkflowを
`workflow_dispatch`し、レビュー済みcommitの40桁SHAを`eval_ref`へ指定します。可変なbranch名は
受け付けないため、レビュー後の差し替えを評価対象へ紛れ込ませません。

未設定・取得失敗・parse失敗ならprivate-evalはfail-closedします。PRコードへ非公開平文と
OIDC権限が自動で渡ることはなく、明示実行時だけ指定したレビュー済みcommitを評価します。

#### ケースのタグ（表記ゆれ等の層化評価）

`Case.Tags`（`Span.Tags` と同じ位置づけ。どちらも `[]string`、`omitempty`）は、表記ゆれ・
ラベル語彙・ケースの由来などでケースを層別集計するためのメタデータで、検出結果そのものには
影響しません。`internal/eval` の `EvaluateCasesStratifiedWithOptions` / `EvaluateStratified` が
`Stratified{Results, Tags, Kinds}` を返し、`Tags` はケースの `Tags` ごと、`Kinds` は入力形式
（`line` / `content` / `diff`）ごとの行レベル Score（1 ケースに複数ルールの期待・検出があれば
同じバケツへ合算）を持ちます。`docs/accuracy.md` の「タグ別」「ケース種別別」表は
`go test ./internal/eval -run 'TestGenerateDoc|TestReadmeBadges' -update` が自動生成します。`Kinds` はデータセットの
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

生成したケースは `source:synthetic` タグ、`source_class: algorithmic`、安定したcase IDを持ちます。
`internal/fixturegen/integration_test.go` は生成したケース
全件を `internal/eval.EvaluateCases` に通し、対象 4 ルールの FN・FP が 0 であることを検証する
自己完結の回帰テストで、`JP_PII_FIXTURES` は不要です（表記ゆれへのルールの頑健性を、外部データセット
なしでも継続的に確認できる）。

`cmd/pii-dataset-gen` は合成契約ケースをversion付きJSONとして書き出すCLIです:

```console
$ go run ./cmd/pii-dataset-gen -output /path/outside/repo/synthetic-cases.json
```

出力先はリポジトリ管理外にしてください。合成契約は仕様回帰のpass/fail用であり、非公開コーパスへ
マージせず、README F1・`docs/accuracy.json`の分母にも含めません。合成ケースを増やして実採取
コーパスの見かけの精度が上がることを防ぐためです。
生成件数はルールあたり数十件規模に抑えています
（Issue #70 のフェーズ2方針: 段階的に増やし、マイクロ平均への影響とゴールデンの安定性を見ながら
判断します）。

### OSS コーパスでの偽陽性率計測（fp-corpus-report）

`internal/eval` の適合率・再現率は自リポジトリの外部フィクスチャ（ラベル付きデータセット）で
測っていますが、実運用の偽陽性率（findings/MLoC）を測る仕組みは自リポジトリの dogfooding
（`ci.yml`、既定で 0 件期待）しかありません。小さな自リポジトリ 1 つでは陰性母数が不足し、
`NegativeContext` 追加や allowlist 追加のような偽陽性削減施策の効果を測る場がないため、
[`.github/workflows/fp-corpus-report.yml`](../.github/workflows/fp-corpus-report.yml) が
大規模公開 OSS コーパスに対して定期的に jp-pii-detect を走らせ、findings/MLoC を
トレンド指標として記録します。**このワークフローは `ci.yml` の test job（精度ゴールデン・README
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

**結果の保存先**: 集計結果はリポジトリの公開 `docs/` には置かず、評価コーパスとは分離した
GCSバケットへ保存します。`JP_PII_REPORTS_PROVIDER`・`JP_PII_REPORTS_SA`・
`JP_PII_REPORTS_BUCKET`を設定し、report writerに評価コーパスのread権限を与えないでください。
`fp-corpus-report/` プレフィックスで JSON/Markdown
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
cmd/pii-dataset-gen/ fixturegen の合成契約ケースを書き出す CLI
cmd/pii-fixture/     非公開コーパスの一時取得・評価・明示キャッシュ管理
internal/
  config/    .jp-pii.toml の読み込み（リポジトリルートまでの上方探索）
  source/    走査対象の列挙: ファイルツリー（並列）/ git diff の追加行
  detect/    行単位の検出エンジン（ScanLine/ScanContent・ソースコード文脈・重複解決）
  normalize/ 日本語テキストの正規化（全角→半角・ハイフン類・長音記号）
  rule/      検出ルールの型定義と組み込みルール一覧
  checksum/  チェックディジット検証（マイナンバー・Luhn・カードブランド）
  dict/      IANA TLD などの埋め込み辞書
  report/    出力フォーマット（text/json/sarif/github）とマスキング
  evalcase/   評価ケースの中立データモデル・構造検証
  testfixtures/ 公開テスト専用の決定的な合成値
  privatecorpus/ 非公開コーパスの厳密なローダ
  piifixtures/ 旧APIの互換層（新規利用禁止）
  eval/      ラベル付き評価データセットと検出精度（適合率・再現率・F1・タグ/ケース種別の層別）の計測。
             golden.go は docs/accuracy.json（ゴールデンファイル）の生成・比較・
             データセット品質統計（匿名の件数）を担う
  fixturegen/ ルール×表記ゆれのマトリクスを計算合成する評価ケースジェネレータ
```

#### 検出パイプライン

1. **source** が走査対象を列挙します。
   - フルスキャン: ファイルツリーを walk し、バイナリ（先頭 8KB に NUL）、5MB 超、
     `node_modules` 等の依存ディレクトリを除外します。
   - バイナリ判定の前に `decodeUTF16` が UTF-16 の BOM（`FF FE`/`FE FF`）を検出し、
     標準ライブラリの `unicode/utf16` で UTF-8 へ変換します。BOM の直後が奇数バイト長、
     または不正なサロゲートペアの場合は通常のバイナリ判定へフォールバックします。
     デコード後の行・列はルーン単位としては正しいものの、元ファイルのバイトオフセット
     とは対応しません。この変換はフルスキャン限定で、`git diff` がバイナリ扱いする
     UTF-16 ファイルは `--staged` / `--diff` の走査対象になりません。
   - git モード: `git diff -U3` で文脈行付きの差分を取得し、`detect.ScanDiffHunk` で
     走査します。検出値が**追加行に乗っているもののみ**を報告し、文脈行（未変更行）上の
     既存 PII は報告しません。
   - ラベルが**論理的に隣接する未変更行**（間が空白のみの行なら最大 2 行挟んでもよい。
     `j-i<=3`）にあり値だけを追加したケースでも、コンテキスト必須ルールが発火します
     （ScanContent の論理隣接ウィンドウに準じます）。
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
   - `.csv`/`.tsv`（[`internal/detect/csv_context.go`](../internal/detect/csv_context.go)、
     フルスキャン限定）は上記のコード文パーサとは別の専用パーサへ分岐します
     （`sourceExtensions` には加えていません。カンマを文区切りとして誤解釈するためです）。
     1 行目をヘッダとして RFC 4180 準拠の引用符処理（`""` エスケープ）でフィールドに
     分割します。区切り直後の半角空白を挟む引用フィールドも認識し、引用符が続かない
     先頭空白は値の一部として保持します。各列のラベル語をその列の**全データ行**の
     該当フィールドへ `PositiveText` / `NegativeText` として付与し、隣接 ±1 行の
     source context では文脈を失っていた 3 行目以降の FN を解消します。
     ヘッダらしくない 1 行目（フィールド数が 2 未満・空フィールドあり・数値主体の
     フィールドあり）は列コンテキストを一切付与しません（安全側 = 現状維持）。フィールド内
     改行で引用符が行末までに閉じないレコードを検出したら、それ以降への列コンテキスト
     付与を打ち切ります（列がずれた誤帰属を防ぐためです）。高再現率モードでは、ヘッダが
     氏名系ラベル語彙（`rule.CSVNameHeaderRe`）と完全一致する列について、各データ行の
     フィールド値を `rule.CSVNameValueRe` で切り出し `rule.ValidCrossLineName`
     （姓名辞書照合）で検証して `person-name-structured` として報告します（フリガナ列は
     辞書が漢字ベースのため対象外です）。この Medium finding は `min_confidence` を尊重します。
     diff 走査では使いません（hunk はヘッダ行を含まないことが多く、列のずれた誤帰属の
     リスクが高いためです）。
   - 各ルールのパターンを正規表現でマッチし、`Validate`（チェックディジット等）と
     allowlist で絞り込みます。
     - 同一行にコンテキストキーワードがあれば信頼度を High に昇格します。昇格時の探索は
       マッチ前後 40 ルーン（`RequireContextWindow` 設定時はその値）に限定し、minified JSON
       や長い 1 行の遠方にあるキーワードで無関係なマッチまで昇格するのを防ぎます。
       `RequireContext` のルールはキーワードがなければ破棄します。この検出可否の判定は
       `RequireContextWindow` が設定されていれば指定ルーン数以内、未設定なら後方互換のため
       行全体を探索します。
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
   - **detect.ScanContent / detect.ScanDiffHunk** は通常の行単位検出に加え、
     「行 i と、間が空白のみの行を挟んでもよい後続の最初の非空白行 j」（`j-i<=3`。
     空行なしの物理隣接は `j-i=1`）を結合した仮想ウィンドウとして走査します（論理隣接）。
     `RequireContext` ルールだけでなく非 `RequireContext` ルールも対象で、後者は値の
     マッチ位置から 40 ルーン以内にラベルがある場合だけ High へ昇格します
     （`digitRuleRequireContextWindow` と同じ窓幅を流用し、遠く離れたラベルによる
     誤昇格を抑えます。昇格時は `Reason.ContextPromoted` を立てます）。ignore マーカーは
     結合文字列ではなく値が乗る行ごとに判定するため、ラベル側だけの marker が値側の
     検出を消しません（フル走査・diff 走査とも対称）。検出位置は元の行と列へマップし直します。
     単独行走査で得た finding と論理隣接ウィンドウで得た finding が同じ span になった場合、
     `dedupAndSortFindings` は信頼度の高い方を残します。
     ソースコード文脈では、`bankAccountNo:` の次行に値があるような key/value 分離も
     logical context として値行に付与します。diff では文脈行由来の source context は正の
     コンテキスト補完にだけ使い、文脈行由来の負コンテキストでは追加行を抑制しません。
     論理隣接ウィンドウで得た finding も、元の値行へ戻した後にその行の source
     `NegativeText` を評価し、コード限定の負コンテキストを迂回しません。
     隣接行の負コンテキスト判定（`hasCrossLineNegativeContext`、ScanContent 経由のみ）も
     同じ論理隣接規則で前後の非空白行を見るため、空行を挟んだ負コンテキストも取りこぼしません。
3. **report** が `min_confidence` で絞った結果を指定フォーマットで出力します。
   検出値は既定でマスクされます。`--explain` 指定時は JSON 出力の `reason` に加え、text 出力にも
   検出理由（コンテキスト昇格・検証有無等）を 1 行追加します。`--fail-on` を指定すると、報告閾値
   （`min_confidence`）とは独立に、その信頼度以上の検出があるときだけ終了コードを 1 にできます
   （未指定時は既存どおり報告があれば 1）。SARIF の各 result には `region.endLine`/`endColumn` と、
   ルール ID・ファイルパス・同一ルールのファイル内出現順ベースの `partialFingerprints` を付与します。
   `partialFingerprints` には行・カラムと生の検出値を含めず、周辺行の増減に対する安定性と
   マスク方針を維持します。

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
    RequireContextWindow: 40,          // RequireContext 判定は 0 なら行全体、正数なら前後ルーン数。
                                        // High 昇格判定は未設定でも常に窓あり（既定 40 ルーン）。
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
  コード限定 `NegativeText` として扱います。数百〜千語規模の辞書（固有名詞等）を
  文脈シグナルにしたい場合は `Context` に語をすべて足さず、`ContextPattern`
  （`Rule.ContextPatterns`）で「安価な `Literals` ゲート → 正規表現で候補切り出し
  → 辞書 `Validate`」の専用経路にします（`jp-bank-account` の銀行名辞書照合を参照）。
  日本語の連続文を候補の前方に取り込みうる場合は `ValidateSuffixes` を有効にし、
  辞書に一致する最長の接尾部分を回収します。
  `Context` の線形走査（`containsWord`）に大きな辞書を混ぜるとホットパスが劣化します。
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

`jp-invoice-number`（適格請求書発行事業者登録番号 / インボイス登録番号）について: 法人の登録番号は
番号自体が法人番号と同一であり、国税庁の適格請求書発行事業者公表サイトで制度上公開されている情報です。
個人事業主分は氏名までの名寄せが可能な実質的個人識別子となるため検出対象としていますが、法人・個人を
区別せずに検出する設計上、自社の請求書テンプレートや契約書ひな形などで誤検出（公開情報の指摘ノイズ）が
起きた場合は `.jp-pii.toml` の allowlist で除外してください。書式（`T` + 13 桁）・周辺語に加え、
`T` を除いた末尾 13 桁を `checksum.CorporateNumber`（法人番号の検査用数字、平成26年財務省令第70号）で
検証する。

固定電話の市外局番は総務省の電気通信番号指定状況（「市外局番の一覧」）由来の実在集合を
[`internal/dict/area_codes.txt`](../internal/dict/area_codes.txt) にテキストで保存して
`//go:embed` で取り込む。`dict.ValidAreaCode` は電話番号の先頭から**最長一致**する
市外局番を探し、`validPhone`（`internal/rule/builtin.go`）が区切りなし固定電話 10 桁の
実在性検証に使う。市外局番はほぼ変化しないため、郵便番号のような月次自動更新ワークフローは
設けていない。

> **既知の制限（#56 時点）**: `area_codes.txt` は総務省の公式データそのものではなく、
> 都道府県庁所在地・政令指定都市クラスの市外局番（46 件、2〜3 桁のみ）に絞った
> **代表的なシードデータ**である。総務省が公開する市外局番は全国で約 500 件（4〜5 桁の
> 中小都市分を含む）あり、このシードはそのごく一部にすぎない。未収録の実在市外局番を使う
> 固定電話番号は誤って未検出（false negative）になる。総務省の公式データを取得できる環境で、
> 市外局番列を抽出した CSV（1 列目が市外局番。ヘッダ行や他の列があっても無視される）を用意し、
> 次のコマンドで完全な一覧に差し替えること。

```console
$ go run ./internal/dict/gen -phone \
    -input /path/to/area_codes_raw.csv \
    -output internal/dict/area_codes.txt
```

差し替え後は `go test ./internal/dict ./internal/detect ./internal/rule` に加えて、
`JP_PII_FIXTURES=<path> go test ./internal/eval` で `jp-phone-number` の F1 を再測定し、
必要なら `wantF1` を更新のうえ `-update` で README バッジと `docs/accuracy.md` を
再生成すること（区切りなし固定電話 10 桁の正例・未割当プレフィックスの負例を
評価データセットに追加した場合は特に）。

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

同じ KEN_ALL データの record[6]（都道府県名）・record[7]（市区町村名）から、実在する
市区町村名の一覧 [`internal/dict/municipalities.txt`](../internal/dict/municipalities.txt)
（1 行 1 エントリ、ソート・重複排除済み）も生成し `//go:embed` で取り込みます。
`dict.MunicipalitySuffixMatch` が jp-address-high-recall の `Validate` に使い、
「通学区域」のような市区町村ではない語を municipality と誤認した検出を棄却します
（既定の `jp-address` には付けません。郡・表記揺れによる FN リスクが高再現率でない
既定ルールでは相対的に大きいためです）。郡付きエントリ（石狩郡当別町）は郡を省いた
省略形（当別町）も、政令指定都市の区（札幌市中央区）は市単独形（札幌市）も併録し、
`ヶ`/`ケ` の表記揺れは生成側・照合側の両方で `ケ` に正規化します
（詳細は `internal/dict/gen/postal.go` の `addMunicipalityVariants` を参照してください）。

更新は通常 [`.github/workflows/postal-update.yml`](../.github/workflows/postal-update.yml) が
毎月 1 日に自動で行います。手動で更新する場合は次の 2 つのデータを取得し、コマンドでビットセットと
市区町村名一覧を再生成してから
`go test ./internal/dict ./internal/dict/gen ./internal/detect ./internal/eval` で検証します。

- 住所の郵便番号（UTF-8）: `https://www.post.japanpost.jp/zipcode/dl/utf-zip.html`
  （`utf_ken_all.zip` / `KEN_ALL.CSV`）
- 事業所の個別郵便番号（Shift_JIS）: `https://www.post.japanpost.jp/zipcode/dl/jigyosyo/index-zip.html`
  （`jigyosyo.zip` / `JIGYOSYO.CSV`）

```console
$ go run ./internal/dict/gen \
    -ken-all-input /path/to/utf_ken_all.zip \
    -jigyosyo-input /path/to/jigyosyo.zip \
    -output internal/dict/postal_codes.bitset \
    -municipalities-output internal/dict/municipalities.txt
```

`-ken-all-input` / `-jigyosyo-input` はどちらか片方だけでも、両方指定してもよいです
（両方指定時はマージされ、重複コードは自動的に排除されます）。それぞれ展開済みの CSV
（前者は UTF-8、後者は Shift_JIS）も直接指定できます。`-municipalities-output` を指定する
場合は、市区町村列を持つ `-ken-all-input` も必須です。列インデックス（ken_all は郵便番号が
3 列目、jigyosyo は 8 列目）はフォーマットごとに固定なので、`-ken-all-input` と
`-jigyosyo-input` を取り違えないでください（取り違えると実質ゼロ件取り込みになります）。
`-output` / `-municipalities-output` はそれぞれ省略でき、省略した方は生成しません。ただし
`-municipalities-output` は市区町村名（record[7]）を持つ KEN_ALL フォーマット専用のため
`-ken-all-input` が必須です（`-jigyosyo-input` だけでは生成できません）。
郵便番号の増減で `jp-postal-code` の精度数値が動くことがあるため、新しいビットセットを
コミットしたら eval / バッジの再生成も行ってください（市区町村名一覧は jp-address-high-recall
のみに使い、eval は既定で high-recall ルールを評価しないため精度ゲートへの影響はありません）。

姓名辞書（[`internal/dict/surnames.txt`](../internal/dict/surnames.txt) /
[`given_names.txt`](../internal/dict/given_names.txt)）のカタカナ読みと、ローマ字姓名辞書
（[`romaji_surnames.txt`](../internal/dict/romaji_surnames.txt) /
[`romaji_given_names.txt`](../internal/dict/romaji_given_names.txt)、
`person-name-romaji` ルール専用）は
[`shuheilocale/japanese-personal-name-dataset`](https://github.com/shuheilocale/japanese-personal-name-dataset)
（MIT。ライセンス全文は [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md)）の CSV から
[`internal/dict/gen-names`](../internal/dict/gen-names) で生成する。既存エントリは変更せず、
未収録の新規エントリだけをソート済みで追記する（再実行しても重複しない）。

```console
$ go run ./internal/dict/gen-names \
    -last-names last_name_org.csv \
    -given-names-man first_name_man_opti.csv \
    -given-names-woman first_name_woman_opti.csv \
    -surnames-out internal/dict/surnames.txt \
    -given-names-out internal/dict/given_names.txt \
    -romaji-surnames-out internal/dict/romaji_surnames.txt \
    -romaji-given-names-out internal/dict/romaji_given_names.txt
```

名側は同データセットが提供する「curated popular names」サブセット（`*_opti.csv`）に限定して
いる。カタカナ・ローマ字表記の氏名はサービス名・製品名や辞書外の英単語と同形になりやすく
（さくら・ひかり型、Ken/Kai/Mori 型の誤検出）、全件（`*_org.csv`、数千〜1 万件規模）を
無条件に取り込むと適合率への影響が大きいおそれがあるため、代表的な部分集合から始め、外部
評価データセット（`$JP_PII_FIXTURES`）で適合率を確認してから拡大する方針をとっている
（issue #58）。姓は全件（`last_name_org.csv`、1999 件）を使っている。4 文字姓
（勅使河原・小比類巻 等）は同データセットに収録が無いため、`surnames.txt` に人手で追加した
小さな代表集合を個別に参照している。辞書を拡張したら
`go test ./internal/dict ./internal/detect ./internal/eval` で検証し、person-name /
jp-address の精度が動く場合は eval / バッジの再生成も行うこと。

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

銀行名（[`internal/dict/bank_names.txt`](../internal/dict/bank_names.txt)、
`dict.IsBankName` が参照）は、全国銀行協会（Zengin）加盟金融機関のうち著名な
銀行・信用金庫・労働金庫を**手作業で収録した代表サブセット**（約 110 件）です。
zengin-code 等が公開する公式マスタ（約 1,100 件）そのものではありません。
`jp-bank-account` ルールは、この辞書と `internal/rule/builtin.go` の
`bankNameCandidateRe`（`(候補)(銀行|信用金庫|信用組合|信金|信組|労働金庫|ろうきん|農協)`
のアンカー正規表現）で候補を切り出し、候補の接尾部分を長い順に
`dict.IsBankName` で O(1) 検証した結果を
`rule.ContextPattern` 経由の文脈シグナルとして使います（銀行名 1,000 語超を
`Context` の線形走査に混ぜないための専用経路。`internal/detect/context.go` の
`matchContextPatterns` を参照）。支店辞書（全国支店で数百 KB〜数 MB 規模になりうる）は
スコープ外として別 Issue に切り出しています。

実データ（zengin-code 等）で辞書を更新・拡張する場合は、ライセンス（元データ提供元
への帰属を含む）と継続性をメンテナが確認・サインオフしてから取り込んでください
（postal_codes.bitset が公式 KEN_ALL を出典にしているのと同水準の確認が必要）。
`internal/dict/bank_names.txt` はテキストファイルを直接編集し、
`go test ./internal/dict ./internal/detect ./internal/eval` で検証します
（`internal/dict/postal_codes.bitset` のような自動生成パイプライン・定期更新
ワークフローはまだありません）。

金融機関コード（`internal/dict/bank_codes.go`、`dict.ValidBankCode` が参照）も、
上記の銀行名辞書に含まれる主要行 7 行だけを手作業で収録した代表サブセットです。
`4桁の金融機関コード-3桁の支店コード-7桁の口座番号`（空白区切りも可）という
構造を `bankCodeAccountRe` で確認し、先頭 4 桁が辞書にある場合だけ
`jp-bank-account` の文脈として使います。支店コードは桁構造だけを確認し、支店の
実在性は検証しません。全国版への拡張は銀行名と同じく、全銀協・提供元の利用条件と
帰属をメンテナが確認してから行ってください。ライセンス未確認の外部マスタや支店
データをそのまま取り込まないでください。

ゆうちょ銀行の記号番号（`jp-yucho-account`）は記号（5 桁・先頭は必ず "1"）＋
番号（7〜8 桁・末尾は必ず "1"）をハイフンで相関させた表記（例: `12345-1234561`）だけを対象にして
います。記号 4 桁目に意味を持つチェックディジット式が存在するとされますが、公開
情報から具体式を確認できなかったため未実装です（要追加調査）。新規ルールのため
評価データセット（リポジトリ外管理）に正例・負例ケースがまだなく、`wantF1` にも
未登録です。追加する場合は `internal/eval/eval_test.go` の該当コメント（Issue #61）
を参照してください。

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
