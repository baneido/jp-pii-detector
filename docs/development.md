# 開発者向けガイド

jp-pii-detect のビルド、テスト、内部構成と、検出ルールの追加方法をまとめます。
利用方法は [README](../README.md)、検出手法の調査と設計判断は
[detection-methods.md](detection-methods.md) を参照してください。

## ビルドとテスト

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

## ベンチマーク

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

## 検出精度の計測

`internal/eval` にルールごとの陽性と陰性のケースを集めたラベル付き評価データセットと、
適合率、再現率、F1 を計測するハーネスがあります。データセットは実在しうる PII を含むため
リポジトリにはコミットせず、外部ストレージ（GCS）で管理して `JP_PII_FIXTURES` 経由で読み込みます
（後述の「評価データセット・テストフィクスチャの取得」を参照）。README の検出精度バッジと
[accuracy.md](accuracy.md) は、ルール自体の検出能力を見るため `min_confidence=low`、
高再現率ルール無効のプロファイルで測った実測値です。`EvaluateWithOptions` /
`EvaluateCasesWithOptions` を使うと、既定 CLI 相当（`min_confidence=medium`）や
高再現率ルール有効時も同じハーネスで評価できます。`JP_PII_FIXTURES` が未設定の環境では
eval 系テストは `t.Skip` され、ローカル/オフラインでも `go test ./...` は緑のままになります。

```console
$ export JP_PII_FIXTURES=$PWD/pii-fixtures.json   # GCS から取得（取得手順は後述）
$ go test ./internal/eval            # 実測 F1 と wantF1・README バッジの一致を検証
$ go test ./internal/eval -update    # docs/accuracy.md と README のバッジを実測値で再生成
```

`eval_test.go` の `TestAccuracy` は実測 F1 が `wantF1` と一致するか、
`readme_test.go` の `TestReadmeBadges` は README の総合バッジとルール別バッジが
実測値と一致するかを検証します。ルールやデータセットを変えて精度が動くと
CI が落ちるので、**`wantF1` を更新し、`-update` で README のバッジと
`docs/accuracy.md` を再生成**してください。

## 評価データセット・テストフィクスチャの取得

評価データセットと各テストのフィクスチャは、実在しうる PII（電話番号・氏名・住所など）を含むため
リポジトリにコミットせず、非公開の GCS バケットで管理します。テスト時は環境変数 `JP_PII_FIXTURES`
にローカル JSON のパスを渡し、[`internal/piifixtures`](../internal/piifixtures/piifixtures.go) が
読み込みます。未設定・取得不可なら依存テストは `t.Skip` され、ビルド・dogfooding・その他のテストは通ります。

ローカル開発（GCS への閲覧権限が必要）:

```console
$ gcloud auth application-default login
$ gcloud storage cp gs://<bucket>/pii-fixtures.json ./pii-fixtures.json
$ export JP_PII_FIXTURES=$PWD/pii-fixtures.json
$ go test ./...
```

`pii-fixtures.json` は `.gitignore` 済みでコミットされません。JSON スキーマは
`{ "strings": { "<key>": "<値>" }, "dataset": [ { "file", "line", "content", "diff", "want", "spans" } ] }` で、
`line` / `content` / `diff` のいずれか 1 つを入力として指定します。`want` または `spans` が
あるケースでは入力指定漏れをエラーにします。`line` は単一行の `ScanLine`、`content` は複数行の `ScanContent`、`diff` は `{ "text", "added" }` の配列で
`ScanDiffHunk`（追加行だけを報告）を評価します。`spans` は `{ "rule_id", "line", "start", "end" }`
で、`line` は 1 始まり、`start` / `end` はその行内の 0 始まりルーンオフセットです
（`line` 省略時は後方互換のため 1 行目）。`file` は任意で、`.go` や `.ts` などファイル名依存の
ソースコード文脈を評価したいケースだけ指定します。未指定時は従来どおり `dataset` として走査します。詳細は `internal/piifixtures/piifixtures.go` の
コメントに定義があります。値を編集したら GCS に再アップロードします。

CI（GitHub Actions）は GitHub OIDC → GCP Workload Identity Federation で認証し、サービスアカウントの
鍵を持たずに取得します。リポジトリ変数 `JP_PII_FIXTURES_PROVIDER`（プロバイダのリソース名）・
`JP_PII_FIXTURES_SA`（サービスアカウントのメール）・`JP_PII_FIXTURES_BUCKET`（バケット名）を設定すると
`.github/workflows/ci.yml` が取得します。未設定なら取得をスキップし、eval 系テストは Skip されます。

## OSS コーパスでの偽陽性率計測（fp-corpus-report）

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

1. 対象リポジトリの安定版タグに対応するコミット SHA を確認する
   （`git ls-remote --tags <url>` など。ワークフロー再実行時に upstream の変更で
   トレンドがノイズ化しないよう、コミットを固定する）。
2. ローカルでそのコミットを浅く取得し、`jp-pii-detect scan --format text --unmask <dir>`
   を実行する。報告される findings の大半は JAN コード・型番・テスト用カード番号・
   スコア/日付が住所形式に一致した、といった偽陽性のはずである。目視で内容を確認し、
   実在しうる PII が含まれていないことを確認する。
3. 問題がなければ `.github/workflows/fp-corpus-report.yml` のコーパス一覧
   （`name|git-url|commit-sha` 形式）にコミット SHA を固定して登録する。

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

## プロジェクト構成

```
cmd/jp-pii-detect/   CLI エントリポイント（引数解析・出力フォーマットの振り分け・終了コード）
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
  eval/      ラベル付き評価データセットと検出精度（適合率・再現率・F1）の計測
```

### 検出パイプライン

1. **source** が走査対象を列挙する。フルスキャンはファイルツリーを walk し、
   バイナリ（先頭 8KB に NUL）、5MB 超、`node_modules` 等の依存ディレクトリを除外。
   git モードは `git diff -U3` で文脈行付きの差分を取得し、`detect.ScanDiffHunk` で走査する。
   検出値が**追加行に乗っているもののみ**を報告し、文脈行（未変更行）上の既存 PII は
   報告しない。ラベルが**直前・直後の未変更行**にあり値だけを追加したケースでも
   コンテキスト必須ルールが発火する（行をまたぐ相関は隣接 ±1 行のみ。ScanContent の
   2 行ウィンドウに準ずる）。文脈行は正のコンテキスト補完にのみ使い、抑制
   （ignore マーカー・負コンテキスト）の駆動には使わないため、追加行の新規 PII を
   既存行の都合で取りこぼさない。
2. **detect.ScanLine** が 1 行ごとに処理する。
   - **normalize.Line** で全角英数字、ハイフン類、数字隣接の長音記号を半角化する。
     変換はルーン単位の 1:1 に限定しているため、正規化後の位置がそのまま元テキストの
     位置になり、列番号の報告に逆引きが不要。
   - ルールの `Prefilter`（数字、`@`、日本語などの必須文字種）を含まない行は
     正規表現マッチ自体をスキップする。大半のルールは数字必須のため、
     数字を含まないコード行がほぼ無コストになる。
   - `.go`、`.ts`、`.py`、`.json`、`.yaml`、`.env` など既知のソースコード/設定ファイルでは、
     変数名・キー名・代入/key-value 構造を軽量な source context として抽出する。
     source context は文脈判定にだけ使い、正規表現は従来どおり正規化済みの元行だけを走査する。
     statement の値範囲は正規化済み行の byte offset で持ち、候補マッチがその範囲内にある場合だけ
     `PositiveText` / `NegativeText` を適用する。AST 解析や言語別 parser は使わない。
   - 各ルールのパターンを正規表現でマッチし、`Validate`（チェックディジット等）と
     allowlist で絞り込む。同一行にコンテキストキーワードがあれば信頼度を High に昇格、
     `RequireContext` のルールはキーワードがなければ破棄する。`RequireContextWindow`
     が設定されたルールでは、キーワードをマッチ前後の指定ルーン数以内に限定する。
     ASCII キーワードは英数字の単語境界つきで照合し、`tel` が `hotel` の一部で成立する
     ような誤昇格を避ける。単語境界で見つからない場合は、行中の識別子を camelCase /
     snake_case / kebab-case の構成語に分割して照合するため、`account_no` が
     `bankAccountNo` を、`phone` が `phoneNumber` を拾える（`smartphone` のように
     語の途中に埋もれた場合は成立しない）。source context 由来の `bankAccountNo` なども同じ
     トークン照合でコンテキストになる。`NegativeContext` が近傍にある場合は、金額、数量、連番 ID と
     みなして検出を棄却する。コード内の `orderId`、`version`、`count` などは source context 由来の
     コード限定 `NegativeText` として、該当 statement の値だけを抑制する。`RequireContext` のパターンはキーワードの存在が前提のため
     昇格せず、`Base` の信頼度のまま報告する。
   - **resolveOverlaps** で範囲が重なる検出を信頼度（同率なら長い方）で 1 件に集約する。
   - **detect.ScanContent** は通常の行単位検出に加え、隣接 2 行を結合した仮想ウィンドウを
     `RequireContext` ルールに限定して走査する。検出位置は元の行と列へマップし直す。
     ソースコード文脈では、`bankAccountNo:` の次行に値があるような key/value 分離も
     logical context として値行に付与する。diff では文脈行由来の source context は正のコンテキスト補完にだけ使い、
     文脈行由来の負コンテキストでは追加行を抑制しない。隣接 2 行の仮想ウィンドウで得た finding も、
     元の値行へ戻した後にその行の source `NegativeText` を評価し、コード限定の負コンテキストを迂回しない。
3. **report** が `min_confidence` で絞った結果を指定フォーマットで出力する。
   検出値は既定でマスクされる。JSON 出力では `--explain` 指定時のみ `reason` を含める。

## 検出ルールの追加

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

- **境界ガード**: 長い数字列の部分一致を防ぐため、数字は `dg()`、英数字は `ag()` で囲む。
  これらはキャプチャグループ 1 に本体を入れるので、`ScanLine` はグループ 1 を検出対象にする。
- **信頼度の設計**: 桁数しか手がかりがないルールは `RequireContext: true` にして
  偽陽性を抑える。検証だけで十分な精度なら `Base: High`。`RequireContext` の
  パターンはコンテキストによる昇格が起きないため、`Base` がそのまま報告される
  信頼度になる。
- **コンテキストの設計**: ASCII キーワードは単語境界つき、加えて camelCase /
  snake_case / kebab-case の識別子を構成語に分割して照合される（`account_no` ⇔
  `bankAccountNo`）。ソースコード/設定ファイルでは、変数名やキー名も同じ仕組みで
  source context として使われる。桁数だけのルールは
  `RequireContextWindow` で肯定語を近接必須にし、金額、数量、連番 ID と衝突しやすい場合は
  `NegativeContext` を設定する。`id`、`version`、`count` などコード特有のノイズは、
  通常テキストにも効く `NegativeContext` へ安易に追加せず、source context 側の
  コード限定 `NegativeText` として扱う。
- **Prefilter**: パターンが特定の文字種（数字、`@`、日本語）なしにマッチし得ない
  場合は `Prefilter` を設定する。該当文字を含まない行の走査が丸ごと省ける。
  迷ったら未設定（常に走査）が安全。
- **検証ロジック**: チェックディジットなどは `internal/checksum` に置き、独立にテストする。
  実在性確認に使う小さな静的辞書は `internal/dict` に置き、`//go:embed` で同梱する。
- **高再現率ルール**: 偽陽性リスクが高いルールは `internal/rule/high_recall.go` の
  `HighRecallRuleIDs()` に追加し、既定では `[rules] high_recall = true` または
  `--high-recall` が指定されたときだけ有効になるようにする。
- **テスト**: 検出と非検出の両方を [`internal/detect/detect_test.go`](../internal/detect/detect_test.go) に追加する。
  特に「隣接する複数件」「コンテキスト有無での信頼度」「長い数字列の一部は対象外」を確認すること。

### 埋め込み辞書の更新

IANA TLD 一覧は公式の `https://data.iana.org/TLD/tlds-alpha-by-domain.txt` を
[`internal/dict/tlds-alpha-by-domain.txt`](../internal/dict/tlds-alpha-by-domain.txt) に保存している。

更新は通常 [`.github/workflows/tld-update.yml`](../.github/workflows/tld-update.yml) が
毎月 1 日に自動で行う（新規委任 TLD の見落としによる偽陰性、廃止 TLD が辞書に残り続けることによる
偽陽性の温床化を防ぐため）。gTLD/ccTLD の削除は極めて稀なため、削除が 1 件でも検出された場合は
PR タイトルに `[要レビュー]` を付与し、本文に削除された TLD 一覧を明記するので、マージ前に必ず
目視でレビューすること。手動で更新する場合は同 URL から取得して
`internal/dict/tlds-alpha-by-domain.txt` を置き換え、
`go test ./internal/dict ./internal/detect ./internal/eval` で検証する。

郵便番号は日本郵便の UTF-8 版「住所の郵便番号」全データから 7 桁の実在集合を
ビットセット化し、[`internal/dict/postal_codes.bitset`](../internal/dict/postal_codes.bitset)
（10,000,000 ビット = 1,250,000 バイト）に保存して `//go:embed` で取り込む。
`dict.ValidPostalCode` はこのビットセットで **7 桁完全一致**を判定する（上位 3 桁ではなく
7 桁すべてで実在を確認するため、`150-9999` のように上位 3 桁は実在しても 7 桁としては
未割当の番号は棄却される）。インデックスのエンコーディングとサイズ定数は `internal/dict` 側で
公開し、ジェネレータと共有する（両者が無言で乖離しないため）。

更新は通常 [`.github/workflows/postal-update.yml`](../.github/workflows/postal-update.yml) が
毎月 1 日に自動で行う。手動で更新する場合は `https://www.post.japanpost.jp/zipcode/dl/utf-zip.html`
の最新全データ（`utf_ken_all.zip`）を取得し、次のコマンドでビットセットを再生成してから
`go test ./internal/dict ./internal/detect ./internal/eval` で検証する。

```console
$ go run ./internal/dict/gen \
    -input /path/to/utf_ken_all.zip \
    -output internal/dict/postal_codes.bitset
```

`-input` には展開済みの UTF-8 版 KEN_ALL CSV も指定できる。郵便番号の増減で
`jp-postal-code` の精度数値が動くことがあるため、新しいビットセットをコミットしたら
eval / バッジの再生成も行うこと。

新ルールは `jp-pii-detect rules` に自動で表示されます。

## リリース

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
