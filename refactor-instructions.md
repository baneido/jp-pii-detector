# refactor-instructions.md

> 実装担当モデルへ。このファイルに書かれたことを完遂してください。
> あなたのゴールは「**既存仕様を一切壊さずに、特定された技術的負債を小さく安全に減らし、
> 今後変更しやすい構造にする**」ことです。見た目の綺麗さや「全面リファクタ」は目的では
> ありません。証拠（ファイル・行）なしに大きな削除や全面書き換えをしないでください。

---

## Objective（目的）

`jp-pii-detect`（日本特化 PII 静的検出器・Go 製シングルバイナリ）のコードベースについて、
**振る舞いを保ったまま**、以下を行う。

1. 機械的に安全な整理（フォーマット統一など）。
2. テストの空白地帯への安全網の追加（`internal/rule` の直接テスト等）。
3. 大きすぎるファイルの責務分割（同一パッケージ内のファイル移動のみ、公開境界は変えない）。
4. 明確な重複の解消。
5. 大きな設計変更・挙動変更は**提案に留め**、承認なしに実装しない。

**やらないこと**: 検出精度（recall/precision）の改善、新ルール追加、データセット変更、
モジュール名/バイナリ名/マーカー文字列の改名、出力フォーマットや設定スキーマの変更、
依存の更新（Dependabot 管轄）。詳細は Out-of-scope Items を参照。

---

## Project Understanding（プロジェクト理解 / 証拠ベース）

### これは何か
- リポジトリに混入した**日本の個人情報（マイナンバー・電話・住所・カード番号 等）**を、
  **静的解析のみ**（実行時情報や外部 API なし）で検出する CLI。`git pre-commit hook` と
  GitHub Actions CI での利用を想定（`README.md`, `docs/detection-methods.md`）。
- モジュールパス `github.com/baneido/jp-pii-detecter`（**"detecter" は意図的な旧綴り**）、
  バイナリ名は `jp-pii-detect`（`go.mod:1`, `CLAUDE.md`）。

### 主要ワークフロー（ユーザー体験）
- `jp-pii-detect scan .` フルスキャン / `--staged` ステージ差分 / `--diff <range>` PR 差分
  （`cmd/jp-pii-detect/main.go:108` `runScan`）。
- `jp-pii-detect rules` ルール一覧 / `version` バージョン表示。
- pre-commit フレームワーク（`.pre-commit-hooks.yaml`）・複合 Action（`action.yml`）で配布。

### エントリポイントと責務（証拠）
- `cmd/jp-pii-detect/main.go` — 引数解析・フォーマット振り分け・終了コード（0/1/2）。
- `internal/config/config.go` — `.jp-pii.toml` の読み込み（リポジトリルートまで上方探索）。
- `internal/source/{files.go,gitdiff.go}` — 走査対象列挙（ファイルツリー並列 walk / `git diff -U0` 追加行）。
- `internal/normalize/normalize.go` — 日本語正規化（全角→半角・ハイフン類・数字隣接の長音記号）。
- `internal/detect/detect.go` — 行単位検出エンジン（`ScanLine`/`ScanContent`・コンテキスト判定・
  ネガティブコンテキスト・重複解決）。**約 634 行で複数責務が同居**（後述 D3）。
- `internal/rule/{rule.go,builtin.go,high_recall.go}` — ルール型と組み込みルール定義。
- `internal/checksum/checksum.go` — マイナンバー検査用数字・Luhn・カードブランド判定。
- `internal/dict/{tld.go,postal.go}` — `//go:embed` 辞書（IANA TLD・郵便番号上位3桁）。`gen/` は再生成ツール。
- `internal/report/report.go` — `text|json|sarif|github` 出力とマスキング。
- `internal/eval/{eval.go,dataset.go,eval_test.go,readme_test.go}` — ラベル付き評価データセットと
  精度計測（**CI のアキュラシー回帰ガードの中核**、後述 Non-Negotiables）。

### データフロー
`source`（行を列挙）→ `normalize.Line`（1:1 ルーン変換）→ `detect.ScanLine/ScanContent`
（prefilter → 正規表現 → `Validate` → allowlist → コンテキスト昇格/必須/ネガティブ → 重複解決）
→ `report`（`min_confidence` で絞り、フォーマット出力、既定マスク）。

### 外部依存・境界
- 依存ライブラリは **`github.com/BurntSushi/toml` のみ**（`go.mod`）。標準ライブラリ中心。
- 実行時の外部 I/O は **`git` サブプロセス呼び出し**（`internal/source/gitdiff.go:28`）と
  埋め込み辞書（`go:embed`）のみ。**ネットワーク・DB・マイグレーション・認証・課金・通知・
  キュー・ジョブ・外部 API は存在しない**（確認済み）。
- CI/配布の境界: `.github/workflows/ci.yml`, `action.yml`, `.pre-commit-hooks.yaml`,
  `.github/dependabot.yml`。

### 現在の検証コマンド（Baseline Commands 参照）
`go vet ./...` / `go test -race ./...` / 評価ドキュメントのドリフト検査 / `go build` /
ドッグフーディングの自己スキャン。

---

## Behaviors To Preserve（壊してはいけない既存挙動 / テストが固定している仕様）

以下はテストで固定されている**機能仕様**。リファクタで結果が変わってはならない。

1. **正規化の 1:1 ルーン不変条件**: `normalize.Line` はルーン数を変えず、変換後の位置が
   元テキストの位置と一致する（`internal/normalize/normalize.go` の設計、`normalize_test.go:32`
   `TestLineKeepsRuneCount`）。列番号報告の逆引き不要性はこれに依存。
2. **純 ASCII 行の 0 アロケーション・ファストパス**（`normalize_test.go:40`
   `TestLineASCIIFastPathReturnsSameString`）。
3. **長音記号「ー」は数字隣接時のみハイフン化**（`normalize_test.go:14,15,20`）。
4. **信頼度モデル**:
   - パターン+検証で高精度なものは単独 High（〒付き郵便番号・Luhn 通過カード）。
   - 区切りなし携帯・マイナンバーは Base=Medium、同一行キーワードで High に昇格
     （`detect_test.go:95` `TestPhoneNoSepWithoutContextIsMedium`, `:430` `TestReasonRecordsPromotionAndContext`）。
   - **`RequireContext` のパターンは昇格しない**（キーワードは前提であり昇格根拠にしない）。
     口座番号・保険者番号は Base=Medium のまま、免許証は Base=High のまま
     （`detect_test.go:404` `TestContextRequiredConfidenceNotPromoted`）。
5. **`min_confidence` 既定は medium**。person-name(low) は既定で非表示
   （`detect_test.go:282` `TestPersonNameHiddenByDefault`, `:471` `TestMinConfidenceHigh`）。
6. **ASCII コンテキスト語は単語境界つき**（`tel` は `hotel` の一部で成立しない、
   `card`/`license no` も同様）。日本語語は部分一致（`detect_test.go:195` `TestASCIIContextRequiresWordBoundary`）。
7. **ネガティブコンテキスト**（金額・数量・連番）が近傍 40 ルーン以内なら桁ベースルールを棄却。
   遠ければ検出する（`detect_test.go:217,250,258` 系、`builtin.go:48` `digitRuleNegativeContext`）。
8. **隣接 2 行のラベル/値分離検出**（`口座番号:` の次行に値）を `RequireContext` ルールに限定で拾い、
   位置を元行へ戻す。隣接行のネガティブコンテキストも抑制（`detect_test.go:522,534,562` 系）。
9. **重複解決**: 重なり検出は「信頼度 → 長さ → 先勝ち」で 1 件化（`detect_test.go:333,342`）。
10. **境界ガードで隣接 PII を取りこぼさない**（カンマ区切り電話 2〜3 件、隣接メール 2 件）
    （`detect_test.go:370` `TestAdjacentFindings`）。
11. **4-4-4-4 グループ除外**（カード様式の先頭 12 桁を誤ってマイナンバーにしない）
    （`detect_test.go:394`）。
12. **allowlist/マーカー**: stopword（正規化込み一致）、regex、行内マーカー
    `jp-pii-detector:ignore`・旧 `pii-allow`、`disabled` ルール（`detect_test.go:302,325,480`）。
13. **high-recall ルールは既定オフ**、`--high-recall`/`[rules] high_recall=true` でのみ有効
    （`detect_test.go:287,293`, `config_test.go` の high_recall 系 4 テスト）。
14. **電話の桁数厳密判定**（固定 10 桁・携帯/IP 11 桁・+81 表記）（`detect_test.go:489` `TestPhoneDigitCountStrict`）。
15. **出力**: 既定マスク、`--unmask` で生値、`--explain` でも生値は出さず `reason` のみ付与、
    終了コード 0/1/2、`--exit-zero`（`report_test.go`, `cmd/.../main_test.go` 全般）。
16. **設定の上方探索はリポジトリルート(`.git`)で打ち切る**（`config_test.go:183,206`）。
17. **フルスキャンの allowlist は「報告パス」と「リポジトリルート相対パス」の両方で評価**
    （`source/files_test.go:67,94`）。並列スキャンの結果は walk 順で決定的（`files_test.go:123`）。
18. **`git diff` パース**: `core.quotePath=false`、日本語/引用符付きファイル名、`/dev/null` 除外、
    `--diff-filter=ACMRT`、追加行のみ（`source/gitdiff_test.go` 全般）。

---

## Non-Negotiables（絶対に変えてはならないもの）

- **公開識別子（外部契約）**:
  - モジュールパス `github.com/baneido/jp-pii-detecter`（"detecter" の綴りも含め固定。
    `go install`・`action.yml:39`・README の `rev:` 参照が依存）。
  - バイナリ/コマンド名 `jp-pii-detect`。
  - 行内マーカー文字列 `jp-pii-detector:ignore`（"detector" 綴り）と旧 `pii-allow`
    （`internal/detect/detect.go:14,17`。**利用者がコードに書く文字列＝API**）。
  - `.jp-pii.toml` のスキーマ（`min_confidence`, `[rules] disabled/high_recall`,
    `[allowlist] paths/regexes/stopwords`）。利用者の設定ファイルが依存。
  - 出力フォーマットのフィールド名・形（`json`/`sarif`/`github`/`text`）。外部ツールが消費。
  - 終了コード 0=検出なし / 1=検出あり / 2=エラー。
- **セキュリティ**: 検出値は既定でマスク。`--unmask` 以外で生 PII を出力経路に流さない。
  `DetectReason` に生 PII を入れない（`internal/detect/detect.go:36-45` は信頼度名・キーワード名・
  真偽値のみ）。
- **アキュラシー回帰ガード**: `internal/eval` の実測 F1 と `wantF1`（`eval_test.go:19`）、
  README のバッジ、`docs/accuracy.md` は一致していなければ CI が落ちる。
  **検出挙動を変えない限りこれらは動かない**。もし `go test ./internal/eval` が落ちたら、
  それは「あなたがリファクタで検出挙動を変えてしまった」シグナル。原則として元に戻すこと
  （Stop And Ask 参照）。
- **性能不変条件**: 純 ASCII 0 アロケーション、prefilter による無マッチ行スキップ。
- **並行安全**: `Detector` は走査中**読み取り専用**（`internal/source/files.go:124` のコメントと
  `-race` テストが前提）。`ScanLine`/`Detector` に**可変状態やメモ化キャッシュを足さない**。
- **正規表現は RE2（lookaround 非対応）**: 線形時間保証を壊さない。`dg()`/`ag()`/`dgNoSlash()`
  の境界ガード方式（キャプチャグループ1を本体にする）を維持。
- **CI ゲート**（`.github/workflows/ci.yml`）が引き続き全て緑であること。

---

## Stop And Ask Conditions（実装を止めて確認すべき条件）

以下に該当したら**実装を止め、人間に確認**すること（勝手に進めない）:

1. `go test ./internal/eval`（`TestAccuracy`/`TestReadmeBadges`）が落ちた
   = 検出挙動を変えてしまった可能性。安全な整理のはずが数値が動いたら、まず原因を特定し、
   挙動変更が不可避か・意図的かを確認する。
2. Non-Negotiables のいずれかに触れる必要が出た。
3. `.github/workflows/ci.yml` / `action.yml` / `.pre-commit-hooks.yaml` / `.jp-pii.toml` /
   `go.mod` を変更したくなった（CI・配布・設定・依存の境界）。
4. 公開構造体・出力スキーマ・設定スキーマのフィールドを変えたくなった。
5. 「削除候補」が本当に不要か確証が持てない（例: `Span.Tags`。後述 D13）。
6. テストと実装が矛盾していて、どちらが正かコードから判断できない。
7. 改善案が複数あり、プロダクト判断が必要（例: エラー時に走査を中断 vs 継続。D11）。

---

## Baseline Commands（着手前に記録する基準）

着手前に**必ず全て実行し、結果を控える**（このリポジトリの現状はすべて緑であることを確認済み）。

```console
git status                                   # 作業ツリーがクリーンであることを確認
gofmt -l .                                   # 現状: internal/detect/detect.go が 1 件出る（D1）
go vet ./...                                 # 現状: 問題なし
go test -race ./...                          # 現状: 全パッケージ ok
go test ./internal/eval -run TestGenerateDoc -update && git diff --exit-code docs/accuracy.md
                                             # 現状: ドリフトなし（diff 空）
go build ./cmd/jp-pii-detect                 # 現状: OK
./jp-pii-detect scan --format github .       # 現状: 検出ゼロ・終了コード 0（ドッグフーディング）
go test -bench . -benchmem ./internal/normalize/ ./internal/detect/   # ホットパス変更時のみ
```

> 注: `gofmt -l .` が現状 1 件出るのは既知（D1 で解消対象）。それ以外は基準＝全緑。

---

## Debt Map（技術的負債マップ）

各項目: **根拠 / なぜ負債か / 影響範囲 / 変更リスク / 改善案 / 検証 / 今やる or 提案のみ**。

### ✅ 今すぐ実装してよい（安全・挙動不変）

#### D1. gofmt ドリフトがあり、CI がフォーマットを強制していない
- 根拠: `gofmt -l .` → `internal/detect/detect.go`。具体的には `detect.go:318-323` の
  `if r.Validate != nil { ... }` ブロックがインデント不足（`gofmt -d` で確認可）。
  `.github/workflows/ci.yml` に `gofmt`/`golangci-lint` チェックなし。
- なぜ負債か: スタイルの非一貫が静かに蓄積し、差分ノイズになる。Go はインデント非依存のため
  コンパイル・テストは通ってしまい、レビューでしか気づけない。
- 影響範囲: `internal/detect/detect.go` のみ（純粋に空白）。
- 変更リスク: 極小（gofmt は意味を変えない）。
- 改善案: `gofmt -w internal/detect/detect.go`（または `gofmt -w .`）。
- 検証: `gofmt -l .` が空 → `go test -race ./...` 緑。
- 判定: **今やる**。
  - CI に `gofmt` ゲートを追加するか否かは `.github/workflows/ci.yml` の変更になるため
    **Stop And Ask（条件3）**。承認があれば別フェーズで追加。

#### D2. `internal/rule` に直接テストが存在しない（安全網の空白）
- 根拠: `go test ./...` 出力で `internal/rule [no test files]`。`builtin.go` の
  `validPhone`（`:267`）/`validEmail`（`:299`）/`stripSeparators`/`containsASCIIAlnum`/
  `dg`/`ag`/`dgNoSlash` は `detect`・`eval` 経由でしか間接検証されていない。
- なぜ負債か: `validPhone`/`validEmail` は分岐が多く（+81 処理・桁数・予約 TLD・連続ドット 等）、
  ルールをいじる前の安全網がない。リファクタ前にここを固定したい。
- 影響範囲: テスト追加のみ（プロダクトコード不変）。
- 変更リスク: なし（純粋追加）。
- 改善案: `internal/rule/builtin_test.go` を新設し、`validPhone`/`validEmail`/`stripSeparators`/
  `containsASCIIAlnum` の**現状の振る舞いをそのまま固定する**テストを追加。
  値は `internal/eval/dataset.go` と `internal/detect/detect_test.go` の既存ケースから採る
  （新しい仕様を発明しない）。
- 検証: `go test ./internal/rule` 緑。`go test -race ./...` 緑。
- 判定: **今やる**（Implementation Phases の安全網フェーズ）。

#### D3. `internal/detect/detect.go`（約 634 行）が複数責務を同居
- 根拠: 1 ファイルに (a) エンジン（`Detector`/`New`/`ScanLine`/`ScanContent`/`scanAdjacentLines`/
  `classifyLine`）、(b) コンテキスト語照合（`matchingContexts`/`containsWord`/`asciiOnly`/
  `hasASCIIAlnumBefore/After`/`isASCIIAlnum`/`contextWindow`）、(c) ネガティブコンテキストの
  単位近接判定（`hasNegativeContextNear`/`isCurrency*`/`isCounterSuffix`/`hasUnitBefore`/
  `hasUnitAfter`/`runesEqual`/`isJapaneseLetter`/`hasCrossLineNegativeContext`）、
  (d) 重複解決（`resolveOverlaps`/`overlaps`/`better`）、(e) `itoa`/`findingKey` が混在。
- なぜ負債か: 読みづらく、変更時の影響範囲が見えにくい。
- 影響範囲: `internal/detect` パッケージ内のみ。**公開 API は変えない**。
- 変更リスク: 低（**同一パッケージ内のファイル分割のみ**。関数のパッケージ間移動はしない）。
- 改善案: 関数を同一パッケージの複数ファイルへ機械的に移動するだけにする。例:
  - `detect.go`（`Detector`/`New`/`Rules`/`ScanLine`/`ScanContent`/`scanAdjacentLines`/`Finding`/`DetectReason`/`classifyLine`/`findingKey`/`itoa`）
  - `context.go`（`matchingContexts`/`containsWord`/`asciiOnly`/`hasASCIIAlnum*`/`isASCIIAlnum`/`contextWindow`）
  - `negative_context.go`（`hasNegativeContextNear`/`isCurrency*`/`isCounterSuffix`/`hasUnitBefore`/`hasUnitAfter`/`runesEqual`/`isJapaneseLetter`/`hasCrossLineNegativeContext`/定数 `negativeContextWindowRunes`）
  - `overlap.go`（`resolveOverlaps`/`overlaps`/`better`）
  - **シグネチャ・ロジックは一切変えない。コメントも移動するだけ。**
- 検証: `go test -race ./internal/detect` 緑、`go vet ./...` 緑、`gofmt -l .` 空、全体テスト緑。
- 判定: **今やる**（ただし D1/D2 の後）。1 コミットで完結させ、移動以外を混ぜない。

#### D4. F1/適合率/再現率の計算が重複
- 根拠: `internal/eval/eval.go` の `fillScore`（`:226`）と `Micro`（`:240`）が同じ
  precision/recall/F1 算出をインラインで二重実装。
- なぜ負債か: 同じ式が 2 箇所。片方だけ直すと不整合になりうる。
- 影響範囲: `internal/eval` のみ。`Micro` の戻り値（README 総合バッジ・accuracy.md 合計行）。
- 変更リスク: 低〜中（バッジ/ドキュメントのドリフトガードが守る）。
- 改善案: `Micro` を「`Score` に TP/FP/FN を集計 → `fillScore` を呼ぶ」形に置換し、
  計算式の単一所有にする（数値は不変）。
- 検証: `go test ./internal/eval` 緑（`TestAccuracy`/`TestReadmeBadges`）→
  `go test ./internal/eval -run TestGenerateDoc -update && git diff --exit-code docs/accuracy.md`
  が**diff ゼロ**であること（数値が動いていない証明）。
- 判定: **今やる**（小さな純リファクタ）。

#### D5. `detect.Finding` の JSON タグが誤解を招く（生 PII 漏えいの潜在フットガン）
- 根拠: `internal/detect/detect.go:22-34` の `Finding` は `Match string json:"match"`（**生値**）
  等のタグを持つが、実際の JSON 出力は `internal/report/report.go:47` の別構造体 `jsonFinding`
  を経由し、`Finding` を直接 marshal する箇所は**存在しない**（確認済み: `report.go` の
  `json.NewEncoder` は `out`/`doc` を符号化）。
- なぜ負債か: `Finding` のタグは現状未使用かつ「`match` がマスク済み」という出力の実態と食い違う。
  将来誰かが `json.Marshal(finding)` すると**生 PII を `"match"` で漏らす**。
- 影響範囲: `internal/detect`（内部パッケージのみ。外部 import 不可）。出力経路には現状無影響。
- 変更リスク: 低（内部型・直接 marshal 経路なし）。
- 改善案（どちらか）:
  - (推奨) `Finding` から誤解を招く JSON タグを外す、または `Match` を `json:"-"` にして
    「直接 marshal では生値を出さない」ことを型で示す。`start,end`（非公開）はそのまま。
  - もしくは型コメントで「直接 marshal するな。出力は report.jsonFinding 経由」と明記。
- 検証: `go test -race ./...` 緑（出力テストは `jsonFinding` 経由なので影響なし）。
  追加で「`json.Marshal(Finding{Match:"..."})` が生値を含まない」回帰テストを足すと尚良い。
- 判定: **今やってよい**（内部型）。ただし**タグ削除が出力に波及しないこと**をテストで必ず確認。
  少しでも不安なら型コメント明記に留め、Stop And Ask。

### 🟡 提案のみ（承認なしに実装しない／挙動・契約・性能に触れる）

#### D6. `config.containsID` が `slices.Contains` の再実装
- 根拠: `internal/config/config.go:167` `containsID`。`builtin.go:323` は既に `slices.Contains` 使用。
- なぜ負債か: 標準ライブラリの再発明。
- 影響範囲/リスク: `internal/config` のみ／極小（`config_test.go` が網羅）。
- 改善案: `slices.Contains` に置換（`slices` import 追加）。
- 検証: `go test ./internal/config` 緑。
- 判定: **任意・低優先**。安全だが価値が小さい。D3 と混ぜず単独コミットなら今やってもよい。

#### D7. ネガティブコンテキストの「データ」と「意味」の所有が分離（隠れ結合）
- 根拠: キーワード一覧 `digitRuleNegativeContext` は `internal/rule/builtin.go:48`。
  各語が「通貨接頭/通貨接尾/カウンタ接尾/汎用」のどれかという**意味判定**は
  `internal/detect/detect.go:408-430`（`isCurrencyPrefix`/`isCurrencySuffix`/`isCounterSuffix`）に
  ハードコード。
- なぜ負債か: `rule` 側に語を足しても、`detect` 側の分類器を更新しないと黙って「汎用」扱いになり、
  単位近接判定（前後の `円`/`人` 等）が効かない。結合が暗黙で発見しづらい。
- 影響範囲: 検出挙動（ネガティブコンテキスト）。
- 変更リスク: **中〜高**（挙動に直結。`detect_test.go:217` 系が固定）。
- 改善案（提案）: (a) まずは両所にクロスリファレンスのコメントを足して結合を可視化（安全）。
  (b) 将来的に語の分類を `rule` 側のメタデータ（例: 種別つきの語リスト）に寄せて単一所有にする
  （これは設計変更）。
- 検証: 挙動不変を `go test ./internal/eval`＋`detect` テストで担保。
- 判定: **(a) コメント追記は今やってよい。(b) 設計変更は提案のみ＝Stop And Ask**。

#### D8. コンテキスト照合の二重 toLower（ナイーブな最適化は危険）
- 根拠: `matchingContexts`（`detect.go:486`）が内部で `strings.ToLower`。呼び出し側 `ScanLine` の
  `ctx()`（`:258`）は既に `lower` を作って渡す → 二重。一方 `ctxNear`（`:266`）は未小文字化の
  `contextWindow(norm,...)` を渡しており、**`matchingContexts` 内の ToLower に依存している**。
- なぜ負債か: 一見「内部 ToLower を消せば速くなる」が、`ctxNear` 経路が壊れる。安易な最適化の罠。
- 影響範囲: ホットパス（昇格・RequireContext 判定）。
- 変更リスク: **高**（消し方を誤ると照合が壊れる。挙動 6/7 に影響）。
- 改善案（提案）: 小文字化の所有を**一箇所に明確化**する（例: `matchingContexts` が必ず小文字化し、
  呼び出し側は小文字化しない、を統一）リファクタ。やるならベンチ前後比較必須。
- 検証: `go test ./internal/detect` 緑＋`go test -bench . ./internal/detect` で退行なし確認。
- 判定: **提案のみ**（今は触らない。少なくともこのナイーブ削除はしないこと）。

#### D9. `min_confidence` の検証が遅い（`config.Parse` ではなく `detect.New`）
- 根拠: `config.go` は `MinConfidence` を検証しない。`detect.New`（`:58`）で `ParseConfidence`。
- なぜ負債か: `min_confidence="bogus"` でも `config.Parse` は成功し、エラーは後段で出る（契約が曖昧）。
- 影響範囲: エラーの**発生タイミング/メッセージ**。`main_test.go:121` は `--min-confidence bogus`→
  終了コード 2 を期待（現状は `detect.New` 経由で満たす）。
- 変更リスク: 中（エラー文言・タイミングが変わると既存テスト/利用者の期待に影響しうる）。
- 改善案（提案）: `config.compile()` で `min_confidence` を早期検証。
- 判定: **提案のみ**（挙動タイミング変更。Stop And Ask）。

#### D10. `--diff <range>` の引数インジェクション・ハードニング
- 根拠: `internal/source/gitdiff.go:26-28` は固定オプション群の末尾に `<range>` を**そのまま追加**し、
  `--`/`--end-of-options` のガードがない。シェルは経由しない（`exec.Command`）ため**シェル
  インジェクションはない**が、`--diff "--something"` のような**git オプション注入**が理論上可能。
- なぜ負債か: 低リスクだが堅牢性の欠如。実運用（リポジトリ所有者が範囲を渡す、Action は
  `github.base_ref`=保護されたターゲットブランチ名）では脅威度は低い。
- 影響範囲: `internal/source/gitdiff.go`。
- 変更リスク: 中（`git diff` のコマンド契約変更。`--` を素直に付けると range がパス扱いになり
  **壊れる**ため、`--end-of-options <range>` 等の正しい方法と git バージョン互換の検証が必要）。
- 改善案（提案）: `git diff [opts] --end-of-options <range>` 化を検証付きで。
- 検証: `source/gitdiff_test.go` 全緑＋手動で範囲指定が従来通り動くこと。
- 判定: **提案のみ**（セキュリティ堅牢化。要検証・Stop And Ask）。

#### D11. `scanFiles` は最初の読み取りエラーで全走査を中断（fail-fast）
- 根拠: `internal/source/files.go:154-158` は `errs[i]` の最初の非 nil で全体を返す。
- なぜ負債か: 1 ファイルの読み取り失敗でスキャン全体が止まる。意図的（fail-closed）かもしれない。
- 影響範囲: フルスキャンの堅牢性／終了コード（2）。
- 変更リスク: 中（「中断 vs 継続して警告」はプロダクト判断）。
- 改善案（提案）: 継続して末尾でまとめて報告、等。
- 判定: **提案のみ**（Stop And Ask 条件7）。

#### D12. `hasCrossLineNegativeContext` の再正規化＋線形ルール探索（軽微な性能）
- 根拠: `detect.go:144-184` は候補 finding ごとに隣接行を `normalize.Line` で再正規化し、
  `d.rules` を線形走査して `NegativeContext` を引く（`:148-154`）。`ScanContent` 内で候補毎に発生。
- なぜ負債か: finding がある時のみとはいえ、行の再正規化とルールの線形検索が重複。
- 影響範囲: `ScanContent` の性能（検出のある入力）。
- 変更リスク: 中（**挙動を厳密に保ったまま**キャッシュ化する必要）。
- 改善案（提案）: ルール ID→NegativeContext の map を `Detector` 構築時に用意（ただし
  `Detector` は読み取り専用不変条件を守る＝構築時に確定し走査中は不変なら可）、隣接行の
  正規化結果を `ScanContent` 内で再利用。
- 検証: `detect` 全テスト緑＋ベンチ。
- 判定: **提案のみ**（性能最適化。挙動不変が必須）。

#### D13. `eval.Span.Tags` が未使用（write-only メタデータ）
- 根拠: `internal/eval/eval.go:28` で定義、`dataset.go`/`eval_test.go` で**設定はされるが、
  評価ロジック（`matchSpans`/`augment`）からは一切読まれない**（`grep '\.Tags'` で参照ゼロ＝確認済み）。
- なぜ負債か: 現状デッドな書き込み専用フィールド。一方で「easy/hard 層化用」の意図が
  コメントに明記され、将来の層化レポートを見据えた前方互換の可能性がある。
- 影響範囲: `internal/eval`。
- 変更リスク: 低（消すだけならコンパイルは通る）。
- 改善案: **削除しない**。意図（層化）を活かすなら層化集計を足す、不要なら削除、の判断が要る。
- 判定: **削除候補だが不要と断定できない → Stop And Ask（条件5）**。質問で確認するまで保持。

#### D14. レポートの書き込みエラー処理が不統一
- 根拠: `report.Text`（`:36`）/`report.GitHub`（`:85`）は `fmt.Fprintf` のエラーを捨てる。
  一方 `report.JSON`（`:59`）/`report.SARIF`（`:106`）は error を返し `main.go` が処理。
- なぜ負債か: 同種 API でエラー契約が不一致。
- 影響範囲: `internal/report`、`main.go` の呼び出し。
- 変更リスク: 低〜中（`Text`/`GitHub` を error 返しに変えると `main.go` の分岐も変わる）。
- 改善案（提案）: 4 関数のエラー契約を揃える。
- 判定: **提案のみ・低優先**（小さな API 整合。価値も小）。

#### D15. `itoa` のハンドロール（`strconv.Itoa` の再実装）
- 根拠: `detect.go:130-142` `itoa` は `findingKey`（`ScanContent` の重複排除）でのみ使用。
- なぜ負債か: 標準の再発明。ただし配置はホットパスではない（マッチ毎ではなく候補集約時）。
- 改善案（提案）: `strconv.Itoa` 置換、または `fmt.Sprintf` 不使用方針の理由をコメント化。
- 判定: **提案のみ・低優先**。

---

## Implementation Phases（実装フェーズ / 小さく安全な順）

> 各フェーズは**独立コミット**にし、無関係な変更を混ぜない。各フェーズ後に Verification を実行。

**Phase 0 — 現状確認**
- `git status` で作業ツリーがクリーンか確認。**既存の未コミット変更があれば自分の変更と混ぜない**
  （別管理 or 確認）。
- Baseline Commands を全実行し、結果を控える（特に `gofmt -l .` の現状 1 件と、eval/build/scan が
  緑であること）。

**Phase 1 — 安全網（純追加）**
- D2: `internal/rule/builtin_test.go` を新設し、`validPhone`/`validEmail`/`stripSeparators`/
  `containsASCIIAlnum` の**現状挙動**を固定（値は既存テスト/データセットから流用、新仕様を作らない）。
- 検証: `go test ./internal/rule` 緑、`go test -race ./...` 緑。

**Phase 2 — 明らかに安全な整理**
- D1: `gofmt -w internal/detect/detect.go`（whitespace のみ）。
- （任意）D6: `containsID` → `slices.Contains`。
- 検証: `gofmt -l .` 空、`go vet ./...`、`go test -race ./...` 緑。

**Phase 3 — 小さな責務分離（同一パッケージ内のファイル移動）**
- D3: `internal/detect/detect.go` を `context.go`/`negative_context.go`/`overlap.go` 等へ機械分割
  （シグネチャ・ロジック不変、移動のみ）。
- D4: `eval.Micro` を `fillScore` 利用へ統一（数値不変）。
- 検証: `go test -race ./...` 緑、かつ
  `go test ./internal/eval -run TestGenerateDoc -update && git diff --exit-code docs/accuracy.md`
  が**diff ゼロ**。`gofmt -l .` 空。

**Phase 4 — 境界・契約の明確化（低リスクのみ）**
- D5: `detect.Finding` の誤解を招く JSON タグの除去 or `json:"-"` 化（必要なら回帰テスト追加）。
  少しでも出力に波及する懸念があれば**型コメント明記に留めて Stop And Ask**。
- D7(a): ネガティブコンテキストの「語(rule)↔意味(detect)」結合を相互コメントで可視化。
- 検証: `go test -race ./...` 緑、出力テスト不変。

**Phase 5 — 大きな設計/挙動/性能変更（提案に留める。承認なしに実装しない）**
- D7(b)/D8/D9/D10/D11/D12/D13/D14/D15。各々について「現状・改善案・リスク・検証方法」を
  Reporting Format の `Proposals` にまとめ、**実装はしない**。Stop And Ask で人間の判断を仰ぐ。

---

## Verification Requirements（検証要件）

**各フェーズ後**に最低限:

```console
gofmt -l .                                   # 空であること
go vet ./...
go test -race ./...                          # 全パッケージ緑（並行安全の回帰防止）
go test ./internal/eval -run TestGenerateDoc -update && git diff --exit-code docs/accuracy.md
                                             # diff ゼロ = 検出挙動を変えていない証拠
go build ./cmd/jp-pii-detect
./jp-pii-detect scan --format github .       # 検出ゼロ・終了コード 0
```

- **ホットパス**（`normalize.Line` / `detect.ScanLine` 周辺）に触れたら追加で:
  `go test -bench . -benchmem ./internal/normalize/ ./internal/detect/` を前後比較し、
  純 ASCII 0 アロケーション（`TestLineASCIIFastPathReturnsSameString`）が維持されていること。
- `go test ./internal/eval` が落ちたら、それは**挙動を変えた**サイン。安全リファクタのはずなら
  原因を特定して**元に戻す**（`wantF1` を書き換えて通すのは禁止＝Out-of-scope）。
- `git diff` を読み、**移動/整形以外の意味変化が混入していない**ことを目視確認。

---

## Reporting Format（最終報告フォーマット）

実装後、以下を Markdown で報告すること:

1. **Summary** — 実施したフェーズと変更の要約（挙動は不変である旨）。
2. **Commits** — フェーズ単位のコミットと、各々が何を移動/整形/追加したか。
3. **Verification Log** — 実行した**全コマンドと結果**（Baseline と着手後の両方。特に
   `git diff --exit-code docs/accuracy.md` が diff ゼロだったこと、`go test -race ./...` が緑、
   `gofmt -l .` が空、ドッグフーディング scan が終了コード 0）。
4. **Skipped/Deferred** — 提案のみに留めた項目（D7b/D8/D9/D10/D11/D12/D13/D14/D15）と理由。
5. **Proposals** — 上記提案の各々について「現状・改善案・リスク・検証方法」。
6. **Open Questions** — Stop And Ask で保留した事項（特に D13 `Span.Tags` の扱い、CI への
   `gofmt` ゲート追加可否）。

---

## Out-of-scope Items（今回やらないこと）

- 検出精度（recall/precision/F1）の向上、`wantF1`・`internal/eval/dataset.go`・README バッジ・
  `docs/accuracy.md` の**数値変更**（挙動変更を伴うため）。
- 新しい検出ルールの追加、既存ルールの正規表現・しきい値・コンテキスト語の変更。
- モジュールパス（`...detecter`）・バイナリ名（`jp-pii-detect`）・マーカー文字列
  （`jp-pii-detector:ignore` / `pii-allow`）の改名。
- 出力フォーマット（json/sarif/github/text）や `.jp-pii.toml` スキーマの変更。
- 依存ライブラリの追加/更新（Dependabot 管轄）。`go.mod`/`go.sum` の変更。
- CI（`.github/workflows/ci.yml`）・`action.yml`・`.pre-commit-hooks.yaml`・`.jp-pii.toml` の変更
  （承認があった場合のみ別途）。
- 「見た目を綺麗にするための」広範な改名・整形・ついでのリファクタ。
- 証拠（ファイル・行・テスト）のない削除や全面書き換え。

---

### 作業上の制約（再掲・必読）
- 最初に `git status` を確認し、既存の未コミット変更と自分の変更を混ぜない。
- 編集前に Baseline の検証結果を記録する。
- 変更は小さく戻しやすい単位（フェーズ＝コミット）に。
- 無関係な整形やついでのリファクタをしない。
- 既存挙動を勝手に変えない。正しさが不明なら**実装を止めて質問**する。
- 各フェーズごとに検証する。
- 最後に実行したコマンドと結果を報告する。
