# 開発者向けガイド

jp-pii-detect のビルド・テスト・内部構成と、検出ルールの追加方法をまとめます。
利用方法は [README](../README.md)、検出手法の調査・設計判断は
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

純 ASCII 行（ソースコードの大半）は `normalize.Line` のファストパスで
アロケーションが発生しない（0 allocs/op）ことが回帰テストで保証されています。

## 検出精度の計測

`internal/eval` にルールごとの陽性・陰性ケースを集めたラベル付き評価データセット
（[dataset.go](../internal/eval/dataset.go)）と、適合率・再現率・F1 を計測する
ハーネスがあります。README の検出精度バッジと [accuracy.md](accuracy.md) はこの実測値です。

```console
$ go test ./internal/eval            # 実測 F1 と wantF1・README バッジの一致を検証
$ go test ./internal/eval -update    # docs/accuracy.md と README のバッジを実測値で再生成
```

`eval_test.go` の `TestAccuracy` は実測 F1 が `wantF1` と一致するか、
`readme_test.go` の `TestReadmeBadges` は README の総合・ルール別バッジが
実測値と一致するかを検証します。ルールやデータセットを変えて精度が動くと
CI が落ちるので、**`wantF1` を更新し、`-update` で README のバッジと
`docs/accuracy.md` を再生成**してください。

## プロジェクト構成

```
cmd/jp-pii-detect/   CLI エントリポイント（引数解析・出力フォーマットの振り分け・終了コード）
internal/
  config/    .jp-pii.toml の読み込み（リポジトリルートまでの上方探索）
  source/    走査対象の列挙: ファイルツリー（並列）/ git diff の追加行
  detect/    行単位の検出エンジン（ScanLine/ScanContent・重複解決）
  normalize/ 日本語テキストの正規化（全角→半角・ハイフン類・長音記号）
  rule/      検出ルールの型定義と組み込みルール一覧
  checksum/  チェックディジット検証（マイナンバー・Luhn・カードブランド）
  dict/      IANA TLD などの埋め込み辞書
  report/    出力フォーマット（text/json/sarif/github）とマスキング
  eval/      ラベル付き評価データセットと検出精度（適合率・再現率・F1）の計測
```

### 検出パイプライン

1. **source** が走査対象を列挙する。フルスキャンはファイルツリーを walk し、
   バイナリ（先頭 8KB に NUL）・5MB 超・`node_modules` 等の依存ディレクトリを除外。
   git モードは `git diff -U0` の追加行のみを対象にする。
2. **detect.ScanLine** が 1 行ごとに処理する。
   - **normalize.Line** で全角英数字・ハイフン類・数字隣接の長音記号を半角化する。
     変換はルーン単位の 1:1 に限定しているため、正規化後の位置がそのまま元テキストの
     位置になり、列番号の報告に逆引きが不要。
   - ルールの `Prefilter`（数字・`@`・日本語などの必須文字種）を含まない行は
     正規表現マッチ自体をスキップする。大半のルールは数字必須のため、
     数字を含まないコード行がほぼ無コストになる。
   - 各ルールのパターンを正規表現でマッチし、`Validate`（チェックディジット等）と
     allowlist で絞り込む。同一行にコンテキストキーワードがあれば信頼度を High に昇格、
     `RequireContext` のルールはキーワードがなければ破棄する。`RequireContextWindow`
     が設定されたルールでは、キーワードをマッチ前後の指定ルーン数以内に限定する。
     ASCII キーワードは英数字の単語境界つきで照合し、`tel` が `hotel` の一部で成立する
     ような誤昇格を避ける。`NegativeContext` が近傍にある場合は、金額・数量・連番 ID と
     みなして検出を棄却する。`RequireContext` のパターンはキーワードの存在が前提のため
     昇格せず、`Base` の信頼度のまま報告する。
   - **resolveOverlaps** で範囲が重なる検出を信頼度（同率なら長い方）で 1 件に集約する。
   - **detect.ScanContent** は通常の行単位検出に加え、隣接 2 行を結合した仮想ウィンドウを
     `RequireContext` ルールに限定して走査する。検出位置は元の行・列へマップし直す。
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
- **コンテキストの設計**: ASCII キーワードは単語境界つきで照合される。桁数だけのルールは
  `RequireContextWindow` で肯定語を近接必須にし、金額・数量・連番 ID と衝突しやすい場合は
  `NegativeContext` を設定する。
- **Prefilter**: パターンが特定の文字種（数字・`@`・日本語）なしにマッチし得ない
  場合は `Prefilter` を設定する。該当文字を含まない行の走査が丸ごと省ける。
  迷ったら未設定（常に走査）が安全。
- **検証ロジック**: チェックディジットなどは `internal/checksum` に置き、独立にテストする。
  実在性確認に使う小さな静的辞書は `internal/dict` に置き、`//go:embed` で同梱する。
- **高再現率ルール**: 偽陽性リスクが高いルールは `internal/rule/high_recall.go` の
  `HighRecallRuleIDs()` に追加し、既定では `[rules] high_recall = true` または
  `--high-recall` が指定されたときだけ有効になるようにする。
- **テスト**: 検出・非検出の両方を [`internal/detect/detect_test.go`](../internal/detect/detect_test.go) に追加する。
  特に「隣接する複数件」「コンテキスト有無での信頼度」「長い数字列の一部は対象外」を確認すること。

### 埋め込み辞書の更新

IANA TLD 一覧は公式の `https://data.iana.org/TLD/tlds-alpha-by-domain.txt` を
[`internal/dict/tlds-alpha-by-domain.txt`](../internal/dict/tlds-alpha-by-domain.txt) に保存している。
更新時は同 URL から取得し、`go test ./internal/dict ./internal/detect ./internal/eval` で検証する。

郵便番号プレフィックスは日本郵便の UTF-8 版「住所の郵便番号」全データから上位 3 桁を抽出し、
[`internal/dict/postal_prefixes.txt`](../internal/dict/postal_prefixes.txt) に保存している。
更新時は `https://www.post.japanpost.jp/service/search/zipcode/download/utf-zip.html` の
最新全データを取得し、次のコマンドで再生成してから同じテストで検証する。

```console
$ go run ./internal/dict/gen -input /path/to/utf_ken_all.zip -output internal/dict/postal_prefixes.txt
```

`-input` には展開済みの UTF-8 版 KEN_ALL CSV も指定できる。

新ルールは `jp-pii-detect rules` に自動で表示されます。

## リリース

`go install ...@<version>` で配布するため、タグを切るだけで利用できます。
README・action.yml の例で参照しているバージョン（`rev: v0.1.0` 等）も合わせて更新してください。
