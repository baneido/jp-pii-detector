---
name: tag-release
description: Create and push a new release tag (vX.Y.Z) and shepherd the release workflow to completion. Use when the user asks to cut a release, tag a new version, publish binaries, or bump the released version of jp-pii-detect.
---

# リリースタグの作成と公開

`v*` タグの push が `.github/workflows/release.yml` をトリガーし、4 つのジョブが順に走る。

- **release**: `go test ./...` の後、6 ターゲット（linux/darwin/windows × amd64/arm64）をクロスビルドし、`jp-pii-detect_<goos>_<goarch>.tar.gz` と `checksums.txt` を GitHub Release に公開（`--generate-notes`）。最後にムービングメジャータグ（例 `v0`）を今回のタグへ force-move する。
- **docker**: `ghcr.io/baneido/jp-pii-detector` にマルチアーチイメージ（`<tag>` と `latest`）を push。
- **homebrew**: `TAP_GITHUB_TOKEN` があれば `baneido/homebrew-tap` に formula 更新 PR を作成（未設定なら警告のみでスキップ）。
- **docs**: README.md / README.en.md / docs/integrations.md / docs/comparison.md のバージョン表記と `scripts/distribution_test.go` の `docsVersion` 定数を新タグへ書き換える PR を自動作成する。**この PR のマージまでがリリース作業。**

重要な前提:

- ドットを含まないタグ（`v0` 等）は `release` ジョブの `if: contains(github.ref_name, '.')` によりスキップされる（force-move による再帰起動防止）。**ムービングメジャータグは手で push しない。**
- CHANGELOG ファイルは無く、リリースノートは `--generate-notes` の自動生成。
- リリースノートは Release 公開後に追記できる。

## 手順

### 1. リリース前チェック

- main ブランチの最新コミットで CI（`.github/workflows/ci.yml`）がグリーンであることを確認する。CI にはテスト・`-race`・`go vet`・精度ゴールデンゲート・dogfood（自リポジトリの PII スキャン）・docker smoke がすべて含まれる。GitHub の checks を必ず確認する。
- ローカルが main の最新と一致しているか確認する。タグは main の最新コミットに打つのが原則。

```console
git fetch origin main
git log --oneline -1 origin/main
git status
```

### 2. バージョン番号の決定

- このワークスペースはタグを fetch していないことがあるため、**リモートの**最新タグを必ず確認する（ローカルの `git tag` が空でも慌てない）。

```console
git fetch --tags origin
git ls-remote --tags origin | sed 's|.*refs/tags/||' | sort -V
```

- semver でインクリメントする。ユーザーがバージョンを指定していなければ、前回タグ以降の変更内容を見て patch / minor を提案し、ユーザーに確認する。

```console
git log <prev-tag>..origin/main --oneline
```

- 前回タグ以降に**検出結果が変わる変更**（ルール・辞書・正規化の変更）が含まれる場合、CONTRIBUTING.md の規約によりリリースノートへの明記が必要。`--generate-notes` の自動生成に頼らず、Release 公開後にノートへ追記するようユーザーに促すか、代行する。

### 3. タグ作成と push

- lightweight タグで良い（既存タグと同様。annotated にしない）。main の最新コミットに打つ。

```console
git tag vX.Y.Z origin/main
git push origin vX.Y.Z
```

- 注意: タグ push はやり直しが効きにくい（Release・GHCR・homebrew に伝播する）。**push 前にタグ名とコミット（`git rev-parse vX.Y.Z`）を最終確認する。**

### 4. ワークフローの監視

- `release.yml` の 4 ジョブ（release / docker / homebrew / docs）の完走を確認する。GitHub Actions の run を監視する。
- `release` ジョブ内の `go test ./...` が落ちるとリリース自体が中止される（アセットは公開されない）。

### 5. 後処理

- `docs` ジョブが作成する `docs-version-vX.Y.Z` ブランチの PR をレビューしてマージする。**このマージまでがリリース作業。** マージしないと `TestDocsVersionReferencesMatchDocsVersion` が案内バージョンと実リリースの不一致を検知できないままになる。
- 最終確認: GitHub Release ページのアセット、`ghcr.io/baneido/jp-pii-detector` イメージ（`<tag>` と `latest`）、`v0` タグが新タグの位置を指していること。
- 検出結果が変わる変更を含むリリースなら、Release ノートにその旨を追記する（手順 2 参照）。

## トラブルシューティング

- **`docs` ジョブの PR が作られない**: リポジトリ設定「Allow GitHub Actions to create and approve pull requests」が有効である必要がある（CLAUDE.md 記載）。有効化後、`docs` ジョブを再実行する。
- **`homebrew` ジョブがスキップされた**: `TAP_GITHUB_TOKEN` secret が未設定。formula 更新が必要なら secret を設定して再実行する。
- **タグを打ち間違えた**: 既に配布された可能性がある版数の**再利用（同名タグの打ち直し）は避ける**。Release と誤タグを削除（`gh release delete vX.Y.Z`、`git push origin :refs/tags/vX.Y.Z`）したうえで、**新しいパッチ版を切り直す**。GHCR や homebrew に伝播済みの場合、同名タグの上書きは利用者に不整合を招く。
