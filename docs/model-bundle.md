# Sumi モデル同梱ビルド

ローカル推論モデル Sumi（[NagaYu/sumi-ja-pii](https://huggingface.co/NagaYu/sumi-ja-pii)、
ONNX INT8）と ONNX Runtime を同梱し、展開するだけで `--model-dir` 相当の検出
（組み込みルール + モデル起点の検出。[design-ai-detection.md](design-ai-detection.md)）
が動く配布物である。従来の軽量バイナリ（`CGO_ENABLED=0`、`jp-pii-detect_<os>_<arch>.tar.gz`）は
変えずに、別のアセットとして配る。

## アーカイブの構成

`jp-pii-detect-sumi_<goos>_<goarch>.tar.gz` を展開すると、次のディレクトリができる。

```text
jp-pii-detect-sumi_linux_amd64/
├── jp-pii-detect          # CGO_ENABLED=1 -tags ort のビルド（Windows は .exe）
├── model/                 # Sumi（未改変）
│   ├── model.int8.onnx    #   133MB
│   ├── tokenizer.json
│   ├── sumi_labels.json
│   └── calibrator.json
├── lib/
│   └── libonnxruntime.so  # ONNX Runtime（macOS は .dylib、Windows は onnxruntime.dll）
├── README.md              # 使い方
├── NOTICE.md              # 同梱物・帰属表示・変更表示・学習データのクレジット・免責
├── LICENSE                # jp-pii-detect（MIT）
└── licenses/
    ├── jp-pii-detector/   # LICENSE、THIRD_PARTY_NOTICES.md（辞書の出典）
    ├── sumi-ja-pii/       # Apache License 2.0 全文
    ├── modernbert-ja-130m/# MIT（Copyright (c) 2025 SB Intuitions）
    ├── onnxruntime/       # LICENSE、ThirdPartyNotices.txt（ORT のアーカイブから複製）
    └── go/                # Go 標準ライブラリと、静的リンクする Go モジュールのライセンス
```

linux/amd64 の実測（ONNX Runtime 1.31.0）では、アーカイブは 108MB（103MiB）、展開後は
約 177MB（モデル 133MB、ONNX Runtime 29MB、実行ファイル 8MB）だった。

## モデルとライブラリの探し方

- `bundledModelDir`（`-ldflags -X main.bundledModelDir=model`）が埋め込まれたビルドでは、
  `--model-dir` を指定しなくても、実行ファイルのあるディレクトリの `model/` を使う。
  実行ファイルがシンボリックリンクなら、リンク先の実体の場所を基準にする。
- 優先順位は `--no-model`（モデルを使わない）、`--model-dir <dir>`、同梱の `model/` の順。
- 同梱モデルを読み込めないときは、ルールだけで走査を続けず終了コード `2` で終わる
  （`--no-model` で回避できる旨を表示する）。
- ONNX Runtime の共有ライブラリは、`JP_PII_ORT_LIBRARY`、モデルディレクトリ内、
  実行ファイルの隣の `lib/`、実行ファイルと同じディレクトリの順に探す。
  `LD_LIBRARY_PATH` などの設定は要らない。
- `jp-pii-detect version` は、2 行目に同梱しているモデルのリビジョンと ONNX Runtime の版を表示する。

## 対応プラットフォーム

| ターゲット | ランナー | 状態 |
|---|---|---|
| linux/amd64 | `ubuntu-22.04` | 対応 |
| linux/arm64 | `ubuntu-22.04-arm` | 対応 |
| darwin/arm64 | `macos-14` | 対応 |
| windows/amd64 | `windows-2022` | 試験的（失敗してもほかの公開を止めない） |
| darwin/amd64 | — | 対象外。ONNX Runtime 1.31.0 は Intel Mac 向けの公式ビルドを出していない |
| windows/arm64 | — | 対象外（軽量版と同じくサポート外のため、需要が出るまで作らない） |

cgo を使うため、クロスコンパイルはしない。各ランナーでネイティブにビルドする。
Linux は Ubuntu 22.04 でビルドするので、glibc 2.35 程度以降を前提にする
（ONNX Runtime 自体は glibc 2.28 以降）。

## ピン留めと検証

取得する外部成果物は `scripts/model-bundle.env` でピン留めし、すべて SHA-256 を検証する。

| 成果物 | ピン留め |
|---|---|
| Sumi | Hugging Face のコミット `daa43a033830a38911b178e7951b97ad64b0080a`（2026-10-17）。4 ファイルの SHA-256 |
| ONNX Runtime | 1.31.0。プラットフォームごとの公式アーカイブの SHA-256（GitHub のアセット digest と一致） |

更新するときは `scripts/model-bundle.env` の値を変え、`scripts/package-model-bundle.sh` と
`scripts/smoke-model-bundle.sh` が通ることを確かめる。ONNX Runtime の Go バインディング
（`github.com/microsoft/onnxruntime/go`）は ORT_API_VERSION 29 以上を要るので、
ONNX Runtime を 1.29 未満には下げられない。

## ビルド

```sh
# ホストの OS/アーキテクチャ向けのアーカイブを dist/ に作る（C コンパイラが必要）
scripts/package-model-bundle.sh --version v0.0.0-local
# 空のディレクトリに展開して、ダミーの PII と PII のないコードで動作を確かめる
scripts/smoke-model-bundle.sh dist/jp-pii-detect-sumi_linux_amd64.tar.gz
```

`SUMI_LOCAL_DIR=<dir>` を指定すると Sumi をダウンロードせずにコピーし、`ORT_CACHE_DIR` に
ONNX Runtime のアーカイブを置いておくと再ダウンロードしない（いずれも SHA-256 は検証する）。

## リリース

`v*` タグの push で `.github/workflows/release-model.yml` が動く。

1. `build`：プラットフォームごとに `package-model-bundle.sh` でアーカイブを作り、
   `smoke-model-bundle.sh` で確かめ、`-tags ort` の単体テストを同梱のモデルで流す。
2. `publish`：`release.yml` がリリースを作るのを待ち（最大 30 分）、
   `jp-pii-detect-sumi_*.tar.gz` と `checksums-model.txt` を添付する。軽量版の
   `checksums.txt`（Homebrew formula が参照）には触れない。

`workflow_dispatch` で手動実行もできる。`tag` を空にするとアーティファクトとして保存する
だけで、既存リリースのタグを渡すとそのリリースに添付する。

## ライセンスと帰属表示

| 構成要素 | ライセンス | 配布物での対応 |
|---|---|---|
| jp-pii-detect | MIT | `LICENSE`、`licenses/jp-pii-detector/` |
| Sumi（重み・トークナイザ・ラベル・校正値） | Apache-2.0 | 全文を `licenses/sumi-ja-pii/LICENSE` に同梱。`NOTICE.md` に出典（リビジョン）と、ファイルを改変していないこと（ONNX 変換と INT8 量子化は Sumi の作者による）を記載。Sumi のリポジトリに NOTICE ファイルはない |
| ModernBERT-Ja-130M（Sumi のベースモデル） | MIT | 著作権表示（SB Intuitions）と許諾文を `licenses/modernbert-ja-130m/LICENSE` に同梱 |
| ONNX Runtime | MIT | ORT のアーカイブの `LICENSE` と `ThirdPartyNotices.txt` をそのまま同梱 |
| Go 標準ライブラリ・Go モジュール | BSD-3-Clause、MIT | `licenses/go/` に同梱（ビルド時に `go list -deps` から集める） |
| 学習データ NagaYu/sumi-ja-pii-corpus | CC BY-SA 4.0 | 同梱しない。`NOTICE.md` と README でクレジットする |

Sumi の作者による免責（"Sumi is not a compliance control. It reduces risk; it does not
certify anything."、"Misses are certain."、評価値は合成データでの上限値であること）は
`NOTICE.md` と同梱の README に残している。

学習データに CC BY-SA 4.0（Wikipedia 由来の部分を含む）が使われていることが、学習済みの
重みの再配布に影響するかは法務判断として残る（[design-ai-detection.md](design-ai-detection.md) の
未解決事項）。本ドキュメントは法的助言ではない。

## 既知の制約

- 走査はルールだけの場合より大幅に遅い。このリポジトリ全体（222 ファイル、氏名辞書を含む）の
  フルスキャンは、8 コアの Linux でルールだけなら 0.3 秒、モデルを使うと 5 分 14 秒だった。
  辞書データのような氏名の羅列はモデルが大量に氏名と判定するので、`allowlist.paths` で除外するか
  `--no-model` を使う。pre-commit（`--staged`）など差分の走査に向く。
- Linux（x86-64）では AMX を使わせないために seccomp フィルタを入れるので、プロセスに
  no_new_privs が付く（`JP_PII_ORT_AMX=1` で解除）。
- macOS で、ブラウザでダウンロードしたアーカイブは Gatekeeper の隔離属性が付き、実行や
  `lib/libonnxruntime.dylib` の読み込みが拒否されることがある（`xattr -dr com.apple.quarantine`）。
  実行ファイルは Go のリンカによるアドホック署名だけで、公証（notarization）はしていない。
- Windows 版の ONNX Runtime は Microsoft Visual C++ 再頒布可能パッケージを要ることがある。
  Windows 版のモデル同梱ビルドは、リリース時のスモークテストとモデルテスト（`-tags ort`）でしか
  確かめていない（ルール部分のテストは ci.yml の test (windows) で PR ごとに回している）。
