# jp-pii-detect モデル同梱ビルド：同梱物とライセンス表示

このアーカイブは、jp-pii-detect（MIT License）に、ローカル推論モデル
sumi-ja-pii-nemotron-ft（Sumi を追加学習したモデル）と ONNX Runtime を同梱した配布物です。
各構成要素のライセンス本文は `licenses/` にあります。

This archive bundles jp-pii-detect (MIT) with sumi-ja-pii-nemotron-ft, a fine-tune of
the Sumi model (Apache-2.0), and ONNX Runtime (MIT). Full license texts are in `licenses/`.

## 同梱物

| 構成要素 | 置き場所 | ライセンス | 著作権者・出典 |
|---|---|---|---|
| jp-pii-detect | `jp-pii-detect` | MIT（`licenses/jp-pii-detector/LICENSE`） | Copyright (c) 2026 baneido。辞書の出典は `licenses/jp-pii-detector/THIRD_PARTY_NOTICES.md` |
| sumi-ja-pii-nemotron-ft（`baneido/sumi-ja-pii-nemotron-ft`） | `model/` | Apache License 2.0（`licenses/sumi-ja-pii/LICENSE`） | baneido。https://huggingface.co/baneido/sumi-ja-pii-nemotron-ft （リビジョン `@@SUMI_REVISION@@`） |
| Sumi（`NagaYu/sumi-ja-pii`。追加学習の元） | sumi-ja-pii-nemotron-ft の重みに含まれる | Apache License 2.0（`licenses/sumi-ja-pii/LICENSE`） | Sumi contributors。https://huggingface.co/NagaYu/sumi-ja-pii （リビジョン `daa43a033830a38911b178e7951b97ad64b0080a`）、https://github.com/NagaYu/sumi |
| ModernBERT-Ja-130M（Sumi のベースモデル） | Sumi の重みに含まれる | MIT（`licenses/modernbert-ja-130m/LICENSE`） | Copyright (c) 2025 SB Intuitions。https://huggingface.co/sbintuitions/modernbert-ja-130m |
| ONNX Runtime @@ORT_VERSION@@ | `lib/` | MIT（`licenses/onnxruntime/LICENSE`） | Copyright (c) Microsoft Corporation。ONNX Runtime が含むサードパーティのライセンスは `licenses/onnxruntime/ThirdPartyNotices.txt` |
| Go 標準ライブラリと Go モジュール | `jp-pii-detect` に静的リンク | BSD-3-Clause / MIT ほか（`licenses/go/`） | 各ディレクトリの LICENSE を参照 |

## モデルのファイルについて（Apache-2.0 第 4 条の変更表示）

`model/` の 4 ファイルは、上記リビジョンの sumi-ja-pii-nemotron-ft のファイルです
（SHA-256 はリポジトリの `scripts/model-bundle.env` に記録）。Sumi との違いは次のとおりです。

- `model.int8.onnx`：Sumi の重みを baneido が追加学習で変更し、ONNX に変換して INT8 に動的量子化したもの。
- `calibrator.json`：追加学習後に baneido が合わせ直した温度スケーリングの値。
- `tokenizer.json`、`sumi_labels.json`：Sumi の作者が公開したファイルを**改変せずに**含めている。

jp-pii-detect は、このモデルの出力に独自の後処理（書式検証などの確認器、組み込み
ルールとの重複解決）をかけて報告します。後処理は jp-pii-detect のコード
（MIT License）であり、モデルのファイル自体は変更していません。

The model weights in `model/` are Sumi's weights changed by fine-tuning (baneido),
then exported to ONNX and INT8-quantized; `calibrator.json` was refitted after
fine-tuning. `tokenizer.json` and `sumi_labels.json` are Sumi's files, unmodified.

## 学習データのクレジット（同梱していません）

sumi-ja-pii-nemotron-ft は、次のデータで Sumi を追加学習しています。

- [nvidia/Nemotron-PII-Japan](https://huggingface.co/datasets/nvidia/Nemotron-PII-Japan)（NVIDIA、CC BY 4.0）
- 個人情報を含まない例として [reactjs/ja.react.dev](https://github.com/reactjs/ja.react.dev)（CC BY 4.0）、
  [yasslab/railsguides.jp](https://github.com/yasslab/railsguides.jp)（文書は CC BY-SA 4.0、コードは MIT）、
  [ikawaha/kagome](https://github.com/ikawaha/kagome)（MIT）の文書とコード

元の Sumi は、合成データセット
[NagaYu/sumi-ja-pii-corpus](https://huggingface.co/datasets/NagaYu/sumi-ja-pii-corpus)
（CC BY-SA 4.0。Wikipedia 由来の部分を含む）で学習されています。このアーカイブには
学習データを含めていません。

sumi-ja-pii-nemotron-ft was fine-tuned on nvidia/Nemotron-PII-Japan (CC BY 4.0), with
PII-free text and code from reactjs/ja.react.dev (CC BY 4.0), yasslab/railsguides.jp
(content CC BY-SA 4.0, code MIT) and ikawaha/kagome (MIT). Sumi was trained on
NagaYu/sumi-ja-pii-corpus (CC BY-SA 4.0, partly derived from Wikipedia). No training
data is included in this archive.

## 免責

- Sumi の作者は、Sumi がコンプライアンスを保証する仕組みではないこと（"Sumi is not a
  compliance control. It reduces risk; it does not certify anything."）、見逃しは
  必ず起きること（"Misses are certain."）、評価値はすべて合成データでの上限値で
  あることを明記しています。sumi-ja-pii-nemotron-ft と jp-pii-detect も同様に、
  個人情報が含まれないことを保証するものではありません。
- 本アーカイブの各構成要素は、それぞれのライセンスに従い「現状のまま」（AS IS）、
  いかなる保証もなく提供されます。
- この表示は法的助言ではありません。
