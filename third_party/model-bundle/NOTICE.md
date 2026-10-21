# jp-pii-detect モデル同梱ビルド：同梱物とライセンス表示

このアーカイブは、jp-pii-detect（MIT License）に、ローカル推論モデル Sumi と
ONNX Runtime を同梱した配布物です。各構成要素のライセンス本文は `licenses/` にあります。

This archive bundles jp-pii-detect (MIT) with the Sumi model (Apache-2.0) and
ONNX Runtime (MIT). Full license texts are in `licenses/`.

## 同梱物

| 構成要素 | 置き場所 | ライセンス | 著作権者・出典 |
|---|---|---|---|
| jp-pii-detect | `jp-pii-detect` | MIT（`licenses/jp-pii-detector/LICENSE`） | Copyright (c) 2026 baneido。辞書の出典は `licenses/jp-pii-detector/THIRD_PARTY_NOTICES.md` |
| Sumi（`NagaYu/sumi-ja-pii`） | `model/` | Apache License 2.0（`licenses/sumi-ja-pii/LICENSE`） | Sumi contributors。https://huggingface.co/NagaYu/sumi-ja-pii （リビジョン `@@SUMI_REVISION@@`）、https://github.com/NagaYu/sumi |
| ModernBERT-Ja-130M（Sumi のベースモデル） | Sumi の重みに含まれる | MIT（`licenses/modernbert-ja-130m/LICENSE`） | Copyright (c) 2025 SB Intuitions。https://huggingface.co/sbintuitions/modernbert-ja-130m |
| ONNX Runtime @@ORT_VERSION@@ | `lib/` | MIT（`licenses/onnxruntime/LICENSE`） | Copyright (c) Microsoft Corporation。ONNX Runtime が含むサードパーティのライセンスは `licenses/onnxruntime/ThirdPartyNotices.txt` |
| Go 標準ライブラリと Go モジュール | `jp-pii-detect` に静的リンク | BSD-3-Clause / MIT ほか（`licenses/go/`） | 各ディレクトリの LICENSE を参照 |

## Sumi のファイルについて（Apache-2.0 第 4 条の変更表示）

`model/` の 4 ファイル（`model.int8.onnx`、`tokenizer.json`、`sumi_labels.json`、
`calibrator.json`）は、上記リビジョンで Sumi の作者が公開したファイルを**改変せずに**
同梱しています（SHA-256 はリポジトリの `scripts/model-bundle.env` に記録）。
`model.int8.onnx` の ONNX への変換と INT8 動的量子化は、Sumi の作者が行ったものです。
同梱しているのは Sumi リポジトリのファイルの一部だけです（fp32 版の重み、GGUF、MLX、
図などは含みません）。

jp-pii-detect は、このモデルの出力に独自の後処理（書式検証などの確認器、組み込み
ルールとの重複解決）をかけて報告します。後処理は jp-pii-detect のコード
（MIT License）であり、モデルのファイル自体は変更していません。

The Sumi files in `model/` are redistributed unmodified from the revision above.
The ONNX conversion and INT8 quantization were performed by the Sumi authors.
jp-pii-detect applies its own post-processing to the model output; the model
files themselves are not modified.

## 学習データのクレジット（同梱していません）

Sumi は、合成データセット
[NagaYu/sumi-ja-pii-corpus](https://huggingface.co/datasets/NagaYu/sumi-ja-pii-corpus)
（CC BY-SA 4.0。Wikipedia 由来の部分を含む）で学習されています。このアーカイブには
学習データを含めていません。

Sumi was trained on NagaYu/sumi-ja-pii-corpus (CC BY-SA 4.0, partly derived from
Wikipedia). The dataset is not included in this archive.

## 免責

- Sumi の作者は、Sumi がコンプライアンスを保証する仕組みではないこと（"Sumi is not a
  compliance control. It reduces risk; it does not certify anything."）、見逃しは
  必ず起きること（"Misses are certain."）、評価値はすべて合成データでの上限値で
  あることを明記しています。jp-pii-detect も同様に、個人情報が含まれないことを
  保証するものではありません。
- 本アーカイブの各構成要素は、それぞれのライセンスに従い「現状のまま」（AS IS）、
  いかなる保証もなく提供されます。
- この表示は法的助言ではありません。
