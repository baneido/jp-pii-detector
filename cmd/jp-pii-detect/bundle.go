package main

// bundledModelDir は、モデル同梱ビルド（scripts/package-model-bundle.sh）が
// -ldflags "-X main.bundledModelDir=model" で埋め込む既定のモデルディレクトリ。
// 相対パスは実行ファイルのあるディレクトリ（シンボリックリンクは解決する）を基準にする。
// 空（通常のビルド）なら、--model-dir を指定しない限りモデルを使わない。
var bundledModelDir = ""

// bundleInfo は、モデル同梱ビルドで version の 2 行目に表示する同梱物の説明
// （例: "bundle: NagaYu/sumi-ja-pii@daa43a0 + onnxruntime 1.31.0"）。
var bundleInfo = ""
