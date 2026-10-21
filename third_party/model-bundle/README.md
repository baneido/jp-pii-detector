# jp-pii-detect（Sumi モデル同梱ビルド）

日本特化の個人情報（PII）静的検出器 jp-pii-detect に、ローカル推論モデル
[Sumi](https://huggingface.co/NagaYu/sumi-ja-pii)（ONNX INT8）と ONNX Runtime を
同梱したビルドです。展開するだけで、組み込みルールにモデル起点の検出を加えた走査が
できます（`--model-dir` の指定や ONNX Runtime の別途インストールは不要）。

```sh
./jp-pii-detect scan .            # 組み込みルール + Sumi で走査
./jp-pii-detect scan --staged     # pre-commit 用
./jp-pii-detect scan --no-model . # モデルを使わず組み込みルールだけで走査
./jp-pii-detect version           # 2 行目に同梱しているモデルと ONNX Runtime の版
```

- 実行ファイルは、隣にある `model/`（モデル）と `lib/`（ONNX Runtime）を使います。
  ディレクトリ構成を保ったまま任意の場所に置き、`PATH` にはシンボリックリンクを
  張ってください（リンク先の実体の場所を基準に探します）。
- モデルの読み込みに失敗したときは、黙ってルールだけで走査せず終了コード 2 で
  終わります。
- モデル推論は試験的機能です。メモリを 1 ワーカーあたり数百 MB 使い、
  ルールだけの走査より遅くなります。
- Linux（x86-64）では、仮想マシンで INT8 推論の結果が壊れる ONNX Runtime の不具合
  （microsoft/onnxruntime#33247）を避けるため、既定で AMX を使わせません
  （`JP_PII_ORT_AMX=1` で解除）。このためプロセスに no_new_privs が付きます。
- macOS で、ブラウザでダウンロードしたアーカイブから展開した場合は、Gatekeeper の
  隔離属性で実行や `lib/` の読み込みが拒否されることがあります。その場合は
  `xattr -dr com.apple.quarantine <展開先>` で外してください。

同梱物のライセンスと帰属表示、免責は `NOTICE.md` と `licenses/` を参照してください。
Sumi は見逃しが必ず起きることを前提にしたリスク低減の道具であり、コンプライアンスを
保証するものではありません。
