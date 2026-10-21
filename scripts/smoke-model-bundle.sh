#!/usr/bin/env bash
# モデル同梱ビルドのアーカイブを空のディレクトリに展開し、追加の設定なしで
# モデル起点の検出が動くことを確かめる（release-model ワークフローとローカル確認用）。
# PII はダミー値だけを使う。
#
#   scripts/smoke-model-bundle.sh <archive.tar.gz>
set -euo pipefail

archive=${1:?usage: smoke-model-bundle.sh <archive.tar.gz>}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xzf "$archive" -C "$work"
top=$(find "$work" -mindepth 1 -maxdepth 1 -type d | head -n 1)
bin="$top/jp-pii-detect"
[ -x "$bin" ] || bin="$top/jp-pii-detect.exe"

fail() { echo "smoke-model-bundle: $*" >&2; exit 1; }

for f in LICENSE NOTICE.md README.md \
	licenses/sumi-ja-pii/LICENSE licenses/modernbert-ja-130m/LICENSE \
	licenses/onnxruntime/LICENSE licenses/onnxruntime/ThirdPartyNotices.txt \
	licenses/jp-pii-detector/THIRD_PARTY_NOTICES.md licenses/go/golang-go.LICENSE \
	model/model.int8.onnx model/tokenizer.json model/sumi_labels.json model/calibrator.json; do
	[ -s "$top/$f" ] || fail "$f がありません"
done

"$bin" version | grep -q '^bundle: ' || fail "version に同梱物の表示がありません"

mkdir -p "$work/scan"
cd "$work/scan"
# ダミーの PII（実在しない氏名・番号）。
cat >pii.txt <<'TXT'
田中太郎様よりご連絡をいただきました。連絡先は090-1234-5678です。
お届け先：東京都千代田区千代田1-1 架空ビル101 佐藤花子 様
TXT
# PII を含まないコード。
cat >sample.go <<'GO'
package sample

import "os"

// Open は設定ファイルを開く。
func Open(name string) (*os.File, error) {
	def := name + ".toml"
	return os.Open(def)
}
GO

set +e
"$bin" scan --format json --explain pii.txt >pii.json
code=$?
set -e
[ "$code" = 1 ] || fail "ダミー PII の走査の終了コードが $code（期待値 1）"
grep -q '"model": *true' pii.json || fail "モデル起点の検出がありません: $(cat pii.json)"

set +e
"$bin" scan --format json sample.go >code.json
code=$?
set -e
[ "$code" = 0 ] || fail "PII のないコードで検出がありました（終了コード $code）: $(cat code.json)"

set +e
"$bin" scan --no-model --format json --explain pii.txt >nomodel.json
code=$?
set -e
[ "$code" = 1 ] || fail "--no-model の走査の終了コードが $code（期待値 1）"
if grep -q '"model": *true' nomodel.json; then fail "--no-model でモデル起点の検出が出ました"; fi

echo "smoke-model-bundle: OK ($(basename "$archive"))"
