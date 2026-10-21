#!/usr/bin/env bash
# Sumi（NagaYu/sumi-ja-pii）の ONNX INT8 モデル一式を、scripts/model-bundle.env で
# ピン留めした Hugging Face のリビジョンから取得し、SHA-256 を検証して <dest> に置く。
#
#   scripts/fetch-sumi-model.sh <dest>
#
# SUMI_LOCAL_DIR を指定すると、ダウンロードせずにそのディレクトリからコピーする
# （オフライン用。その場合も SHA-256 は検証する）。
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=model-bundle.env
. "$here/model-bundle.env"

dest=${1:?usage: fetch-sumi-model.sh <dest>}
mkdir -p "$dest"

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

for f in model.int8.onnx tokenizer.json sumi_labels.json calibrator.json; do
	key="SUMI_SHA256_${f//./_}"
	want=${!key:?"$key が model-bundle.env にありません"}
	out="$dest/$f"
	if [ -f "$out" ] && [ "$(sha256 "$out")" = "$want" ]; then
		continue
	fi
	if [ -n "${SUMI_LOCAL_DIR:-}" ]; then
		cp "$SUMI_LOCAL_DIR/$f" "$out.tmp"
	else
		url="https://huggingface.co/${SUMI_REPO}/resolve/${SUMI_REVISION}/${f}"
		curl -fsSL --retry 3 -o "$out.tmp" "$url"
	fi
	got=$(sha256 "$out.tmp")
	if [ "$got" != "$want" ]; then
		rm -f "$out.tmp"
		echo "fetch-sumi-model: $f の SHA-256 が一致しません（want $want, got $got）" >&2
		exit 1
	fi
	mv "$out.tmp" "$out"
done
echo "fetch-sumi-model: ${SUMI_REPO}@${SUMI_REVISION} -> $dest" >&2
