#!/usr/bin/env bash
# モデル同梱ビルド（jp-pii-detect + Sumi + ONNX Runtime + ライセンス表示）の
# アーカイブを作る。cgo を使うので、実行しているホストの OS/アーキテクチャ向けにしか
# 作れない（release-model ワークフローは OS/アーキテクチャごとのランナーで実行する）。
#
#   scripts/package-model-bundle.sh [--version <v>] [--out <dir>]
#
# 出力: <out>/jp-pii-detect-sumi_<goos>_<goarch>.tar.gz
# 中身（トップディレクトリ jp-pii-detect-sumi_<goos>_<goarch>/）:
#   jp-pii-detect[.exe]  -tags ort の cgo ビルド。既定で ./model を使う
#   model/               Sumi の ONNX INT8 モデル一式（未改変）
#   lib/                 ONNX Runtime の共有ライブラリ
#   README.md NOTICE.md LICENSE licenses/
#
# SUMI_LOCAL_DIR（fetch-sumi-model.sh）と ORT_CACHE_DIR（fetch-onnxruntime.sh）で
# ダウンロードを省ける。いずれも SHA-256 は検証する。
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
# shellcheck source=model-bundle.env
. "$here/model-bundle.env"

version=dev
out="$root/dist"
while [ $# -gt 0 ]; do
	case "$1" in
	--version) version=${2:?}; shift 2 ;;
	--out) out=${2:?}; shift 2 ;;
	*) echo "usage: package-model-bundle.sh [--version <v>] [--out <dir>]" >&2; exit 2 ;;
	esac
done

goos=$(go env GOOS)
goarch=$(go env GOARCH)
if [ "$goos" != "$(go env GOHOSTOS)" ] || [ "$goarch" != "$(go env GOHOSTARCH)" ]; then
	echo "package-model-bundle: cgo ビルドのためクロスコンパイルはできません（GOOS/GOARCH を外してください）" >&2
	exit 2
fi

asset="jp-pii-detect-sumi_${goos}_${goarch}"
mkdir -p "$out"
out=$(cd "$out" && pwd)
stage="$out/$asset"
rm -rf "$stage" "$out/$asset.tar.gz"
mkdir -p "$stage/licenses"

# Windows（Git Bash）では go が返す C:\... 形式のパスを Unix 形式に直す。
unixpath() {
	if command -v cygpath >/dev/null 2>&1; then cygpath -u "$1"; else printf '%s\n' "$1"; fi
}

bin=jp-pii-detect
[ "$goos" = windows ] && bin=jp-pii-detect.exe
info="bundle: ${SUMI_REPO}@${SUMI_REVISION:0:7} + onnxruntime ${ORT_VERSION}"
(
	cd "$root"
	CGO_ENABLED=1 go build -tags ort -trimpath \
		-ldflags "-s -w -X main.version=${version} -X main.bundledModelDir=model -X 'main.bundleInfo=${info}'" \
		-o "$stage/$bin" ./cmd/jp-pii-detect
)

"$here/fetch-sumi-model.sh" "$stage/model"
"$here/fetch-onnxruntime.sh" "$goos" "$goarch" "$stage"

# ライセンス表示。
mkdir -p "$stage/licenses/jp-pii-detector" "$stage/licenses/sumi-ja-pii" "$stage/licenses/modernbert-ja-130m" "$stage/licenses/go"
cp "$root/LICENSE" "$stage/LICENSE"
cp "$root/LICENSE" "$stage/licenses/jp-pii-detector/LICENSE"
cp "$root/THIRD_PARTY_NOTICES.md" "$stage/licenses/jp-pii-detector/THIRD_PARTY_NOTICES.md"
cp "$root/third_party/model-bundle/Apache-2.0.txt" "$stage/licenses/sumi-ja-pii/LICENSE"
cp "$root/third_party/model-bundle/modernbert-ja-130m.LICENSE" "$stage/licenses/modernbert-ja-130m/LICENSE"
sed -e "s|@@SUMI_REVISION@@|${SUMI_REVISION}|g" -e "s|@@ORT_VERSION@@|${ORT_VERSION}|g" \
	"$root/third_party/model-bundle/NOTICE.md" >"$stage/NOTICE.md"
cp "$root/third_party/model-bundle/README.md" "$stage/README.md"
# バイナリに静的リンクされる Go 標準ライブラリとモジュールのライセンス。
cp "$(unixpath "$(go env GOROOT)")/LICENSE" "$stage/licenses/go/golang-go.LICENSE"
(
	cd "$root"
	CGO_ENABLED=1 go list -tags ort -deps -f '{{if .Module}}{{.Module.Path}}{{end}}' ./cmd/jp-pii-detect |
		sort -u | grep -v '^github.com/baneido/jp-pii-detector$' || true
) | while read -r mod; do
	dir=$(unixpath "$(cd "$root" && go list -m -f '{{.Dir}}' "$mod")")
	found=0
	for f in "$dir"/LICENSE* "$dir"/COPYING* "$dir"/NOTICE*; do
		[ -f "$f" ] || continue
		cp "$f" "$stage/licenses/go/${mod//\//_}.$(basename "$f")"
		found=1
	done
	if [ "$found" = 0 ]; then
		echo "package-model-bundle: $mod のライセンスファイルが見つかりません" >&2
		exit 1
	fi
done

tar -czf "$out/$asset.tar.gz" -C "$out" "$asset"
echo "$out/$asset.tar.gz"
