#!/usr/bin/env bash
# ONNX Runtime の公式 CPU 版リリースを取得して SHA-256 を検証し、共有ライブラリを
# <dest>/lib/ に、LICENSE と ThirdPartyNotices.txt を <dest>/licenses/onnxruntime/ に置く。
#
#   scripts/fetch-onnxruntime.sh <goos> <goarch> <dest>
#
# ダウンロードしたアーカイブは ORT_CACHE_DIR（既定: ${XDG_CACHE_HOME:-~/.cache}/jp-pii-detect）
# に残し、次回はそれを使う（SHA-256 は毎回検証する）。
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=model-bundle.env
. "$here/model-bundle.env"

goos=${1:?usage: fetch-onnxruntime.sh <goos> <goarch> <dest>}
goarch=${2:?usage: fetch-onnxruntime.sh <goos> <goarch> <dest>}
dest=${3:?usage: fetch-onnxruntime.sh <goos> <goarch> <dest>}

case "$goos/$goarch" in
linux/amd64) plat=linux_x64 ext=tgz lib=libonnxruntime.so src="lib/libonnxruntime.so.${ORT_VERSION}" ;;
linux/arm64) plat=linux_aarch64 ext=tgz lib=libonnxruntime.so src="lib/libonnxruntime.so.${ORT_VERSION}" ;;
darwin/arm64) plat=osx_arm64 ext=tgz lib=libonnxruntime.dylib src="lib/libonnxruntime.${ORT_VERSION}.dylib" ;;
windows/amd64) plat=win_x64 ext=zip lib=onnxruntime.dll src="lib/onnxruntime.dll" ;;
*)
	echo "fetch-onnxruntime: $goos/$goarch 向けの ONNX Runtime 公式ビルドはありません（対応: linux/amd64, linux/arm64, darwin/arm64, windows/amd64）" >&2
	exit 1
	;;
esac
key="ORT_SHA256_${plat}"
want=${!key:?"$key が model-bundle.env にありません"}
name="onnxruntime-${plat//_/-}-${ORT_VERSION}"
archive="${name}.${ext}"

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

cache=${ORT_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/jp-pii-detect}
mkdir -p "$cache"
if [ ! -f "$cache/$archive" ] || [ "$(sha256 "$cache/$archive")" != "$want" ]; then
	curl -fsSL --retry 3 -o "$cache/$archive.tmp" \
		"https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/${archive}"
	mv "$cache/$archive.tmp" "$cache/$archive"
fi
got=$(sha256 "$cache/$archive")
if [ "$got" != "$want" ]; then
	echo "fetch-onnxruntime: $archive の SHA-256 が一致しません（want $want, got $got）" >&2
	exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [ "$ext" = zip ]; then
	if command -v unzip >/dev/null 2>&1; then
		# デバッグシンボル（.pdb、数百 MB）は展開しない。
		unzip -q "$cache/$archive" "$name/$src" "$name/LICENSE" "$name/ThirdPartyNotices.txt" -d "$work"
	else
		# Git Bash に unzip がない場合。PowerShell には Windows 形式のパスを渡す。
		powershell -NoProfile -Command "Expand-Archive -LiteralPath '$(cygpath -w "$cache/$archive")' -DestinationPath '$(cygpath -w "$work")'"
	fi
else
	tar -xzf "$cache/$archive" -C "$work"
fi

mkdir -p "$dest/lib" "$dest/licenses/onnxruntime"
# シンボリックリンクではなく実体を、ORT の探索名（libonnxruntime.so など）で置く。
cp -L "$work/$name/$src" "$dest/lib/$lib"
cp "$work/$name/LICENSE" "$dest/licenses/onnxruntime/LICENSE"
cp "$work/$name/ThirdPartyNotices.txt" "$dest/licenses/onnxruntime/ThirdPartyNotices.txt"
echo "fetch-onnxruntime: onnxruntime ${ORT_VERSION} ($plat) -> $dest/lib/$lib" >&2
