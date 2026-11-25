#!/usr/bin/env bash
# ONNX Runtime の公式 NuGet パッケージ（Microsoft.ML.OnnxRuntime、CPU 版）を取得して
# SHA-256 を検証し、共有ライブラリを <dest>/lib/ に、LICENSE と ThirdPartyNotices.txt を
# <dest>/licenses/onnxruntime/ に置く。
#
#   scripts/fetch-onnxruntime.sh <goos> <goarch> <dest>
#
# ダウンロードしたパッケージは ORT_CACHE_DIR（既定: ${XDG_CACHE_HOME:-~/.cache}/jp-pii-detect）
# に残し、次回はそれを使う（SHA-256 は毎回検証する）。
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=model-bundle.env
. "$here/model-bundle.env"

goos=${1:?usage: fetch-onnxruntime.sh <goos> <goarch> <dest>}
goarch=${2:?usage: fetch-onnxruntime.sh <goos> <goarch> <dest>}
dest=${3:?usage: fetch-onnxruntime.sh <goos> <goarch> <dest>}

case "$goos/$goarch" in
linux/amd64) rid=linux-x64 lib=libonnxruntime.so ;;
linux/arm64) rid=linux-arm64 lib=libonnxruntime.so ;;
darwin/arm64) rid=osx-arm64 lib=libonnxruntime.dylib ;;
windows/amd64) rid=win-x64 lib=onnxruntime.dll ;;
*)
	echo "fetch-onnxruntime: $goos/$goarch 向けの ONNX Runtime 公式ビルドはありません（対応: linux/amd64, linux/arm64, darwin/arm64, windows/amd64）" >&2
	exit 1
	;;
esac
want=${ORT_NUGET_SHA256:?"ORT_NUGET_SHA256 が model-bundle.env にありません"}
archive="microsoft.ml.onnxruntime.${ORT_VERSION}.nupkg"
src="runtimes/${rid}/native/${lib}"

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
		"https://api.nuget.org/v3-flatcontainer/microsoft.ml.onnxruntime/${ORT_VERSION}/${archive}"
	mv "$cache/$archive.tmp" "$cache/$archive"
fi
got=$(sha256 "$cache/$archive")
if [ "$got" != "$want" ]; then
	echo "fetch-onnxruntime: $archive の SHA-256 が一致しません（want $want, got $got）" >&2
	exit 1
fi

# .nupkg は zip。必要な 3 ファイルだけを取り出す（Android・iOS 版などは展開しない）。
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if command -v unzip >/dev/null 2>&1; then
	unzip -q "$cache/$archive" "$src" LICENSE ThirdPartyNotices.txt -d "$work"
else
	# Git Bash に unzip がない場合。PowerShell には Windows 形式のパスを渡す。
	powershell -NoProfile -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; \$z = [IO.Compression.ZipFile]::OpenRead('$(cygpath -w "$cache/$archive")'); foreach (\$n in @('$src', 'LICENSE', 'ThirdPartyNotices.txt')) { \$e = \$z.GetEntry(\$n); \$o = Join-Path '$(cygpath -w "$work")' \$n; New-Item -ItemType Directory -Force -Path (Split-Path \$o) | Out-Null; [IO.Compression.ZipFileExtensions]::ExtractToFile(\$e, \$o, \$true) }; \$z.Dispose()"
fi

mkdir -p "$dest/lib" "$dest/licenses/onnxruntime"
cp "$work/$src" "$dest/lib/$lib"
cp "$work/LICENSE" "$dest/licenses/onnxruntime/LICENSE"
cp "$work/ThirdPartyNotices.txt" "$dest/licenses/onnxruntime/ThirdPartyNotices.txt"
echo "fetch-onnxruntime: onnxruntime ${ORT_VERSION} (NuGet, $rid) -> $dest/lib/$lib" >&2
