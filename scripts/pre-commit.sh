#!/usr/bin/env sh
set -eu

die() {
	printf '%s\n' "jp-pii-detect pre-commit: $*" >&2
	exit 1
}

bin_name_for_os() {
	case "$1" in
		linux | Linux | darwin | Darwin) printf 'jp-pii-detect' ;;
		windows | Windows_NT | MINGW* | MSYS* | CYGWIN*) printf 'jp-pii-detect.exe' ;;
		*) die "unsupported OS: $1" ;;
	esac
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)

version=${JP_PII_DETECT_VERSION:-}
if [ -z "$version" ] && command -v git >/dev/null 2>&1; then
	# リリースワークフローはムービングメジャータグ（v0 等）をリリースタグと同じ
	# コミットへ付けるため、無条件の describe は v0 を返しうる。v0 という名前の
	# GitHub Release は存在せずダウンロードが 404 になるので、リリース資産が
	# 実在する vX.Y.Z 形式のタグだけに限定して解決する。
	version=$(git -C "$repo_root" describe --tags --exact-match \
		--match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null || true)
fi
if [ -z "$version" ]; then
	version=latest
fi

cache_root=${JP_PII_DETECT_CACHE_DIR:-}
if [ -z "$cache_root" ]; then
	if [ -n "${XDG_CACHE_HOME:-}" ]; then
		cache_root="${XDG_CACHE_HOME}/jp-pii-detector/pre-commit"
	else
		cache_root="${HOME:-.}/.cache/jp-pii-detector/pre-commit"
	fi
fi

install_dir="${cache_root}/${version}"
# 既定はモデル同梱版（install.sh）。軽量版を選んだときは別のディレクトリに
# キャッシュし、同じバージョンの同梱版と取り違えないようにする。
case "${JP_PII_DETECT_MODEL:-true}" in
	0 | false | False | FALSE | no | off) install_dir="${install_dir}-no-model" ;;
esac
bin_name=$(bin_name_for_os "${JP_PII_DETECT_OS:-$(uname -s)}")
bin="${install_dir}/${bin_name}"

# 同梱版を取得できずに軽量版を入れた後（install.sh が印を残す）も、毎回入れ直しを試す。
if [ "$version" = "latest" ] || [ ! -x "$bin" ] || [ -f "${install_dir}/.jp-pii-detect-model-fallback" ]; then
	# ダウンロード失敗（オフライン・GitHub 障害等）でコミット自体を止めない。
	# キャッシュ済みバイナリがあれば警告してそれで走査を続行する。
	if ! JP_PII_DETECT_VERSION="$version" "$script_dir/install.sh" --version "$version" --install-dir "$install_dir"; then
		if [ -x "$bin" ]; then
			printf '%s\n' "jp-pii-detect pre-commit: ダウンロードに失敗したためキャッシュ済みの ${bin} を使用します" >&2
		else
			die "jp-pii-detect ${version} をインストールできず、キャッシュ済みバイナリもありません"
		fi
	fi
fi

case "${JP_PII_DETECT_PRE_COMMIT_MODE:-staged}" in
	staged) exec "$bin" scan --staged "$@" ;;
	full) exec "$bin" scan --full "$@" ;;
	*) die "invalid internal scan mode" ;;
esac
