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
	version=$(git -C "$repo_root" describe --tags --exact-match 2>/dev/null || true)
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
bin_name=$(bin_name_for_os "${JP_PII_DETECT_OS:-$(uname -s)}")
bin="${install_dir}/${bin_name}"

if [ "$version" = "latest" ] || [ ! -x "$bin" ]; then
	JP_PII_DETECT_VERSION="$version" "$script_dir/install.sh" --version "$version" --install-dir "$install_dir"
fi

if [ "${1:-}" = "--full" ]; then
	shift
	exec "$bin" scan "$@" .
fi

exec "$bin" scan --staged "$@"
