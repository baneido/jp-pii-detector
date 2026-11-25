#!/usr/bin/env sh
set -eu

die() {
	printf '%s\n' "jp-pii-detect install: $*" >&2
	exit 1
}

usage() {
	cat <<'USAGE'
Usage: scripts/install.sh [--version <version>] [--install-dir <dir>] [--repo <owner/repo>] [--no-model] [--print-url]

Downloads a prebuilt jp-pii-detect binary from GitHub Releases.

By default it installs the Sumi model bundle (rules + local model,
jp-pii-detect-sumi_<os>_<arch>.tar.gz) into <install-dir>/jp-pii-detect-sumi/
and links <install-dir>/jp-pii-detect to it. Platforms without a bundle
(darwin/amd64, windows) and releases that lack one get the rules-only
binary, with a warning. --no-model (or JP_PII_DETECT_MODEL=false) always
installs the rules-only binary.

Environment:
  JP_PII_DETECT_VERSION           Release tag to install (default: latest)
  JP_PII_DETECT_INSTALL_DIR       Destination directory (default: $HOME/.local/bin)
  JP_PII_DETECT_REPO              GitHub repo (default: baneido/jp-pii-detector)
  JP_PII_DETECT_RELEASE_BASE_URL  Override release base URL for tests/mirrors
  JP_PII_DETECT_OS                Override detected GOOS (linux/darwin/windows)
  JP_PII_DETECT_ARCH              Override detected GOARCH (amd64/arm64)
  JP_PII_DETECT_MODEL             false/0/no/off installs the rules-only binary (default: true)
USAGE
}

normalize_os() {
	case "$1" in
		linux | Linux) printf 'linux' ;;
		darwin | Darwin) printf 'darwin' ;;
		windows | Windows_NT | MINGW* | MSYS* | CYGWIN*) printf 'windows' ;;
		*) die "unsupported OS: $1" ;;
	esac
}

normalize_arch() {
	case "$1" in
		amd64 | x86_64) printf 'amd64' ;;
		arm64 | aarch64) printf 'arm64' ;;
		*) die "unsupported architecture: $1" ;;
	esac
}

download() {
	url=$1
	output=$2
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$url" -o "$output"
	elif command -v wget >/dev/null 2>&1; then
		wget -q "$url" -O "$output"
	else
		die "curl or wget is required to download release assets"
	fi
}

sha256_file() {
	path=$1
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$path" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$path" | awk '{print $1}'
	else
		die "sha256sum or shasum is required to verify release assets"
	fi
}

verify_checksum() {
	archive=$1
	checksums=$2
	asset=$3
	want=$(awk -v asset="$asset" '$2 == asset {print $1}' "$checksums")
	[ -n "$want" ] || die "$(basename "$checksums") does not contain ${asset}"
	got=$(sha256_file "$archive")
	if [ "$got" != "$want" ]; then
		die "checksum verification failed for ${asset}"
	fi
}

repo=${JP_PII_DETECT_REPO:-baneido/jp-pii-detector}
version=${JP_PII_DETECT_VERSION:-latest}
install_dir=${JP_PII_DETECT_INSTALL_DIR:-}
print_url=0
case "${JP_PII_DETECT_MODEL:-true}" in
	0 | false | False | FALSE | no | off) model=0 ;;
	*) model=1 ;;
esac

while [ "$#" -gt 0 ]; do
	case "$1" in
		--version)
			[ "$#" -ge 2 ] || die "--version requires a value"
			version=$2
			shift 2
			;;
		--install-dir)
			[ "$#" -ge 2 ] || die "--install-dir requires a value"
			install_dir=$2
			shift 2
			;;
		--repo)
			[ "$#" -ge 2 ] || die "--repo requires a value"
			repo=$2
			shift 2
			;;
		--no-model)
			model=0
			shift
			;;
		--print-url)
			print_url=1
			shift
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			die "unknown argument: $1"
			;;
	esac
done

if [ -z "$install_dir" ]; then
	install_dir="${HOME:-.}/.local/bin"
fi

goos=$(normalize_os "${JP_PII_DETECT_OS:-$(uname -s)}")
goarch=$(normalize_arch "${JP_PII_DETECT_ARCH:-$(uname -m)}")
warn() {
	printf '%s\n' "jp-pii-detect install: warning: $*" >&2
}

# release_url <ファイル名>: 指定バージョンのリリースアセットの URL。
release_url() {
	if [ -n "${JP_PII_DETECT_RELEASE_BASE_URL:-}" ]; then
		printf '%s/%s/%s' "${JP_PII_DETECT_RELEASE_BASE_URL%/}" "$version" "$1"
	elif [ "$version" = "latest" ]; then
		printf 'https://github.com/%s/releases/latest/download/%s' "$repo" "$1"
	else
		printf 'https://github.com/%s/releases/download/%s/%s' "$repo" "$version" "$1"
	fi
}

# モデル同梱版を配っているのは release-model.yml がビルドする組み合わせだけ。
# windows/amd64 は試験的で公開されないことがあり、action.yml は .exe を直接
# 実行するので、シンボリックリンクを使う同梱版の配置に合わない。
if [ "$model" -eq 1 ]; then
	case "${goos}/${goarch}" in
		linux/amd64 | linux/arm64 | darwin/arm64) ;;
		*)
			warn "${goos}/${goarch} 向けのモデル同梱版はないため、組み込みルールだけの軽量版を入れます（モデルによる検出は行いません）"
			model=0
			;;
	esac
fi

asset="jp-pii-detect_${goos}_${goarch}.tar.gz"
bundle="jp-pii-detect-sumi_${goos}_${goarch}"

if [ "$print_url" -eq 1 ]; then
	if [ "$model" -eq 1 ]; then
		release_url "${bundle}.tar.gz"
	else
		release_url "$asset"
	fi
	printf '\n'
	exit 0
fi

bin_name=jp-pii-detect
if [ "$goos" = "windows" ]; then
	bin_name=jp-pii-detect.exe
fi

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/jp-pii-detect.XXXXXX")
cleanup() {
	rm -rf "$tmpdir"
}
trap cleanup EXIT HUP INT TERM

dest="${install_dir}/${bin_name}"
dest_tmp="${dest}.tmp.$$"
bundle_dest="${install_dir}/jp-pii-detect-sumi"

# 取得に失敗して軽量版にしたときの印。pre-commit.sh はこれがあれば次回も入れ直す
# （一時的な失敗で、同じバージョンのモデルなしの走査がずっと続かないように）。
fallback_mark="${install_dir}/.jp-pii-detect-model-fallback"
fell_back=0

if [ "$model" -eq 1 ]; then
	archive="${tmpdir}/${bundle}.tar.gz"
	checksums="${tmpdir}/checksums-model.txt"
	sha_file="${bundle_dest}/.archive-sha256"
	# 同梱版を添付していないリリース（v0.9.3、v0.9.4 など）は軽量版に切り替える。
	# チェックサムの不一致は改ざんの疑いがあるので、切り替えずに失敗させる。
	if download "$(release_url checksums-model.txt)" "$checksums"; then
		want=$(awk -v asset="${bundle}.tar.gz" '$2 == asset {print $1}' "$checksums")
		# 入れてある同梱版と同じなら、約 100MB のアーカイブを取り直さない
		# （pre-commit.sh は latest のとき毎回この処理を呼ぶ）。
		if [ -n "$want" ] && [ -L "$dest" ] && [ -x "${bundle_dest}/${bin_name}" ] &&
			[ "$(cat "$sha_file" 2>/dev/null)" = "$want" ]; then
			rm -f "$fallback_mark"
			printf 'Up to date %s (rules + Sumi model)\n' "$dest"
			exit 0
		fi
		if [ -n "$want" ] && download "$(release_url "${bundle}.tar.gz")" "$archive"; then
			verify_checksum "$archive" "$checksums" "${bundle}.tar.gz"
			tar -xzf "$archive" -C "$tmpdir"
			[ -f "${tmpdir}/${bundle}/${bin_name}" ] || die "archive did not contain ${bundle}/${bin_name}"
			printf '%s\n' "$want" >"${tmpdir}/${bundle}/.archive-sha256"
			mkdir -p "$install_dir"
			# 実行ファイルは隣の model/ と lib/ を使うので、ディレクトリごと置いて
			# リンクを張る（リンク先の実体の場所を基準に探す。docs/model-bundle.md）。
			rm -rf "${bundle_dest}.tmp.$$"
			mv "${tmpdir}/${bundle}" "${bundle_dest}.tmp.$$"
			rm -rf "$bundle_dest"
			mv "${bundle_dest}.tmp.$$" "$bundle_dest"
			rm -f "$dest_tmp"
			ln -s "jp-pii-detect-sumi/${bin_name}" "$dest_tmp"
			mv -f "$dest_tmp" "$dest"
			rm -f "$fallback_mark"
			printf 'Installed %s (rules + Sumi model)\n' "$dest"
			exit 0
		fi
	fi
	warn "${version} のモデル同梱版（${bundle}.tar.gz）を取得できないため、組み込みルールだけの軽量版を入れます（モデルによる検出は行いません）"
	fell_back=1
fi

archive="${tmpdir}/${asset}"
checksums="${tmpdir}/checksums.txt"
download "$(release_url "$asset")" "$archive"
download "$(release_url checksums.txt)" "$checksums"
verify_checksum "$archive" "$checksums" "$asset"
tar -xzf "$archive" -C "$tmpdir"

src="${tmpdir}/${bin_name}"
if [ ! -f "$src" ]; then
	src=$(find "$tmpdir" -type f -name "$bin_name" -print | head -n 1)
fi
[ -n "$src" ] && [ -f "$src" ] || die "archive did not contain ${bin_name}"

mkdir -p "$install_dir"
rm -f "$dest_tmp"
cp "$src" "$dest_tmp"
chmod 0755 "$dest_tmp"
mv -f "$dest_tmp" "$dest"
# 以前に入れた同梱版が残っていれば消す（展開後で約 177MB）。
rm -rf "$bundle_dest"
if [ "$fell_back" -eq 1 ]; then
	: >"$fallback_mark"
else
	rm -f "$fallback_mark"
fi
printf 'Installed %s\n' "$dest"
