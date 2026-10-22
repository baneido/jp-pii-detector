#!/usr/bin/env sh
# scripts/fp-corpus-report.sh
#
# 大規模公開 OSS コーパス 1 件分の偽陽性率（findings/MLoC）を集計する。
# 自リポジトリの dogfooding（既定で 0 件期待）だけでは陰性母数が小さすぎて
# 偽陽性率の実証にならないため、第三者に長期間精査されている著名 OSS を対象に
# .github/workflows/fp-corpus-report.yml から呼び出す想定（詳細は同ファイル参照）。
#
# 使い方:
#   fp-corpus-report.sh <corpus-name> <corpus-dir> <findings-json>
#
# <findings-json> は `jp-pii-detect scan --format json --exit-zero <corpus-dir>` の
# 出力（internal/report.JSON の {"findings": [...], "count": N} 形式。値は既定でマスク
# 済み）をファイルに保存したものを渡す。本スクリプトは rule_id と件数だけを集計し、
# マスク済みの match 値すら出力に含めない（生値はもちろん、マスク値も外部に残さない）。
#
# MLoC（Million Lines of Code）は scanner が走査対象にするファイルの物理行数を
# 1,000,000 で割った値。専用の loc 計測ツールは使わず、単純な物理行数で十分とする
# （対応方針 (1) 参照）。
#
# 出力: 集計結果の JSON を標準出力へ。
set -eu

die() {
	printf '%s\n' "fp-corpus-report: $*" >&2
	exit 1
}

command -v jq >/dev/null 2>&1 || die "jq が見つかりません"

if [ "$#" -ne 3 ]; then
	die "usage: fp-corpus-report.sh <corpus-name> <corpus-dir> <findings-json>"
fi
corpus=$1
dir=$2
findings_json=$3

[ -n "$corpus" ] || die "corpus-name が空です"
[ -d "$dir" ] || die "ディレクトリが存在しません: $dir"
[ -f "$findings_json" ] || die "findings JSON が存在しません: $findings_json"

scanner_physical_lines() {
	# internal/source/files.go の skipDirs / MaxFileSize / isBinary に合わせる。
	find "$1" \
		\( -type d \( \
			-name '.git' -o \
			-name 'node_modules' -o \
			-name 'vendor' -o \
			-name '.venv' -o \
			-name 'venv' -o \
			-name '__pycache__' -o \
			-name 'dist' -o \
			-name 'build' -o \
			-name '.next' -o \
			-name 'target' \
		\) -prune \) -o \
		\( -type f -size -5242881c -exec sh -c '
			for path do
				bytes=$(dd if="$path" bs=8192 count=1 2>/dev/null | wc -c | tr -d " ")
				non_nul_bytes=$(dd if="$path" bs=8192 count=1 2>/dev/null | LC_ALL=C tr -d "\000" | wc -c | tr -d " ")
				if [ "$bytes" = "$non_nul_bytes" ]; then
					wc -l < "$path"
				fi
			done
		' sh {} + \) |
		awk '{ sum += $1 } END { print sum + 0 }'
}

lines=$(scanner_physical_lines "$dir")

# OSS の著作者メタデータ（LICENSE・AUTHORS・著作権表記・Signed-off-by 等）に含まれる
# 氏名・メールアドレスは、本人が公開を前提に記載した実在の個人情報である。検出器と
# しては検出するのが正しい（ルールは変えない）が、偽陽性ではないので「attribution」と
# して別に数え、偽陽性率（fp_total / fp_per_mloc）からは除く
# （docs/development.md「著作者メタデータの扱い」参照）。
#
# 判定はパス（ファイル名）と該当行の内容だけで行い、結果には件数しか残さない。
# finding ごとに "rule_id<TAB>attribution(0|1)" を出力する。
classify_attribution() {
	jq -r '(.findings // [])[] | [.rule_id, .file, (.line | tostring)] | @tsv' "$1" |
		FP_CORPUS_BASE=$2 LC_ALL=C awk -F '\t' '
		# base は -v ではなく環境変数で渡す（-v はバックスラッシュをエスケープとして
		# 解釈するため、Windows のパス C:\Users\... が壊れて警告が出る）。
		BEGIN { base = ENVIRON["FP_CORPUS_BASE"] }
		function load(path,    l, n, p) {
			delete buf
			n = 0
			p = path
			if ((getline l < p) < 0) {
				p = base "/" path
				if ((getline l < p) < 0) {
					cached = path
					return
				}
			}
			buf[++n] = l
			while ((getline l < p) > 0) buf[++n] = l
			close(p)
			cached = path
		}
		{
			rule = $1; path = $2; ln = $3 + 0
			name = path
			sub(/.*\//, "", name)
			name = tolower(name)
			attr = 0
			if (name ~ /^(licen[cs]e|copying|authors|contributors|credits|maintainers|codeowners|owners|notice|thanks|patents|\.mailmap|changelog|changes|history|news|release[-_]?notes)/) {
				attr = 1
			} else {
				if (path != cached) load(path)
				text = tolower(buf[ln])
				if (text ~ /copyright|\(c\)|\xc2\xa9|author|signed-off-by|co-authored-by|maintainer|reported-by|reviewed-by|acked-by|tested-by|suggested-by|contributed by|thanks to|written by|<[^<>@ \t]+@[^<> \t]+>/) attr = 1
			}
			print rule "\t" attr
		}'
}

classified=$(classify_attribution "$findings_json" "$dir")

jq -n \
	--arg corpus "$corpus" \
	--argjson lines "$lines" \
	--arg classified "$classified" \
	'
	($lines / 1000000.0) as $mloc
	| ($classified | split("\n") | map(select(length > 0) | split("\t") | {rule_id: .[0], attribution: (.[1] == "1")})) as $findings
	| ($findings | length) as $total
	| ($findings | map(select(.attribution)) | length) as $attr
	| ($total - $attr) as $fp
	| {
		corpus: $corpus,
		physical_lines: $lines,
		mloc: $mloc,
		findings_total: $total,
		findings_per_mloc: (if $mloc > 0 then ($total / $mloc) else null end),
		attribution_total: $attr,
		fp_total: $fp,
		fp_per_mloc: (if $mloc > 0 then ($fp / $mloc) else null end),
		by_rule: (
			$findings
			| group_by(.rule_id)
			| map(
				(map(select(.attribution)) | length) as $a
				| {
					rule_id: .[0].rule_id,
					count: length,
					per_mloc: (if $mloc > 0 then (length / $mloc) else null end),
					attribution: $a,
					fp: (length - $a),
					fp_per_mloc: (if $mloc > 0 then ((length - $a) / $mloc) else null end)
				})
			| sort_by(-.count)
		)
	}
	'
