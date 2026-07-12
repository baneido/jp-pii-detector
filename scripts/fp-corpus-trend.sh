#!/usr/bin/env sh
# fp-corpus-report の匿名集計を直前の永続スナップショットと比較する。
#
# 使い方:
#   fp-corpus-trend.sh <current-summary.json> <previous-summary.json> <threshold-percent>
#
# 閾値超過は観測用の非ゲート警告なので、本スクリプトは warning=true の場合も 0 を返す。
# 入力不正だけをエラーにし、壊れた baseline で誤った比較をしない。
set -eu

die() {
	printf '%s\n' "fp-corpus-trend: $*" >&2
	exit 1
}

command -v jq >/dev/null 2>&1 || die "jq が見つかりません"

if [ "$#" -ne 3 ]; then
	die "usage: fp-corpus-trend.sh <current-summary.json> <previous-summary.json> <threshold-percent>"
fi
current=$1
previous=$2
threshold=$3

[ -f "$current" ] || die "current summary が存在しません: $current"
[ -f "$previous" ] || die "previous summary が存在しません: $previous"

if ! jq -en --arg value "$threshold" '
	$value
	| test("^[0-9]+([.][0-9]+)?$")
	  and ((tonumber >= 0) and (tonumber <= 10000))
' >/dev/null; then
	die "threshold-percent は 0〜10000 の数値で指定してください: $threshold"
fi

validate_summary() {
	jq -e '
		type == "object"
		and (.generated_at | type == "string")
		and (.corpora_count | type == "number" and . >= 1)
		and (.total_mloc | type == "number" and . > 0)
		and (.total_findings | type == "number" and . >= 0 and floor == .)
		and (.findings_per_mloc | type == "number" and . >= 0)
		and (.by_rule | type == "array")
		and all(.by_rule[];
			type == "object"
			and (.rule_id | type == "string" and test("^[a-z0-9][a-z0-9-]*$"))
			and (.count | type == "number" and . >= 0 and floor == .)
			and (.per_mloc | type == "number" and . >= 0)
		)
		and ((.by_rule | map(.rule_id) | unique | length) == (.by_rule | length))
	' "$1" >/dev/null
}

validate_summary "$current" || die "current summary の形式が不正です"
validate_summary "$previous" || die "previous summary の形式が不正です"

jq -n \
	--argjson threshold "$threshold" \
	--slurpfile current "$current" \
	--slurpfile previous "$previous" '
	def change_percent($before; $after):
		if $before == 0 then null else (($after - $before) / $before * 100) end;
	def exceeds($before; $after):
		if $before == 0 then $after > 0
		else change_percent($before; $after) > $threshold
		end;

	($current[0]) as $c
	| ($previous[0]) as $p
	| (
		[($p.by_rule[] | .rule_id), ($c.by_rule[] | .rule_id)]
		| unique
		| map(
			. as $id
			| (($p.by_rule[] | select(.rule_id == $id) | .count) // 0) as $before
			| (($c.by_rule[] | select(.rule_id == $id) | .count) // 0) as $after
			| (($p.by_rule[] | select(.rule_id == $id) | .per_mloc) // 0) as $before_rate
			| (($c.by_rule[] | select(.rule_id == $id) | .per_mloc) // 0) as $after_rate
			| {
				rule_id: $id,
				previous_count: $before,
				current_count: $after,
				previous_per_mloc: $before_rate,
				current_per_mloc: $after_rate,
				change_percent: change_percent($before_rate; $after_rate),
				warning: exceeds($before_rate; $after_rate)
			}
		)
	) as $rules
	| {
		threshold_percent: $threshold,
		previous_generated_at: $p.generated_at,
		current_generated_at: $c.generated_at,
		previous_findings_per_mloc: $p.findings_per_mloc,
		current_findings_per_mloc: $c.findings_per_mloc,
		overall_change_percent: change_percent($p.findings_per_mloc; $c.findings_per_mloc),
		overall_warning: exceeds($p.findings_per_mloc; $c.findings_per_mloc),
		by_rule: $rules,
		warning: (exceeds($p.findings_per_mloc; $c.findings_per_mloc) or any($rules[]; .warning))
	}
'
