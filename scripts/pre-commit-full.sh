#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
JP_PII_DETECT_PRE_COMMIT_MODE=full exec "$script_dir/pre-commit.sh" "$@"
