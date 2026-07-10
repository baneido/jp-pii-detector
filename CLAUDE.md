# CLAUDE.md

This file provides guidance to coding agents (Claude Code, Codex, etc.) when working with code in this repository.

`jp-pii-detect` is a Japan-specific static PII detector (My Number, phone, address, etc.) — a single Go binary meant to run as a pre-commit hook and in CI (GitHub Actions). The canonical Go module path is `github.com/baneido/jp-pii-detector`, while the binary/command name is `jp-pii-detect`.

Source comments and docs are in Japanese; match that when editing them.

## Commands

```console
go test ./...                       # all tests
go test -race ./...                 # required: catches data races in parallel scan (internal/source)
go vet ./...
go build ./cmd/jp-pii-detect
go test -run TestName ./internal/detect   # single test
go test -bench . -benchmem ./internal/normalize/ ./internal/detect/   # hot-path benchmarks
```

Run the built binary against this repo (what CI dogfoods): `./jp-pii-detect scan --format github .`

## CI gates (don't break these)

CI (`.github/workflows/ci.yml`) fails on more than just test failures:

1. **Accuracy must not drift.** `internal/eval` measures precision/recall/F1 against a labeled dataset that lives **outside the repo** (it can contain real-format PII). The `internal/piifixtures` loader reads the dataset and other PII test fixtures from the local JSON path in `$JP_PII_FIXTURES` (fetched from GCS via GitHub OIDC → Workload Identity in CI; see `docs/development.md`). `eval_test.go` asserts measured F1 equals each rule's `wantF1`, and `readme_test.go` asserts the README badges match. **Any change to rules or the dataset moves these numbers and breaks CI.** When that happens: update `wantF1`, then run `JP_PII_FIXTURES=<path> go test ./internal/eval -update` to regenerate the README badges and `docs/accuracy.md`. CI also runs `JP_PII_FIXTURES=<path> go test ./internal/eval -run TestGenerateDoc -update && git diff --exit-code docs/accuracy.md`. Without `$JP_PII_FIXTURES`, the eval/badge/accuracy tests (and all PII-fixture unit tests) `t.Skip`, so `go test ./...` stays green offline.
2. **Dogfooding.** CI scans this repo with itself and expects zero findings. New test fixtures / sample PII must be excluded (see `.jp-pii.toml` allowlist or `jp-pii-detect:ignore` markers) or they'll fail the build.

## Architecture

Detection pipeline (`source → normalize → detect → report`):

- **`internal/source`** enumerates scan targets: full file-tree walk (parallel) or git-diff (`--staged` / `--diff <range>`). The diff is fetched with `git diff -U3` so each hunk carries surrounding context lines; `scanHunk` → `detect.ScanDiffHunk` scans the hunk so a label on a **logically adjacent** unchanged line can promote a value on an added line, but **only reports findings whose detected value lands on an added line**. Context (unchanged) lines supply positive context *only* — they never drive suppression, so a stale `jp-pii-detector:ignore` or a negative-context unit (`円` etc.) on a context line does not silence a newly-added secret. Skips binaries, >5MB files, and dependency dirs like `node_modules`.
- **`internal/normalize`** (`normalize.Line`) folds full-width alphanumerics, hyphen variants, and digit-adjacent long-vowel marks to half-width. **Critical invariant:** conversion is strictly 1:1 per rune, so a match position in the normalized line is the same column in the original — no reverse mapping needed. Preserve this when editing. Pure-ASCII lines take a fast path with **0 allocs/op**, guaranteed by a regression test.
- **`internal/detect`** (`ScanLine` / `ScanContent`) runs each rule per line. A rule's `Prefilter` (digit / `@` / CJK required) skips regex entirely on lines that can't match. Matches are filtered by `Validate` (checksums) and the allowlist. Context keywords on the same line promote confidence to High; `RequireContext` rules are dropped without a keyword (and report at `Base`, never promoted). `resolveOverlaps` collapses overlapping detections (higher confidence, then longer, wins). `ScanContent`/`ScanDiffHunk` additionally re-scan **logically adjacent** line pairs — line `i` paired with the next non-blank line `j` (blank-only lines in between are skipped, capped at `j-i<=3`, i.e. up to 2 blank lines) — remapping positions back to original line/column. Both `RequireContext` and non-`RequireContext` rules can be promoted this way; non-`RequireContext` promotion is limited to a label within 40 runes of the value (`ContextPromoted` in `Reason`) to avoid promoting from a distant, unrelated label. Ignore-marker suppression is judged per value-bearing line, not the combined pair, so a marker on the label-only line never silences the value line. `dedupAndSortFindings` keeps the higher-confidence candidate when the same span is found both standalone and via adjacent-line promotion.
- **`internal/report`** emits `text|json|sarif|github`, masking detected values by default (`--unmask` for local only). Exit codes: `0`=none, `1`=found, `2`=error.

Supporting packages: `internal/checksum` (My Number check digit, Luhn, card brand), `internal/dict` (`//go:embed`-ed IANA TLD list and Japan-Post postal codes; regenerate via `go run ./internal/dict/gen`), `internal/config` (`.jp-pii.toml`, searched upward to the repo root), `internal/rule` (rule type + `Builtin()`).

Postal codes use **7-digit exact matching** against a committed bitset (`postal_codes.bitset`, a 10,000,000-bit / 1.25 MB `//go:embed` holding every real Japan-Post 7-digit code, merged from the address CSV (KEN_ALL) and the individual-business postal code data (jigyosyo)). `dict.ValidPostalCode` indexes that bitset directly, so `150-9999` (prefix `150` is real, but the full code is unassigned) is rejected. `internal/dict/gen` builds the bitset from the official Japan-Post UTF-8 KEN_ALL CSV/zip (`-ken-all-input`) and/or the Shift_JIS jigyosyo CSV/zip (`-jigyosyo-input`, decoded via `golang.org/x/text/encoding/japanese`) — either or both may be given, and codes are merged with duplicates deduped; the index encoding and size constant are shared with `internal/dict` so the two can't drift. Refresh it (monthly automation: `.github/workflows/postal-update.yml`, or by hand) with:

```console
go run ./internal/dict/gen -ken-all-input utf_ken_all.zip -jigyosyo-input jigyosyo.zip -output internal/dict/postal_codes.bitset
```

A bitset refresh that adds/removes codes can move the `jp-postal-code` accuracy numbers, so re-run the eval/badge regeneration (see CI gates below) after committing a new bitset.

## Adding / editing detection rules

Rules live in `internal/rule/builtin.go` (`Builtin()`); see `docs/development.md` for the full guide. Key points:

- Guard numeric/alnum entities against partial matches inside longer runs with `dg()` / `ag()`. These put the body in **capture group 1**, which is what `ScanLine` reports — boundary guards stay outside the group.
- Digit-count-only rules are false-positive-prone: set `RequireContext: true` (often with `RequireContextWindow` to require the keyword nearby, and `NegativeContext` for money/count/sequential-ID contexts). Use `Base: High` only when validation alone is precise.
- High-false-positive rules go in `internal/rule/high_recall.go` (`HighRecallRuleIDs()`) and are off unless `--high-recall` / `[rules] high_recall = true`.
- Put checksum logic in `internal/checksum` and small existence dictionaries in `internal/dict` (embedded), each tested independently.
- Add both positive and negative cases to `internal/detect/detect_test.go` (adjacency, context-dependent confidence, "part of a longer digit run is not a match"). Then expect the eval/badge CI gate above to fire.

## Releasing

Tagging `v*` triggers `.github/workflows/release.yml`, which cross-compiles prebuilt binaries for linux/darwin/windows on amd64/arm64 and uploads `jp-pii-detect_<goos>_<goarch>.tar.gz` assets plus `checksums.txt` to the GitHub Release. GitHub Action and pre-commit users download these assets, so they do not need Go installed. `go install ...@<version>` remains available for developer machines with Go. Update version references in `README.md` and `action.yml` (e.g. `rev: v0.1.0`) to match the tag.
