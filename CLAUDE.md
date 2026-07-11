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

1. **Accuracy must not drift.** `internal/eval` measures precision/recall/F1 against a labeled private corpus that lives outside the repo. `internal/privatecorpus` loads it from `$JP_PII_FIXTURES`; `internal/evalcase` owns the neutral schema, and ordinary tests use `internal/testfixtures` instead. `docs/accuracy.json` includes the opaque `dataset_id` and is the single source of truth for the `low`/badge profile. Run `go run ./cmd/pii-fixture eval` for an ephemeral authenticated local evaluation, or set `$JP_PII_FIXTURES` explicitly. Synthetic `fixturegen` cases are contract tests and must never be merged into the private corpus F1 denominator. Without the corpus only private accuracy/badge/dataset-quality tests skip; public unit/integration coverage must still run.
2. **Dogfooding.** CI scans this repo with itself and expects zero findings. New test fixtures / sample PII must be excluded (see `.jp-pii.toml` allowlist or `jp-pii-detect:ignore` markers) or they'll fail the build.

## Architecture

Detection pipeline (`source → normalize → detect → report`):

- **`internal/source`** enumerates scan targets: full file-tree walk (parallel) or git-diff (`--staged` / `--diff <range>`). The diff is fetched with `git diff -U3` so each hunk carries surrounding context lines; `scanHunk` → `detect.ScanDiffHunk` scans the hunk so a label on a **logically adjacent** unchanged line can promote a value on an added line, but **only reports findings whose detected value lands on an added line**. Context (unchanged) lines supply positive context *only* — they never drive suppression, so a stale `jp-pii-detector:ignore` or a negative-context unit (`円` etc.) on a context line does not silence a newly-added secret. Skips binaries, >5MB files, and dependency dirs like `node_modules`. Before the binary check, `decodeUTF16` looks for a UTF-16 BOM (`FF FE`/`FE FF`) and transcodes to UTF-8 (stdlib `unicode/utf16`, no new dependency); odd byte length or invalid surrogates fall back to the normal binary check. Full-scan only — `git diff` treats UTF-16 files as binary, so they're never in scope for `--staged`/`--diff`. Decoded positions are rune-accurate for `ScanContent` but don't map back to the original file's byte offsets.
- **`internal/normalize`** (`normalize.Line`) folds full-width alphanumerics, hyphen variants, and digit-adjacent long-vowel marks to half-width. **Critical invariant:** conversion is strictly 1:1 per rune, so a match position in the normalized line is the same column in the original — no reverse mapping needed. Preserve this when editing. Pure-ASCII lines take a fast path with **0 allocs/op**, guaranteed by a regression test.
- **`internal/detect`** (`ScanLine` / `ScanContent`) runs each rule per line. A rule's `Prefilter` (digit / `@` / CJK required) skips regex entirely on lines that can't match. Matches are filtered by `Validate` (checksums) and the allowlist. Context keywords on the same line promote confidence to High; `RequireContext` rules are dropped without a keyword (and report at `Base`, never promoted). `resolveOverlaps` collapses overlapping detections (higher confidence, then longer, wins). `ScanContent`/`ScanDiffHunk` additionally re-scan **logically adjacent** line pairs — line `i` paired with the next non-blank line `j` (blank-only lines in between are skipped, capped at `j-i<=3`, i.e. up to 2 blank lines) — remapping positions back to original line/column. Both `RequireContext` and non-`RequireContext` rules can be promoted this way; non-`RequireContext` promotion is limited to a label within 40 runes of the value (`ContextPromoted` in `Reason`) to avoid promoting from a distant, unrelated label. Ignore-marker suppression is judged per value-bearing line, not the combined pair, so a marker on the label-only line never silences the value line. `dedupAndSortFindings` keeps the higher-confidence candidate when the same span is found both standalone and via adjacent-line promotion. `.csv`/`.tsv` files (full scan only, `internal/detect/csv_context.go`) additionally get a dedicated column-context mechanism: the header row (RFC 4180 quoting, `""`-escaped) supplies each column's label, and that label becomes `PositiveText`/`NegativeText` context for the *same column* in every data row — fixing the adjacent-line window's blind spot where only the row right under the header benefited. A first row that isn't header-shaped (fewer than 2 fields, an empty field, or a numeric-majority field) disables column context entirely for that file (safe default). A record whose quotes don't close by end-of-line (an embedded newline this line-based parser can't see) stops column-context assignment for the rest of the file, since column alignment can't be trusted afterward. High-recall mode additionally checks columns whose header matches the person-name label vocabulary (`rule.CSVNameHeaderRe`) against `rule.ValidCrossLineName` per field (`rule.CSVNameValueRe`); since the name dictionary gained katakana readings (kana/romaji name support), katakana furigana columns are now in scope too.
- **`internal/report`** emits `text|json|sarif|github`, masking detected values by default (`--unmask` for local only). Exit codes: `0`=none, `1`=found, `2`=error.

Supporting packages: `internal/checksum` (My Number check digit, Luhn, card brand), `internal/dict` (`//go:embed`-ed IANA TLD list, Japan-Post postal codes, and municipality names; regenerate via `go run ./internal/dict/gen`), `internal/config` (`.jp-pii.toml`, searched upward to the repo root), `internal/rule` (rule type + `Builtin()`).

Postal codes use **7-digit exact matching** against a committed bitset (`postal_codes.bitset`, a 10,000,000-bit / 1.25 MB `//go:embed` holding every real Japan-Post 7-digit code, merged from the address CSV (KEN_ALL) and the individual-business postal code data (jigyosyo)). `dict.ValidPostalCode` indexes that bitset directly, so `150-9999` (prefix `150` is real, but the full code is unassigned) is rejected. `internal/dict/gen` builds the bitset from the official Japan-Post UTF-8 KEN_ALL CSV/zip (`-ken-all-input`) and/or the Shift_JIS jigyosyo CSV/zip (`-jigyosyo-input`, decoded via `golang.org/x/text/encoding/japanese`) — either or both may be given, and codes are merged with duplicates deduped; the index encoding and size constant are shared with `internal/dict` so the two can't drift. It also builds `municipalities.txt` (see below) from the KEN_ALL input via `-municipalities-output`. Refresh it (monthly automation: `.github/workflows/postal-update.yml`, or by hand) with:

```console
go run ./internal/dict/gen -ken-all-input utf_ken_all.zip -jigyosyo-input jigyosyo.zip -output internal/dict/postal_codes.bitset -municipalities-output internal/dict/municipalities.txt
```

A bitset refresh that adds/removes codes can move the `jp-postal-code` accuracy numbers, so re-run the eval/badge regeneration (see CI gates below) after committing a new bitset.

`municipalities.txt` (one real 市区町村 name per line, `//go:embed`-ed as `dict.MunicipalitySuffixMatch`) is generated from the same KEN_ALL rows' prefecture/municipality fields: county-attached entries (`石狩郡当別町`) also get the county-omitted abbreviation (`当別町`), and ordinance-designated cities' wards (`札幌市中央区`) also get the city-alone form (`札幌市`); `ヶ`/`ケ` variants are normalized to `ケ` on both the generation and lookup sides. It's wired into `jp-address-high-recall`'s `Validate` only (not the default `jp-address`) — see `internal/rule/builtin.go`.

## Adding / editing detection rules

Rules live in `internal/rule/builtin.go` (`Builtin()`); see `docs/development.md` for the full guide. Key points:

- Guard numeric/alnum entities against partial matches inside longer runs with `dg()` / `ag()`. These put the body in **capture group 1**, which is what `ScanLine` reports — boundary guards stay outside the group.
- Digit-count-only rules are false-positive-prone: set `RequireContext: true` (often with `RequireContextWindow` to require the keyword nearby, and `NegativeContext` for money/count/sequential-ID contexts). Use `Base: High` only when validation alone is precise.
- High-false-positive rules go in `internal/rule/high_recall.go` (`HighRecallRuleIDs()`) and are off unless `--high-recall` / `[rules] high_recall = true`.
- Put checksum logic in `internal/checksum` and small existence dictionaries in `internal/dict` (embedded), each tested independently.
- Add both positive and negative cases to `internal/detect/detect_test.go` (adjacency, context-dependent confidence, "part of a longer digit run is not a match"). Then expect the eval/badge CI gate above to fire.

## Releasing

Tagging `v*` triggers `.github/workflows/release.yml`, which cross-compiles prebuilt binaries for linux/darwin/windows on amd64/arm64 and uploads `jp-pii-detect_<goos>_<goarch>.tar.gz` assets plus `checksums.txt` to the GitHub Release. GitHub Action and pre-commit users download these assets, so they do not need Go installed. `go install ...@<version>` remains available for developer machines with Go. The `docker` job then builds the `Dockerfile` and pushes a multi-arch (linux/amd64+arm64) image to `ghcr.io/baneido/jp-pii-detector` tagged `<tag>` and `latest` (used as a CI job image by GitLab CI etc.; recipes in `docs/integrations.md`); ci.yml smoke-tests the same Dockerfile. The `release` job also force-moves the moving major tag (e.g. `v0`) to the new release tag. Version references in the docs are updated automatically: the `docs` job opens a PR that rewrites the version strings in `README.md`, `README.en.md`, `docs/integrations.md`, and `docs/comparison.md` plus the `docsVersion` constant in `scripts/distribution_test.go` to the new tag — just merge that PR. The rewrite only touches lines that carry a project marker (`jp-pii-detector`, `jp-pii-detect`, `JP_PII_DETECT_VERSION`, `ghcr.io/baneido`) on the same or previous two lines, so third-party versions like gitleaks' `rev:` are left alone; keep the marker list in the `docs` job and in `TestDocsVersionReferencesMatchDocsVersion` in sync. That same test guards against version-string drift in CI when the docs are edited by hand. The docs auto-PR needs the repository setting "Allow GitHub Actions to create and approve pull requests" enabled.
