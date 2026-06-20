# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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

- **`internal/source`** enumerates scan targets: full file-tree walk (parallel) or git-diff (`--staged` / `--diff <range>`). The diff is fetched with `git diff -U3` so each hunk carries surrounding context lines; `scanHunk` scans the whole hunk (so a label on an unchanged line can promote a value added below it) but **only reports findings whose detected value lands on an added line** — pre-existing PII on context lines is not reported. Skips binaries, >5MB files, and dependency dirs like `node_modules`.
- **`internal/normalize`** (`normalize.Line`) folds full-width alphanumerics, hyphen variants, and digit-adjacent long-vowel marks to half-width. **Critical invariant:** conversion is strictly 1:1 per rune, so a match position in the normalized line is the same column in the original — no reverse mapping needed. Preserve this when editing. Pure-ASCII lines take a fast path with **0 allocs/op**, guaranteed by a regression test.
- **`internal/detect`** (`ScanLine` / `ScanContent`) runs each rule per line. A rule's `Prefilter` (digit / `@` / CJK required) skips regex entirely on lines that can't match. Matches are filtered by `Validate` (checksums) and the allowlist. Context keywords on the same line promote confidence to High; `RequireContext` rules are dropped without a keyword (and report at `Base`, never promoted). `resolveOverlaps` collapses overlapping detections (higher confidence, then longer, wins). `ScanContent` additionally re-scans 2-adjacent-line windows for `RequireContext` rules, remapping positions back to original line/column.
- **`internal/report`** emits `text|json|sarif|github`, masking detected values by default (`--unmask` for local only). Exit codes: `0`=none, `1`=found, `2`=error.

Supporting packages: `internal/checksum` (My Number check digit, Luhn, card brand), `internal/dict` (`//go:embed`-ed IANA TLD list and Japan-Post postal codes; regenerate via `go run ./internal/dict/gen`), `internal/config` (`.jp-pii.toml`, searched upward to the repo root), `internal/rule` (rule type + `Builtin()`).

Postal codes use a 7-digit **exact-match bitset** (`postal_codes.bitset`, a 10,000,000-bit / 1.25 MB `//go:embed`). `internal/dict/gen` builds it from the official Japan-Post UTF-8 KEN_ALL CSV/zip. The committed `postal_codes.bitset` is a tiny **placeholder** — until a real bitset is generated, `dict.ValidPostalCode` falls back to the 3-digit prefix set (`postal_prefixes.txt`). To enable exact matching, download `utf_ken_all.zip` from <https://www.post.japanpost.jp/zipcode/dl/utf-zip.html> and run:

```console
go run ./internal/dict/gen -input utf_ken_all.zip -output internal/dict/postal_codes.bitset -prefixes internal/dict/postal_prefixes.txt
```

Switching from prefix to exact validation moves the `jp-postal-code` accuracy numbers, so re-run the eval/badge regeneration (see CI gates below) after committing a real bitset.

## Adding / editing detection rules

Rules live in `internal/rule/builtin.go` (`Builtin()`); see `docs/development.md` for the full guide. Key points:

- Guard numeric/alnum entities against partial matches inside longer runs with `dg()` / `ag()`. These put the body in **capture group 1**, which is what `ScanLine` reports — boundary guards stay outside the group.
- Digit-count-only rules are false-positive-prone: set `RequireContext: true` (often with `RequireContextWindow` to require the keyword nearby, and `NegativeContext` for money/count/sequential-ID contexts). Use `Base: High` only when validation alone is precise.
- High-false-positive rules go in `internal/rule/high_recall.go` (`HighRecallRuleIDs()`) and are off unless `--high-recall` / `[rules] high_recall = true`.
- Put checksum logic in `internal/checksum` and small existence dictionaries in `internal/dict` (embedded), each tested independently.
- Add both positive and negative cases to `internal/detect/detect_test.go` (adjacency, context-dependent confidence, "part of a longer digit run is not a match"). Then expect the eval/badge CI gate above to fire.

## Releasing

Tagging `v*` triggers `.github/workflows/release.yml`, which cross-compiles prebuilt binaries for linux/darwin/windows on amd64/arm64 and uploads `jp-pii-detect_<goos>_<goarch>.tar.gz` assets plus `checksums.txt` to the GitHub Release. GitHub Action and pre-commit users download these assets, so they do not need Go installed. `go install ...@<version>` remains available for developer machines with Go. Update version references in `README.md` and `action.yml` (e.g. `rev: v0.1.0`) to match the tag.
