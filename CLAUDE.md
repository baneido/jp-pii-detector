# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`jp-pii-detect` is a Japan-specific static PII detector (My Number, phone, address, etc.) — a single Go binary meant to run as a pre-commit hook and in CI (GitHub Actions). The canonical Go module path is `github.com/baneido/jp-pii-detecter` (intentional legacy spelling for repo/module compatibility), while the binary/command name is `jp-pii-detect`.

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

1. **Accuracy must not drift.** `internal/eval` measures precision/recall/F1 against a labeled dataset (`internal/eval/dataset.go`). `eval_test.go` asserts measured F1 equals each rule's `wantF1`, and `readme_test.go` asserts the README badges match. **Any change to rules or the dataset moves these numbers and breaks CI.** When that happens: update `wantF1`, then run `go test ./internal/eval -update` to regenerate the README badges and `docs/accuracy.md`. CI also runs `go test ./internal/eval -run TestGenerateDoc -update && git diff --exit-code docs/accuracy.md`.
2. **Dogfooding.** CI scans this repo with itself and expects zero findings. New test fixtures / sample PII must be excluded (see `.jp-pii.toml` allowlist or `jp-pii-detect:ignore` markers) or they'll fail the build.

## Architecture

Detection pipeline (`source → normalize → detect → report`):

- **`internal/source`** enumerates scan targets: full file-tree walk (parallel) or git-diff added-lines only (`--staged` / `--diff <range>`, via `git diff -U0`). Skips binaries, >5MB files, and dependency dirs like `node_modules`.
- **`internal/normalize`** (`normalize.Line`) folds full-width alphanumerics, hyphen variants, and digit-adjacent long-vowel marks to half-width. **Critical invariant:** conversion is strictly 1:1 per rune, so a match position in the normalized line is the same column in the original — no reverse mapping needed. Preserve this when editing. Pure-ASCII lines take a fast path with **0 allocs/op**, guaranteed by a regression test.
- **`internal/detect`** (`ScanLine` / `ScanContent`) runs each rule per line. A rule's `Prefilter` (digit / `@` / CJK required) skips regex entirely on lines that can't match. Matches are filtered by `Validate` (checksums) and the allowlist. Context keywords on the same line promote confidence to High; `RequireContext` rules are dropped without a keyword (and report at `Base`, never promoted). `resolveOverlaps` collapses overlapping detections (higher confidence, then longer, wins). `ScanContent` additionally re-scans 2-adjacent-line windows for `RequireContext` rules, remapping positions back to original line/column.
- **`internal/report`** emits `text|json|sarif|github`, masking detected values by default (`--unmask` for local only). Exit codes: `0`=none, `1`=found, `2`=error.

Supporting packages: `internal/checksum` (My Number check digit, Luhn, card brand), `internal/dict` (`//go:embed`-ed IANA TLD list and postal-code prefixes; regenerate via `go run ./internal/dict/gen`), `internal/config` (`.jp-pii.toml`, searched upward to the repo root), `internal/rule` (rule type + `Builtin()`).

## Adding / editing detection rules

Rules live in `internal/rule/builtin.go` (`Builtin()`); see `docs/development.md` for the full guide. Key points:

- Guard numeric/alnum entities against partial matches inside longer runs with `dg()` / `ag()`. These put the body in **capture group 1**, which is what `ScanLine` reports — boundary guards stay outside the group.
- Digit-count-only rules are false-positive-prone: set `RequireContext: true` (often with `RequireContextWindow` to require the keyword nearby, and `NegativeContext` for money/count/sequential-ID contexts). Use `Base: High` only when validation alone is precise.
- High-false-positive rules go in `internal/rule/high_recall.go` (`HighRecallRuleIDs()`) and are off unless `--high-recall` / `[rules] high_recall = true`.
- Put checksum logic in `internal/checksum` and small existence dictionaries in `internal/dict` (embedded), each tested independently.
- Add both positive and negative cases to `internal/detect/detect_test.go` (adjacency, context-dependent confidence, "part of a longer digit run is not a match"). Then expect the eval/badge CI gate above to fire.

## Releasing

Distributed via `go install ...@<version>` — tagging is the release. Update version references in `README.md` and `action.yml` (e.g. `rev: v0.1.0`) to match the tag.
