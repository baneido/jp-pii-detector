# jp-pii-detector

English | [日本語](README.md)

![PII detection F1](https://img.shields.io/badge/PII%20detection%20F1%20(eval%20dataset)-0.96-brightgreen)

A Japan-specific **static PII detector**. It finds Japanese personal data — My Number,
Japanese phone numbers, addresses, names, and more — that has leaked into a repository,
at commit time (git hook) and in CI/CD (GitHub Actions).

- Single Go binary. **Go is not required on the user side** — pre-built binaries are shipped for each release.
- Detected values are **masked by default** to prevent secondary leaks.

## What it is

`jp-pii-detect` is a static analyzer: it scans text (source, config, docs, data files) using
pattern matching, checksum validation, Japanese-specific normalization, and context keywords —
no runtime data, no external API, no ML dependency. It runs as a pre-commit hook and in CI.

## Why not just gitleaks?

Secret scanners like **gitleaks / trufflehog / secretlint** target API keys and credentials.
They do **not** detect Japanese PII (My Number, addresses, names, and other Japan-specific
identifiers). `jp-pii-detect` is not a replacement for them — use it **alongside** them.

See [docs/comparison.md](docs/comparison.md) (Japanese) for a detailed comparison and a
combined-setup guide.

## Quick start

```sh
brew install baneido/tap/jp-pii-detect
jp-pii-detect version
jp-pii-detect scan .
```

Exit codes are `0` (clean), `1` (findings), and `2` (scan or configuration error).
Use `--explain` to inspect why a value matched; remove real data, allowlist intentional
fixtures, or create a baseline for existing findings.

## Key features

- **19+ built-in rules** with checksum validation (My Number check digit, Luhn and brand detection for cards, known sandbox PAN exclusion)
- **Japanese normalization**: folds full-width alphanumerics, hyphen variants, and digit-adjacent long-vowel marks to half-width; handles Japanese-era (和暦) dates
- **F1 0.97** under the default medium profile on a labeled evaluation dataset, gated in CI so accuracy can't silently drift
- **Masked output by default** (`--unmask` for local use only)
- **Baseline support** to freeze existing findings and fail only on newly added PII
- **SARIF / JSON / GitHub annotations** output for CI integration
- **Diff scanning** (`--staged` / `--diff`) so only added lines are checked

## Supported PII

Examples below are all fictitious dummy values.

| Type | How it is detected |
|---|---|
| My Number (individual number) | 12 digits + check digit (statutory algorithm) |
| Credit card number | Luhn + brand detection (Visa/Master/JCB/Amex, etc.) + known sandbox PAN exclusion |
| Email address | Pattern + IANA TLD existence check + reserved-domain exclusion; Japanese EAI and limited confusables in high-recall mode |
| Phone number | Mobile / IP / landline / +81 + digit-count validation |
| Postal code | Exact 7-digit match against real Japan-Post codes |
| Address | Prefecture-to-street-number pattern |
| Driver's license number | 12 digits + nearby context keyword required |
| Passport number | 2 letters + 7 digits + nearby context keyword required |
| Basic pension number | 4-digit + 6-digit + nearby context keyword required |
| Residence card number | 2 letters + 8 digits + 2 letters + context required |
| Bank account number | 7 digits + context keyword required |
| Japan Post Bank symbol/number | Official symbol check digit + correlated number + Japan Post Bank context required |
| Health insurance number | 8 digits + context keyword required |
| Employment insurance number | 4-6-1 digit structure + context keyword required |
| Long-term care insurance number | 10 digits + context keyword required |
| Resident record code | 11 digits + context keyword required |
| Qualified invoice issuer number | `T` + 13 digits + corporate-number checksum |
| Date of birth | Labeled; supports Western and Japanese-era dates |
| Person name | Label (e.g. `氏名:`) + surname/given-name dictionary match |

Run `jp-pii-detect rules` to list all rules. See [docs/detection-methods.md](docs/detection-methods.md)
(Japanese) for details on accuracy and methodology.
See [docs/cli.md](docs/cli.md) (Japanese) for the full CLI reference (all commands, flags, and exit codes).

## Install

### Homebrew (macOS / Linux)

```sh
brew install baneido/tap/jp-pii-detect
```

### mise (macOS / Linux)

```sh
mise use -g github:baneido/jp-pii-detector@v0.4.2
```

### Binary (install.sh)

```sh
curl -fsSL https://raw.githubusercontent.com/baneido/jp-pii-detector/v0.4.2/scripts/install.sh | JP_PII_DETECT_VERSION=v0.4.2 sh
```

### Go install

```sh
go install github.com/baneido/jp-pii-detector/cmd/jp-pii-detect@latest
```

### Docker

```sh
docker run --rm -v "$PWD:/scan" ghcr.io/baneido/jp-pii-detector:v0.4.2
```

## Usage

### CLI

```sh
jp-pii-detect scan .                           # full scan of the current directory
jp-pii-detect scan --staged                    # only added lines of staged changes (for pre-commit)
jp-pii-detect scan --diff origin/main...HEAD   # only added lines of a PR (for CI)
jp-pii-detect rules                            # list detection rules
```

### pre-commit framework

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/baneido/jp-pii-detector
    rev: v0.4.2
    hooks:
      - id: jp-pii-detect
```

```sh
pre-commit install
pre-commit run jp-pii-detect
```

The default hook always scans the staged diff. To audit the whole repository during
adoption, configure `id: jp-pii-detect-full` and run
`pre-commit run jp-pii-detect-full --all-files`.

### GitHub Actions

```yaml
name: pii-check
on: pull_request

jobs:
  pii-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: baneido/jp-pii-detector@v0.4.2
        with:
          # Pin the jp-pii-detect binary version too
          version: v0.4.2
          args: scan --diff origin/${{ github.base_ref }}...HEAD --format github
```

The Action ref and downloaded binary version are resolved independently. For
reproducible builds, explicitly set `with.version` to the same tag as `uses:`.

## Configuration

Place `.jp-pii.toml` at the repository root (auto-discovered upward to the repo root):

```toml
min_confidence = "medium"   # low | medium | high

[allowlist]
paths = ["^testdata/"]         # exclude paths (glob or regex)
stopwords = ["090-XXXX-XXXX"]  # exclude exact dummy values
```

Mark intentional dummy values inline with `# jp-pii-detector:ignore`.

## Note

Detection rules and the full documentation are Japanese-first. See [README.md](README.md)
(Japanese) for complete documentation.

## License

MIT — see [LICENSE](LICENSE).
