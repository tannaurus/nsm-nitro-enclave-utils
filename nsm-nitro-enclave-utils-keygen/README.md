# nsm-nitro-enclave-utils-keygen

<p>
  <a href="https://github.com/tannaurus/nsm-nitro-enclave-utils/blob/main/.github/workflows/rust.yml"><img alt="Build Status" src="https://github.com/tannaurus/nsm-nitro-enclave-utils/actions/workflows/rust.yml/badge.svg?branch=main"/></a>
  <a href="https://crates.io/crates/nsm-nitro-enclave-utils-keygen"><img alt="crates.io" src="https://img.shields.io/crates/v/nsm-nitro-enclave-utils-keygen"/></a>
  <a href="https://opensource.org/licenses/MPL-2.0"><img alt="License MPL 2.0" src="https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg"/></a>
  <a href="https://github.com/tannaurus/nsm-nitro-enclave-utils/releases"><img alt="GitHub Release" src="https://img.shields.io/github/v/release/tannaurus/nsm-nitro-enclave-utils?filter=nsm-nitro-enclave-utils-keygen-v*"/></a>
</p>

A CLI tool for generating and inspecting self-signed certificate chains used by [nsm-nitro-enclave-utils](https://crates.io/crates/nsm-nitro-enclave-utils) in local development environments.

## Installation

```bash
cargo install nsm-nitro-enclave-utils-keygen
```

## Commands

### `generate`

Generates a root → intermediate → end certificate chain with P-384 ECDSA keys.

```
Usage: nsm-keygen generate [OPTIONS]

Options:
  -f, --format <FORMAT>  Output format: pem (default) or der
      --days <DAYS>      Certificate validity in days [default: 365]
      --dir <DIR>        Directory to write certificates to. If omitted, outputs JSON to stdout.
```

**Write to a directory:**
```bash
nsm-keygen generate --dir ./certs
```

This produces four files:
- `root-certificate.pem`
- `int-certificate.pem`
- `end-certificate.pem`
- `end-signing-key.pem`

**Print JSON to stdout:**
```bash
nsm-keygen generate
nsm-keygen generate --format der
```

---

### `check`

Inspects the expiry of a generated certificate chain.

```
Usage: nsm-keygen check --dir <DIR> [OPTIONS]

Options:
      --dir <DIR>                   Directory containing the certificates to check.
  -f, --format <FORMAT>             Format of the certificates [default: pem]
      --valid-at <YYYY-MM-DD>  Fail if any certificate is not valid at this date.
```

**Inspect expiry:**
```bash
nsm-keygen check --dir ./certs
```

```
root-certificate:
  Not Before: 2026-01-01T00:00:00Z
  Not After:  2027-01-01T00:00:00Z
  Status:     Valid (expires in 276 days)
...
```

**Use in CI to warn before expiry:**

Exits with code 1 if any certificate is not valid at the given date, making it suitable for a scheduled CI job:

```bash
# Fail if any cert expires within the next 30 days
nsm-keygen check --dir ./certs --valid-at $(date -d '+30 days' +%Y-%m-%d)
```

Example GitHub Actions step:

```yaml
- name: Check dev cert chain expiry
  run: nsm-keygen check --dir ./certs --valid-at $(date -d '+30 days' +%Y-%m-%d)
```
