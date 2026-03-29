# Release Process

This repository contains two independently versioned crates:

| Crate | Tag pattern |
|---|---|
| `nsm-nitro-enclave-utils` | `nsm-nitro-enclave-utils-v*` |
| `nsm-nitro-enclave-utils-keygen` | `nsm-nitro-enclave-utils-keygen-v*` |

Pushing a tag triggers the [release workflow](../.github/workflows/release.yml), which publishes the relevant crate(s) to crates.io using the `CARGO_REGISTRY_TOKEN` repository secret.

---

## Releasing `nsm-nitro-enclave-utils-keygen` only

1. Bump the version in `nsm-nitro-enclave-utils-keygen/Cargo.toml`.
2. Commit the change.
3. Tag and push:
   ```bash
   git tag nsm-nitro-enclave-utils-keygen-v<version>
   git push origin nsm-nitro-enclave-utils-keygen-v<version>
   ```

---

## Releasing both crates together

When releasing `nsm-nitro-enclave-utils`, both crates must be published because the main crate depends on keygen. The workflow handles this automatically — a `nsm-nitro-enclave-utils-v*` tag publishes keygen first, waits for crates.io to index it, then publishes the main crate.

1. Bump the version in both `Cargo.toml` files and update the keygen dependency version in `nsm-nitro-enclave-utils/Cargo.toml`:
   ```toml
   nsm-nitro-enclave-utils-keygen = { version = "<new-keygen-version>", path = "../nsm-nitro-enclave-utils-keygen" }
   ```
2. Commit the changes.
3. Tag and push:
   ```bash
   git tag nsm-nitro-enclave-utils-v<version>
   git push origin nsm-nitro-enclave-utils-v<version>
   ```

> Both crates should be kept on the same version number when doing a combined release.
