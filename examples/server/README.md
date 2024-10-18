# Overview

A simple axum server that uses `nsm-nitro-enclave-utils` to generate attestation documents outside a Nitro Enclave.

# Running the service

Run the service and provide your end certificate, signing key, and int certificate(s). The `dev` feature flag is required to ensure that `NsmBuilder` is configured in `dev_mode`. Otherwise, requests will attempt to be processed by an authentic Nitro Secure Module and result in an InternalError.
The certificates/signing key are intentionally not committed in this repository but can be generated with `scripts/create_chain.sh` if needed.

`cargo run -p service --features dev -- --end-cert-pem <END_CERTIFICATE_PEM> --signing-key-pem <SIGNING_KEY_PEM> --int-cert-pem <INT_CERTIFICATE_PEM>`

# Querying the service

The "attest" handler is listening on `http://127.0.0.1:3000/attest/:nonce`. You _could_ curl that, but the response you get back is a COSE signed attestation document. It's instead encouraged to use `examples/client` to make the query, which will verify the document payload for you.
