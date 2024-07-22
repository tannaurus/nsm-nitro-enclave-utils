# Overview

A simple client that uses `nsm-nitro-enclave-utils` to verify attestation documents with support for "bring your own PKI."

# Using the service

The client is designed to work in tandem with `examples/service`. After that service is running, you can provide this client with a nonce and your pem encoded root certificate. See the root README.md instructions on getting the correct root certificate for both "bring your own PKI" and AWS verification.

`cargo run -p client -- --nonce 123 --root-cert-pem <ROOT_CERTIFICATE>`