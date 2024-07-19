# Overview
`nsm-nitro-enclave-utils` is designed to make the lives of teams building with AWS Nitro Enclaves a bit easier. 
It's primary purpose is to support "bring your own PKI" as a development option for Attestation Documents, allowing you to swap out the root of trust in clients that verifying the attestation document's certificate chain. 
With the root of trust swapped, your enclave services can dynamically generate attestation documents outside a Nitro Enclave.

The api of `nsm-nitro-enclave-utils` is intentionally designed to mimic `aws-nitro-enclaves-nsm-api` in an effort to adopting it a painless process.

⚠️ This crate is a work in progress

## Setup
If you're already using `aws-nitro-enclaves-nsm-api`, you'll need to swap out `aws_nitro_enclaves_nsm_api::driver::nsm_init` with `NsmBuilder`, which allows you to swap our your pki and specify the PCRs of your attestation document.

### Root of trust

#### Creating your own
This crate comes with a script to make generating your own pki easier. These scripts are used to generate the scripts in `data/certs`, which **shouldn't** be used as your root of trust, but you can generate your own with them! You can use`data/cert_chain.sh` to get a root, intermediate, and end cert.

#### AWS Root Certificate
When verifying an attestation document coming from a Nitro Enclave, you'll need to use AWS's root certificate; which can be downloaded from their documentation: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#validation-process


## Wasm Compatability

`nsm-nitro-enclave-utils` provides WebAssembly support by disabling the `nitro` feature flag. When `nitro` is disabled, you can still sign your own attestation documents, and verify any attestation document (including authentic ones!) but you cannot generate authenticate documents due to a lack of wasm support in `aws-nitro-enclaves-nsm-api`.