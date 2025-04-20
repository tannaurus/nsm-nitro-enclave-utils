  <p>
    <a href="https://github.com/tannaurus/nsm-nitro-enclave-utils/blob/main/.github/workflows/rust.yml"><img alt="Build Status" src="https://github.com/tannaurus/nsm-nitro-enclave-utils/actions/workflows/rust.yml/badge.svg?branch=main"/></a>
    <a href="https://crates.io/crates/nsm-nitro-enclave-utils"><img alt="crates.io" src="https://img.shields.io/crates/v/nsm-nitro-enclave-utils"/></a>
    <a href="https://opensource.org/licenses/MPL-2.0"><img alt="License MPL 2.0" src="https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg"/></a>
  </p>

# Overview
`nsm-nitro-enclave-utils` is designed to make the lives of teams building with AWS Nitro Enclaves a bit easier.
It's primary purpose is to support "bring your own PKI" as an option for attestation documents in development environments, allowing you to swap out the root of trust in clients that are verifying the attestation document's certificate chain.
With the root of trust swapped, your enclave services can dynamically generate self-signed attestation documents outside a Nitro Enclave, inside your local development environment. Clients can have _their_ root of trust swapped to successfully perform attestation against your self-signed attestation documents.

Replacing the root of trust inherently destroys the security guarantees of AWS Nitro Enclaves: it is up to your team to ensure `nsm-nitro-enclave-utils` is not misconfigured outside a development environment.

The api of `nsm-nitro-enclave-utils` is intentionally designed to mimic `aws-nitro-enclaves-nsm-api` in an effort to make adopting it a painless process.

⚠️ This crate is functional but its API is changing rapidly until further notice.

## Features

| Name                   |                                                                                              Description                                                                                              | Wasm Support | Cargo feature |
|:-----------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:------------:|:-------------:|
| Verifying              |                                                                        Verify self signed and AWS signed attestation documents                                                                        |      ✅       |   `verify`    |
| Seeded PCRs            |                                                         Use any collection of strings to deterministically seed your PCRs with `Pcrs::seed`.                                                          |      ✅       |    `seed`     |
| Random PCRs            |                                              Don't care about the value of your PCRs, but don't want them to be all zeros? `Pcrs::rand` has you covered.                                              |      ✅       |    `rand`     |
| Signing                |                                                                         Sign attestation documents with "Bring your own PKI"                                                                          |      ❌       |     `pki`     |
| Authentic NSM requests | Due to limitations with `aws-nitro-enclaves-nsm-api`, requests to an authentic Nitro Secure Module don't have WebAssembly support. Disabling the `nitro` feature is required to support wasm targets. |      ❌       |    `nitro`    |


### Not implemented

#### Missing NSM requests
When `NsmBuilder` has been configured in `dev_mode`, only the `DescribePCR` and `Attestation` requests will succeed. The other requests: `ExtendPCR`, `LockPCR`, `LockPCRs`, `DescribeNSM`, and `GetRandom`, are currently unimplemented. Attempts to make these requests while in `dev_mode` will result in a `Response::Error(ErrorCode::InvalidOperation)`. Requests made while `dev_mode` is _not_ enabled will still succeed, provided you are making them inside a Nitro Enclave.

#### Comprehensive NSM errors in `dev_mode`
There are a number of `ErrorCode`s returned from `aws-nitro-enclaves-nsm-api` that are currently unaccounted for when using this in `dev_mode`, configured via `NsmBuilder`. Some of them, like `ReadOnlyIndex` and `Success`, are missing due to their associated feature remaining (currently) unsupported. Others, like `InvalidIndex` and `InputTooLarge` are simply due to missing checks in the existing implementation.

## Setup
If you're already using `aws-nitro-enclaves-nsm-api`, you'll need to swap out `aws_nitro_enclaves_nsm_api::driver::nsm_init` with `NsmBuilder`, which allows you to swap out your pki to self-sign attestation documents, and specify the PCRs that are included in those attestation documents.

### Root of trust

#### AWS Root Certificate
When verifying an attestation document coming from a Nitro Enclave, you'll need to use AWS's root certificate; which can be downloaded from their documentation: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#validation-process

#### Creating your own
This crate comes with a script to make generating your own pki easier. You can use `scripts/cert_chain.sh` to get a root, intermediate, and leaf certificate.

## Why "bring your own PKI"?
AWS Nitro Enclaves cryptographic attestation is a powerful tool that is accompanied by a less-than-desirable hurdle: ["You can request an enclave's attestation document from inside the enclave only"](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html). This limitation introduces two big problems for development teams:
1. You need to pay for infra to start building with Nitro Enclaves, and [there are currently no free EC2 instances that support the AWS Nitro Enclaves.](https://docs.aws.amazon.com/ec2/latest/instancetypes/ec2-nitro-instances.html)
2. Working locally means you either have to disable large parts of your system and/or meticulously mock attestation documents by "extracting" them from a deployed service; the latter of which often requiring the extraction of private key material.

Both of these aren't great. While a funded team may be able to afford to provision new infra during the earliest stages of development, this is a barrier for many who wish to play around with the principles of the technology. Furthermore, once you start building something serious with Nitro Enclaves, the need to address your development environments grows into its own little mountain of tech debt.

When you "bring your own PKI", you can tell `NsmBuilder` to use _your_ signing key instead of AWS's signing key. Now your services can dynamically request new attestation documents outside a Nitro Enclave. Any client that needs to perform attestation against these documents just needs its root of trust to be that of your signing key. All of this is supported by `nsm-nitro-enclave-utils`.

### Examples

Found in the `/examples` directory.

| Name   |                                                          Description                                                           |
|:-------|:------------------------------------------------------------------------------------------------------------------------------:|
| Server | Interacts with the Nitro Secure Module, including the nonce provided in the request body in the returned attestation document. |
| Client |                          Makes a request to the Server example and verifies the attestation document.                          |


## Wasm Compatibility

`nsm-nitro-enclave-utils` provides WebAssembly support by disabling the `nitro`. When `nitro` is disabled, you can still verify any attestation documents (including authentic and self-signed!), but you cannot generate documents due to a lack of wasm support in `aws-nitro-enclaves-nsm-api`.
The `pki` feature flag won't cause the build to fail, but the functionality it provides is not Wasm compatible. The `pki` feature flag retains wasm compilation support to generate test data for the wasm test suite.
