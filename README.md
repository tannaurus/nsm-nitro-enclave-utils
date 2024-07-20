# Overview
`nsm-nitro-enclave-utils` is designed to make the lives of teams building with AWS Nitro Enclaves a bit easier. 
It's primary purpose is to support "bring your own PKI" as an option for attestation documents in development environments, allowing you to swap out the root of trust in clients that are verifying the attestation document's certificate chain.
With the root of trust swapped, your enclave services can dynamically generate attestation documents outside a Nitro Enclave. Clients can have _their_ root of trust swapped to successfully perform attestation against the attestation documents signed by your certificate. 

Replacing the root of trust inherently destroys the security guarantees of AWS Nitro Enclaves: it is up to your team to ensure `nsm-nitro-enclave-utils` is not misconfigured outside a development environment.

The api of `nsm-nitro-enclave-utils` is intentionally designed to mimic `aws-nitro-enclaves-nsm-api` in an effort to make adopting it a painless process.

⚠️ This crate is functional but its API is changing rapidly until further notice.

## Features

| Name                   |                                                                                              Description                                                                                              | Wasm Support | Cargo feature |
|:-----------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:------------:|:-------------:|
| Signing                |                                                                         Sign attestation documents with "Bring your own PKI"                                                                          |      ✅       |     None      |
| Verifying              |                                                                        Verify self signed and AWS signed attestation documents                                                                        |      ✅       |   `verify`    |
| Seeded PCRs            |                                                         Use any collection of strings to deterministically seed your PCRs with `Pcrs::seed`.                                                          |      ✅       |    `seed`     | 
| Random PCRs            |                                              Don't care about the value of your PCRs, but don't want them to be all zeros? `Pcrs::rand` has you covered.                                              |      ✅       |    `rand`     | 
| Authentic NSM requests | Due to limitations with `aws-nitro-enclaves-nsm-api`, requests to an authentic Nitro Secure Module don't have WebAssembly support. Disabling the `nitro` feature is required to support wasm targets. |      ❌       |    `nitro`    |


### Not implemented

#### Missing NSM requests
When `NsmBuilder` has been configured in `dev_mode`, only the `DescribePCR` and `Attestation` requests will succeed. The other requests: `ExtendPCR`, `LockPCR`, `LockPCRs`, `DescribeNSM`, and `GetRandom`, are currently unimplemented. Attempts to make these requests while in `dev_mode` will result in a `Response::Error(ErrorCode::InvalidOperation)`. Requests made while `dev_mode` is _not_ enabled will still succeed, provided you are making them inside a Nitro Enclave.

#### Comprehensive NSM errors
There are a number of `ErrorCode`s returned from `aws-nitro-enclaves-nsm-api` that are currently unaccounted for. Some of them, like `ReadOnlyIndex` and `Success`, are missing due to their associated feature remaining (currently) unsupported. Others, like `InvalidIndex` and `InputTooLarge` are simply due to missing checks in the existing implementation.

## Setup
If you're already using `aws-nitro-enclaves-nsm-api`, you'll need to swap out `aws_nitro_enclaves_nsm_api::driver::nsm_init` with `NsmBuilder`, which allows you to swap our your pki and specify the PCRs of your attestation document.

### Root of trust

#### Creating your own
This crate comes with a script to make generating your own pki easier. These scripts are used to generate the scripts in `data/certs`, which **shouldn't** be used as your root of trust, but you can generate your own with them! You can use`data/cert_chain.sh` to get a root, intermediate, and end cert.

#### AWS Root Certificate
When verifying an attestation document coming from a Nitro Enclave, you'll need to use AWS's root certificate; which can be downloaded from their documentation: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#validation-process

## Why "bring your own PKI"?
AWS Nitro Enclaves cryptographic attestation is a powerful tool that is accompanied by a less-than-desirable hurdle: ["You can request an enclave's attestation document from inside the enclave only"](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html). This limitation introduces two big problems for development teams:
1. You need infra to start building with Nitro Enclaves, and [there are currently no free EC2 instances that support the AWS Nitro System](https://docs.aws.amazon.com/ec2/latest/instancetypes/ec2-nitro-instances.html).
2. Working locally means you either have to disable large parts of your system and/or meticulously mock attestation documents by "extracting" them from a deployed service; the latter of which often requiring the extraction of private key material.

Both of these aren't great. While a funded team may be able to afford to provision new infra during the earliest stages of development, this is a barrier for many who wish to play around with the principles of the technology. Furthermore, once you start building something serious with Nitro Enclaves, the need to address your development environments grows into its own little mountain of tech debt.

When you "bring your own PKI", you can tell `NsmBuilder` to use _your_ signing key instead of AWS's signing key. Now your services can dynamically request new attestation documents outside a Nitro Enclave. Any client that needs to perform attestation against these documents just needs its root of trust to be that of your signing key. All of this is supported by `nsm-nitro-enclave-utils`.


### Examples

Coming soon 👷

## Wasm Compatability

`nsm-nitro-enclave-utils` provides WebAssembly support by disabling the `nitro` feature flag. When `nitro` is disabled, you can still sign your own attestation documents, and verify any attestation document (including authentic ones!), but you cannot generate authentic documents due to a lack of wasm support in `aws-nitro-enclaves-nsm-api`.

### Test coverage

There is a `wasm-pack` test harness in place to ensure features remain wasm compatible. This can be run with the following command: `wasm-pack test --node --no-default-features --features seed,rand`. The test data is intentionally not committed but can be regenerated with `scripts/create_wasm_test_data.sh` 
