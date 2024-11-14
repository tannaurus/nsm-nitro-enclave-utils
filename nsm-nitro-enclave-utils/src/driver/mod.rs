//! `driver` is the primary entry point for `nsm-nitro-enclave-utils`' server-side behavior.
//!
//! ### Features
//! * **nitro** -
//! Enabled by default. Enables the [`nitro`] module, which contains the [`nitro::Nitro`] struct. It makes authentic requests to the Nitro Secure Module, and only works inside an authentic Nitro Enclave.
//!
//! * **pki** -
//! When enabled, the [`dev`] module is included, which contains the [`dev::DevNitro`] struct. It is designed mimic responses from an authentic Nitro Secure Module, allowing you to build for Nitro Enclaves locally.

#[cfg(feature = "pki")]
pub mod dev;

#[cfg(feature = "nitro")]
pub mod nitro;

use crate::api::nsm::{Request, Response};

/// [`Driver`] is a simple trait meant to conform to aws-nitro-enclaves-nsm-api's api interface.
pub trait Driver {
    fn process_request(&self, request: Request) -> Response;
}
