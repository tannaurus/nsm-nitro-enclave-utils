#[cfg(feature = "pki")]
pub mod dev;

#[cfg(feature = "nitro")]
pub mod nitro;

use crate::api::nsm::{Request, Response};

/// [`Driver`] is a simple trait meant to conform to aws-nitro-enclaves-nsm-api's api interface.
/// The authentic nitro secure module behavior is mimicked by the [`DevNitro`] struct, which requires the `pki` feature flag.
pub trait Driver {
    fn process_request(&self, request: Request) -> Response;
}
