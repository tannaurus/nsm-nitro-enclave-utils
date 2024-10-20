#[cfg(feature = "pki")]
pub(crate) mod dev;

#[cfg(feature = "nitro")]
mod nitro;

use crate::api::nsm::{Request, Response};

/// A builder for [`Nsm`]
/// This can be configured in two different ways:
/// 1. Authentic requests to the Nitro Secure Model. This only works inside an authentic Nitro Enclave. Requires the `nitro` feature flag.
/// 2. "Bring your own pki." A builder for this functionality is available via [`NsmBuilder::dev_mode`]. Requires the `pki` feature flag.
pub struct NsmBuilder;

impl NsmBuilder {
    /// Creates a new [`NsmBuilder`]
    pub fn new() -> Self {
        NsmBuilder
    }
}

pub(crate) trait Driver: Send + Sync {
    fn process_request(&self, request: Request) -> Response;
}

/// Processes requests made to the Nitro Secure Module.
/// It can be configured to support "bring your own pki" via [`NsmBuilder`].
pub struct Nsm {
    pub(crate) driver: Box<dyn Driver>,
}

impl Nsm {
    /// Creates a new [`NsmBuilder`]
    pub fn builder() -> NsmBuilder {
        NsmBuilder::new()
    }

    /// Process an NSM request
    pub fn process_request(&self, request: Request) -> Response {
        self.driver.process_request(request)
    }
}
