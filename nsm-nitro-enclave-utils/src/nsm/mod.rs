mod dev;

#[cfg(feature = "nitro")]
mod nitro;

use crate::api::nsm::{Request, Response};

pub(crate) trait Driver: Send + Sync {
    fn process_request(&self, request: Request) -> Response;
}

/// [`Nsm`] processes requires to the Nitro Secure Module.
/// It can be configured to support "bring your own pki" via [`NsmBuilder`]
pub struct Nsm {
    pub(crate) driver: Box<dyn Driver>,
}

impl Nsm {
    /// Create a new [`NsmBuilder`]
    pub fn builder() -> NsmBuilder {
        NsmBuilder::new()
    }

    /// Process an NSM request
    pub fn process_request(&self, request: Request) -> Response {
        self.driver.process_request(request)
    }
}

/// A builder for [`Nsm`]
/// Acts as an entry point to "bring your own pki" via [`Nsm::dev_mode`]
/// and a driver for authentic Nitro Secure Modules via [`Nsm::init`]
pub struct NsmBuilder;

impl NsmBuilder {
    /// Creates a new [`NsmBuilder`], which acts as an entry point to either configure
    pub fn new() -> Self {
        NsmBuilder
    }
}
