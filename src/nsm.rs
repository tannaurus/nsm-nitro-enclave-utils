use crate::phony::PhonyBuilder;
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use p384::SecretKey;
use serde_bytes::ByteBuf;

pub(crate) trait Driver {
    fn process_request(&self, request: Request) -> Response;
}

#[cfg(feature = "nitro")]
struct Nitro(i32);

#[cfg(feature = "nitro")]
impl Driver for Nitro {
    fn process_request(&self, request: Request) -> Response {
        aws_nitro_enclaves_nsm_api::driver::nsm_process_request(self.0, request)
    }
}

#[cfg(feature = "nitro")]
impl Drop for Nitro {
    fn drop(&mut self) {
        aws_nitro_enclaves_nsm_api::driver::nsm_exit(self.0)
    }
}

/// [`Nsm`] processes requires to the Nitro Secure Module.
/// It can be configured to support "bring your own pki" via [`NsmBuilder`]
pub struct Nsm {
    pub(crate) driver: Box<dyn Driver>,
}

impl Nsm {
    #[cfg(feature = "nitro")]
    /// Create a new [`Nsm`] which will attempt to interact with the Nitro Secure Module
    pub fn init() -> Self {
        Self {
            driver: Box::new(Nitro(aws_nitro_enclaves_nsm_api::driver::nsm_init())),
        }
    }

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

    /// Creates a new [`PhonyBuilder`], which supports "bring your own pki"
    pub fn dev_mode(self, signing_key: SecretKey, end_cert: ByteBuf) -> PhonyBuilder {
        PhonyBuilder::new(signing_key, end_cert)
    }

    #[cfg(feature = "nitro")]
    /// Creates a driver for authentic Nitro Secure Modules
    pub fn init(self) -> Nsm {
        Nsm::init()
    }
}
