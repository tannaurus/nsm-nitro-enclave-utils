use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use p384::ecdsa::SigningKey;
use serde_bytes::ByteBuf;
use crate::phony::{Phony, PhonyBuilder};

enum Driver {
    Mocked(Phony),
    Nitro(i32),
}

/// [`Nsm`] processes requires to the Nitro Secure Module.
/// It can be configured to support "bring your own pki" via [`NsmBuilder`]
pub struct Nsm {
    inner: Driver,
}

impl Drop for Nsm {
    fn drop(&mut self) {
        if let Driver::Nitro(fd) = self.inner {
            aws_nitro_enclaves_nsm_api::driver::nsm_exit(fd)
        }
    }
}

impl Nsm {
    /// Create a new [`Nsm`] which will attempt to interact with the Nitro Secure Module
    pub fn init() -> Self {
        Self {
            inner: Driver::Nitro(aws_nitro_enclaves_nsm_api::driver::nsm_init()),
        }
    }

    /// Create a new [`NsmBuilder`]
    pub fn builder() -> NsmBuilder {
        NsmBuilder::new()
    }

    /// Process an NSM request
    pub fn process_request(&self, request: Request) -> Response {
        match &self.inner {
            Driver::Nitro(fd) => {
                aws_nitro_enclaves_nsm_api::driver::nsm_process_request(*fd, request)
            }
            Driver::Mocked(phony) => phony.process_request(request),
        }
    }
}


/// A builder for [`Nsm`]
/// Acts as an entry point to "bring your own pki" via [`Nsm::dev_mode`]
/// and a driver for authentic Nitro Secure Modules via [`Nsm::init`]
pub struct NsmBuilder();

impl NsmBuilder {
    /// Creates a new [`NsmBuilder`], which acts as an entry point to either configure
    pub fn new() -> Self {
        NsmBuilder()
    }

    /// Creates a new [`PhonyBuilder`], which supports "bring your own pki"
    pub fn dev_mode(self, signing_key: SigningKey, end_cert: ByteBuf) -> PhonyBuilder {
        PhonyBuilder::new(signing_key, end_cert)
    }

    /// Creates a driver for authentic Nitro Secure Modules
    pub fn init(self) -> Nsm {
        Nsm::init()
    }
}
