//! Wraps [`aws_nitro_enclaves_nsm_api`] to allow you to mock the Nitro Hypervisor locally

mod cert;
pub mod decoder;
pub mod encoder;
mod pcrs;
mod phony;

use aws_nitro_enclaves_nsm_api::api::{ Request, Response};
use p384::ecdsa::SigningKey;
use serde_bytes::ByteBuf;
use crate::phony::{Phony, PhonyBuilder};

#[derive(Clone, Debug)]
pub struct KeyMaterial;

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

enum Hypervisor {
    Mocked(Phony),
    Nitro(i32),
}

/// [`Nsm`] processes requires to the Nitro Secure Module.
/// It can be configured to support "bring your own pki" via [`NsmBuilder`]
pub struct Nsm {
    inner: Hypervisor,
}

impl Drop for Nsm {
    fn drop(&mut self) {
        if let Hypervisor::Nitro(fd) = self.inner {
            aws_nitro_enclaves_nsm_api::driver::nsm_exit(fd)
        }
    }
}

impl Nsm {
    /// Create a new [`Nsm`] which will attempt to interact with the Nitro Secure Module
    pub fn init() -> Self {
        Self {
            inner: Hypervisor::Nitro(aws_nitro_enclaves_nsm_api::driver::nsm_init()),
        }
    }

    /// Create a new [`NsmBuilder`]
    pub fn builder() -> NsmBuilder {
        NsmBuilder::new()
    }

    /// Process an NSM request
    pub fn process_request(&self, request: Request) -> Response {
        match &self.inner {
            Hypervisor::Nitro(fd) => {
                aws_nitro_enclaves_nsm_api::driver::nsm_process_request(*fd, request)
            }
            Hypervisor::Mocked(phony) => phony.process_request(request),
        }
    }
}
