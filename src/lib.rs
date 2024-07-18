//! Wraps [`aws_nitro_enclaves_nsm_api`] to allow you to mock the Nitro Hypervisor locally

mod cert;
mod decoder;
pub use decoder::*;
mod encoder;
pub use encoder::*;
mod pcrs;
pub use pcrs::*;
mod phony;

mod nsm;
pub use nsm::*;
