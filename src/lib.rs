//! Wraps [`aws_nitro_enclaves_nsm_api`] to allow you to mock the Nitro Hypervisor locally

mod cert;
mod verifier;
pub use verifier::*;
mod signer;
pub use signer::*;
mod pcrs;
pub use pcrs::*;
mod phony;

mod nsm;

pub use nsm::*;
