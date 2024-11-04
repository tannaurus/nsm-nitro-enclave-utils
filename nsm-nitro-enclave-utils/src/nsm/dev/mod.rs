// Signing is only required in wasm targets for the wasm tests that include coverage for supporting attestation document verification in wasm.
#[cfg_attr(target_arch = "wasm32", cfg(test))]
pub(crate) mod sign;

#[cfg(not(target_arch = "wasm32"))]
mod nsm;

#[cfg(not(target_arch = "wasm32"))]
pub use nsm::{DevNitro, DevNitroBuilder};
