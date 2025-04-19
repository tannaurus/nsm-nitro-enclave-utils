use crate::driver::Driver;
use aws_nitro_enclaves_nsm_api::api::{Request, Response};

/// [`Nitro`] makes authentic requests to the Nitro Secure Module, and only works inside an authentic Nitro Enclave.
/// ```rust
/// use nsm_nitro_enclave_utils::{driver::{Driver, nitro::Nitro}, api::nsm::Request};
/// use serde_bytes::ByteBuf;
/// let nsm = Nitro::init();
/// let attestation_doc = nsm.process_request(Request::Attestation {
///         user_data: Some(ByteBuf::from(b"hello, world")),
///         public_key: None,
///         nonce: None,
///     });
///
///  println!("{:?}", attestation_doc);
/// ```
pub struct Nitro(i32);

impl Driver for Nitro {
    fn process_request(&self, request: Request) -> Response {
        aws_nitro_enclaves_nsm_api::driver::nsm_process_request(self.0, request)
    }
}

impl Drop for Nitro {
    fn drop(&mut self) {
        aws_nitro_enclaves_nsm_api::driver::nsm_exit(self.0)
    }
}

impl Nitro {
    pub fn init() -> Self {
        Self(aws_nitro_enclaves_nsm_api::driver::nsm_init())
    }
}
