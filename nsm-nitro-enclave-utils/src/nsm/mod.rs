#[cfg(feature = "pki")]
pub mod dev;

#[cfg(feature = "nitro")]
pub mod nitro;

use crate::api::nsm::{Request, Response};

pub trait Driver {
    fn process_request(&self, request: Request) -> Response;
}
