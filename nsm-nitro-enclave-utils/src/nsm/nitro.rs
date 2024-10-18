use crate::nsm::{Driver, Nsm, NsmBuilder};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};

struct Nitro(i32);

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

impl Nsm {
    /// Create a new [`Nsm`] which will attempt to interact with the Nitro Secure Module
    pub fn init() -> Self {
        Self {
            driver: Box::new(Nitro(aws_nitro_enclaves_nsm_api::driver::nsm_init())),
        }
    }
}

impl NsmBuilder {
    /// Creates a driver for authentic Nitro Secure Modules
    pub fn build(self) -> Nsm {
        Nsm::init()
    }
}
