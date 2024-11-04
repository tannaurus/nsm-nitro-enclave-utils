use crate::nsm::Driver;
use aws_nitro_enclaves_nsm_api::api::{Request, Response};

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
