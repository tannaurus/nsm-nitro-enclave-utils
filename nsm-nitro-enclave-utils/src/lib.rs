//! Wraps [`aws_nitro_enclaves_nsm_api`] to allow you to mock the Nitro Hypervisor locally

#[cfg(feature = "verify")]
mod verify;
#[cfg(feature = "verify")]
pub use verify::*;

mod sign;
pub use sign::*;

mod phony;
pub use phony::*;

mod nsm;
pub use nsm::*;

pub mod api;
#[cfg(test)]
mod test_utils;
mod time;
pub use time::*;

#[cfg(test)]
/// This test suite is expected to reasonable cover all features that WebAssembly support.
/// See README for instructions for running these tests.
mod wasm_tests {
    use super::*;
    use crate::time::GetTimestamp;
    use std::mem;
    use wasm_bindgen_test::*;
    use x509_cert::{
        der::{DecodePem, Encode},
        Certificate,
    };

    #[cfg(feature = "verify")]
    #[wasm_bindgen_test]
    fn verifier() {
        use p384::ecdsa::SigningKey;

        let time = GetTimestamp::new(Box::new(|| include!("../wasm_test_data/created_at.txt")));

        let root_cert =
            Certificate::from_pem(include_bytes!("../wasm_test_data/root/ecdsa_p384_cert.pem"))
                .unwrap()
                .to_der()
                .unwrap();
        let int_cert =
            Certificate::from_pem(include_bytes!("../wasm_test_data/int/ecdsa_p384_cert.pem"))
                .unwrap();
        let end_cert =
            Certificate::from_pem(include_bytes!("../wasm_test_data/end/ecdsa_p384_cert.pem"))
                .unwrap();

        let signing_key = p384::SecretKey::from_sec1_pem(include_str!(
            "../wasm_test_data/end/ecdsa_p384_key.pem"
        ))
        .unwrap();
        let signing_key: SigningKey = signing_key.into();

        let doc = api::nsm::AttestationDoc {
            module_id: "".to_string(),
            digest: api::nsm::Digest::SHA384,
            timestamp: time.time(),
            pcrs: Pcrs::default().into(),
            certificate: end_cert.to_der().unwrap().into(),
            cabundle: vec![int_cert.to_der().unwrap().into()],
            public_key: None,
            user_data: None,
            nonce: None,
        };

        let doc = doc.sign(signing_key).unwrap();

        api::nsm::AttestationDoc::from_cose(&doc, &root_cert, time).unwrap();
    }

    #[wasm_bindgen_test]
    fn phony_driver() {
        let secret_key = p384::SecretKey::from_sec1_pem(include_str!(
            "../wasm_test_data/end/ecdsa_p384_key.pem"
        ))
        .unwrap();
        let end_cert =
            Certificate::from_pem(include_bytes!("../wasm_test_data/end/ecdsa_p384_cert.pem"))
                .unwrap();

        let time = include!("../wasm_test_data/created_at.txt");
        let nsm = NsmBuilder::new()
            .dev_mode(
                secret_key,
                end_cert.to_der().unwrap().into(),
                GetTimestamp::new(Box::new(move || time)),
            )
            .build();

        let response = nsm.process_request(api::nsm::Request::Attestation {
            user_data: None,
            nonce: None,
            public_key: None,
        });

        assert_eq!(
            mem::discriminant(&response),
            mem::discriminant(&api::nsm::Response::Attestation {
                document: Vec::new()
            })
        );
    }

    #[cfg(feature = "seed")]
    #[wasm_bindgen_test]
    fn seed_is_deterministic() {
        use std::collections::BTreeMap;

        let mut seed = BTreeMap::new();
        for index in PCR_INDEXES {
            seed.insert(index, index.to_string());
        }
        let a = Pcrs::seed(seed.clone()).unwrap();
        let b = Pcrs::seed(seed).unwrap();
        assert_eq!(a, b);

        let mut alt_seed = BTreeMap::new();
        for index in PCR_INDEXES {
            alt_seed.insert(index, (index + 1).to_string());
        }
        let c = Pcrs::seed(alt_seed).unwrap();
        assert_ne!(a, c);
    }

    #[cfg(feature = "rand")]
    #[wasm_bindgen_test]
    fn rand() {
        let a = Pcrs::rand();
        let b = Pcrs::rand();
        assert_ne!(a, b);
    }
}
