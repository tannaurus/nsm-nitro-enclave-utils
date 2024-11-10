//! Wraps [`aws_nitro_enclaves_nsm_api`] to allow you to mock the Nitro Hypervisor locally

pub mod api;

pub mod driver;

pub mod time;

pub mod pcr;

#[cfg(feature = "verify")]
pub mod verify;

#[derive(Debug)]
/// Captures errors that can occur during attestation document verification.
/// `kind` is a high-level categorization of the error that is defined by the library.
/// `source` is the underlying error that caused the failure. When possible, the source is the error that was returned by the underlying library.
/// If the error returned from the underlying library does not implement [`std::error::Error`], or the error originated due to this library's own assertions, [`ErrorContext`] is used.
pub struct Error<T> {
    kind: T,
    _backtrace: std::backtrace::Backtrace,
    _source: Box<dyn std::error::Error + Send + Sync>,
}

impl<T> Error<T> {
    fn new<E>(kind: T, err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind,
            _backtrace: std::backtrace::Backtrace::capture(),
            _source: Box::new(err),
        }
    }

    pub fn kind(&self) -> &T {
        &self.kind
    }
}

/// Used by errors to provide additional context if the error returned from the underlying library does not implement [`std::error::Error`],
/// or the error originated due to this library's own assertions.
#[derive(Debug, PartialEq, Eq, Clone, Hash, PartialOrd, Ord)]
pub struct ErrorContext(pub(crate) &'static str);

impl std::fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ErrorContext {}

#[cfg(all(test, target_arch = "wasm32"))]
/// This test suite is expected to reasonable cover all features that WebAssembly support.
/// See README for instructions for running these tests.
mod wasm_tests {
    use wasm_bindgen_test::*;

    #[cfg(all(feature = "verify", feature = "pki"))]
    #[wasm_bindgen_test]
    fn sign_and_verify() {
        use p384::ecdsa::SigningKey;
        use x509_cert::{
            der::{DecodePem, Encode},
            Certificate,
        };

        use crate::api;
        use crate::driver::dev::sign::AttestationDocSignerExt;
        use crate::pcr::Pcrs;
        use crate::time::Time;
        use crate::verify::AttestationDocVerifierExt;

        let time = Time::new(Box::new(|| include!("../../test_data/created_at.txt")));

        let root_cert =
            Certificate::from_pem(include_bytes!("../../test_data/root/ecdsa_p384_cert.pem"))
                .unwrap()
                .to_der()
                .unwrap();
        let int_cert =
            Certificate::from_pem(include_bytes!("../../test_data/int/ecdsa_p384_cert.pem"))
                .unwrap();
        let end_cert =
            Certificate::from_pem(include_bytes!("../../test_data/end/ecdsa_p384_cert.pem"))
                .unwrap();

        let signing_key =
            p384::SecretKey::from_sec1_pem(include_str!("../../test_data/end/ecdsa_p384_key.pem"))
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

    #[cfg(feature = "seed")]
    #[wasm_bindgen_test]
    fn seed_is_deterministic() {
        use crate::pcr::{Pcrs, PCR_INDEXES};

        use std::collections::BTreeMap;

        let mut seed = BTreeMap::new();
        for index in PCR_INDEXES {
            seed.insert(index, usize::from(index).to_string());
        }
        let a = Pcrs::seed(seed.clone());
        let b = Pcrs::seed(seed);
        assert_eq!(a, b);

        let mut alt_seed = BTreeMap::new();
        for index in PCR_INDEXES {
            alt_seed.insert(index, (usize::from(index) + 1).to_string());
        }
        let c = Pcrs::seed(alt_seed);
        assert_ne!(a, c);
    }

    #[cfg(feature = "rand")]
    #[wasm_bindgen_test]
    fn rand() {
        use crate::pcr::Pcrs;

        let a = Pcrs::rand();
        let b = Pcrs::rand();
        assert_ne!(a, b);
    }
}
