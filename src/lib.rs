//! Wraps [`aws_nitro_enclaves_nsm_api`] to allow you to mock the Nitro Hypervisor locally

mod cert;
mod phony;

mod verifier;
pub use verifier::*;
mod signer;
pub use signer::*;
mod pcrs;
pub use pcrs::*;

mod nsm;
pub use nsm::*;

pub(crate) use p384::ecdsa::SigningKey;
pub use p384::SecretKey;
pub use webpki::EndEntityCert;

#[cfg(test)]
/// This test suite is expected to reasonable cover all features that WebAssembly support.
/// wasm-pack test --node --no-default-features --features seed,rand
mod wasm_tests {
    use wasm_bindgen_test::*;

    /// "time" is not implement for wasm targets
    const SECONDS_SINCE_EPOCH: u64 = 1721403617;

    #[wasm_bindgen_test]
    fn verifier() {
        use crate::pcrs::Pcrs;
        use crate::signer::AttestationDocSignerExt;
        use crate::verifier::AttestationDocVerifierExt;
        use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
        use p384::ecdsa::SigningKey;
        use x509_cert::{
            der::{DecodePem, Encode},
            Certificate,
        };

        let root_cert =
            Certificate::from_pem(include_bytes!("../data/certs/root/ecdsa_p384_cert.pem"))
                .unwrap()
                .to_der()
                .unwrap();
        let int_cert =
            Certificate::from_pem(include_bytes!("../data/certs/int/ecdsa_p384_cert.pem")).unwrap();
        let end_cert =
            Certificate::from_pem(include_bytes!("../data/certs/end/ecdsa_p384_cert.pem")).unwrap();

        let signing_key =
            p384::SecretKey::from_sec1_pem(include_str!("../data/certs/end/ecdsa_p384_key.pem"))
                .unwrap();
        let signing_key: SigningKey = signing_key.into();

        let doc = AttestationDoc {
            module_id: "".to_string(),
            digest: Digest::SHA384,
            timestamp: SECONDS_SINCE_EPOCH,
            pcrs: Pcrs::default().into(),
            certificate: end_cert.to_der().unwrap().into(),
            cabundle: vec![int_cert.to_der().unwrap().into()],
            public_key: None,
            user_data: None,
            nonce: None,
        };

        let doc = doc.sign(signing_key).unwrap();

        AttestationDoc::from_cose(&doc, &root_cert, SECONDS_SINCE_EPOCH).unwrap();
    }

    #[cfg(feature = "seed")]
    #[wasm_bindgen_test]
    fn seed_is_deterministic() {
        use crate::Pcrs;

        let seed: [String; crate::pcrs::PCR_COUNT] = core::array::from_fn(|i| format!("pcr{i}"));
        let a = Pcrs::seed(seed.clone()).unwrap();
        let b = Pcrs::seed(seed).unwrap();
        assert_eq!(a, b);

        let alt_seed: [String; crate::pcrs::PCR_COUNT] =
            core::array::from_fn(|i| format!("pcr{}", i + 1));
        let c = Pcrs::seed(alt_seed).unwrap();
        assert_ne!(a, c);
    }

    #[cfg(feature = "rand")]
    #[wasm_bindgen_test]
    fn rand() {
        use crate::Pcrs;

        let a = Pcrs::rand();
        let b = Pcrs::rand();
        assert_ne!(a, b);
    }
}
