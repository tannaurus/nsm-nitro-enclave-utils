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

#[cfg(test)]
mod wasm_tests {
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn verifier() {
        use crate::pcrs::Pcrs;
        use crate::signer::AttestationDocSignerExt;
        use crate::verifier::AttestationDocVerifierExt;
        use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
        use p384::ecdsa::SigningKey;
        use std::time::{SystemTime, UNIX_EPOCH};
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
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            pcrs: Pcrs::default().into(),
            certificate: end_cert.to_der().unwrap().into(),
            cabundle: vec![int_cert.to_der().unwrap().into()],
            public_key: None,
            user_data: None,
            nonce: None,
        };

        let doc = doc.sign(signing_key).unwrap();

        AttestationDoc::from_cose(
            &doc,
            &root_cert,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
    }
}
