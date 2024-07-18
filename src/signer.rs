use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use coset::iana::Algorithm;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use p384::ecdsa::signature::Signer;
use p384::ecdsa::{Signature, SigningKey};
use sealed::sealed;

#[sealed]
pub trait AttestationDocSignerExt {
    fn sign(&self, signing_key: SigningKey) -> Result<Vec<u8>, &'static str>;
}

#[sealed]
impl AttestationDocSignerExt for AttestationDoc {
    fn sign(&self, signing_key: SigningKey) -> Result<Vec<u8>, &'static str> {
            let headers = HeaderBuilder::new().algorithm(Algorithm::ES384).build();

            let payload = self.to_binary();

            let cose = CoseSign1Builder::new()
                .payload(payload)
                .protected(headers)
                .create_signature(b"", |bytes| {
                    let signature: Signature = signing_key.sign(bytes);
                    signature.to_bytes().to_vec()
                })
                .build();

            cose.to_vec().map_err(|_| "Failed to serialize COSE")
    }
}

#[cfg(test)]
mod tests {
    use crate::decoder::Decoder;
    use crate::pcrs::Pcrs;
    use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
    use p384::ecdsa::SigningKey;
    use std::time::{SystemTime, UNIX_EPOCH};
    use x509_cert::{Certificate, der::{DecodePem, Encode}};
    use crate::signer::AttestationDocSignerExt;

    #[test]
    fn encode_decode() {
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

        Decoder::decode_with_root_cert(
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
