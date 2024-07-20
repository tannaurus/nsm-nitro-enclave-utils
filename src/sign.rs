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
    use crate::pcrs::Pcrs;
    use crate::sign::AttestationDocSignerExt;
    use crate::verify::AttestationDocVerifierExt;
    use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
    use std::time::{SystemTime, UNIX_EPOCH};
    use x509_cert::builder::Profile;
    use x509_cert::der::Encode;

    #[test]
    fn encode_decode() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let (root_key, root_public_key) = crate::test_utils::generate_key();
        let root_cert =
            crate::test_utils::build_cert(Profile::Root, root_key.clone(), root_public_key, now);

        let (int_key, int_public_key) = crate::test_utils::generate_key();
        let int_cert = crate::test_utils::build_cert(
            Profile::SubCA {
                issuer: Default::default(),
                path_len_constraint: None,
            },
            root_key,
            int_public_key,
            now,
        );

        let (end_key, end_public_key) = crate::test_utils::generate_key();
        let end_cert = crate::test_utils::build_cert(
            Profile::Leaf {
                issuer: Default::default(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            int_key,
            end_public_key,
            now,
        );

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

        let doc = doc.sign(end_key).unwrap();

        AttestationDoc::from_cose(
            &doc,
            &root_cert.to_der().unwrap(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
    }
}
