use crate::api::nsm::AttestationDoc;
use coset::{CborSerializable, CoseSign1};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sealed::sealed;
use webpki::types::CertificateDer;
use x509_cert::{der::Decode, Certificate};

mod cert;
use cert::ChainVerifier;

#[sealed]
pub trait AttestationDocVerifierExt {
    fn from_cose(
        cose_attestation_doc: &[u8],
        root_cert: &[u8],
        time: u64,
    ) -> Result<AttestationDoc, &'static str>;
}

#[sealed]
impl AttestationDocVerifierExt for AttestationDoc {
    fn from_cose(
        cose_attestation_doc: &[u8],
        root_cert: &[u8],
        time: u64,
    ) -> Result<AttestationDoc, &'static str> {
        let cose =
            CoseSign1::from_slice(cose_attestation_doc).map_err(|_| "Failed to decode COSE")?;

        let payload = cose.payload.as_ref().ok_or("COSE missing payload")?;
        let attestation_doc =
            AttestationDoc::from_binary(payload).map_err(|_| "Failed to decode cbor")?;

        let intermediate_certs = attestation_doc
            .cabundle
            .iter()
            .map(|bytes| bytes.as_slice())
            .collect::<Vec<&[u8]>>();
        let end_cert = CertificateDer::from(attestation_doc.certificate.as_slice());
        let root_cert = CertificateDer::from(root_cert);

        ChainVerifier::new(&root_cert, &intermediate_certs, &end_cert)?.verify(time, None)?;

        let doc_cert = Certificate::from_der(&attestation_doc.certificate)
            .map_err(|_| "Failed to decode attestation certificate")?;
        let doc_cert_pub_key = doc_cert.tbs_certificate.subject_public_key_info;

        doc_cert_pub_key
            .algorithm
            .assert_algorithm_oid(x509_cert::der::oid::db::rfc5912::ID_EC_PUBLIC_KEY)
            .map_err(|_| "Attestation doc certificate has incorrect OID")?;

        let verifying_key = VerifyingKey::from_sec1_bytes(
            doc_cert_pub_key
                .subject_public_key
                .as_bytes()
                .ok_or("Attestation doc missing subject_public_key")?,
        )
        .map_err(|_| "Failed to parse verifying key")?;

        cose.verify_signature(&[], |signature, msg| {
            let signature = Signature::try_from(signature)?;
            verifying_key.verify(msg, &signature)
        })
        .map_err(|_| "Verification of attestation doc signature failed")?;

        Ok(attestation_doc)
    }
}

mod tests {
    #[test]
    fn encode_decode() {
        use crate::{
            api::nsm::{AttestationDoc, Digest},
            AttestationDocSignerExt, AttestationDocVerifierExt, Pcrs,
        };
        use std::time::{SystemTime, UNIX_EPOCH};
        use x509_cert::{builder::Profile, der::Encode};

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
