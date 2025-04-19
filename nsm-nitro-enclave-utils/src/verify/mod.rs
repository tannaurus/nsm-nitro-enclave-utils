//! Implements a verifier extension trait for [AWS Nitro Enclave attestation documents](https://aws.amazon.com/blogs/compute/validating-attestation-documents-produced-by-aws-nitro-enclaves/).
//! [`AttestationDocVerifierExt`] is designed to be work with both authentic AWS-signed attestation documents and ones signed with your own PKI, with the goal of enabling a seamless transition between testing in a local development environment and remote enclave environments.
//! A client that utilizes [`AttestationDocVerifierExt`] must be made aware of the root certificate it expects to verify against.
//! When a client is expecting an authentic AWS-signed attestation document, [`AttestationDocVerifierExt`] should be provided AWS's root certificate, which can be downloaded [from their documentation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#validation-process).
//! When a client is expecting a self-signed attestation document via `nsm-nitro-enclave-utils`'s "bring your own pki" support, [`AttestationDocVerifierExt`] should be provided your root certificate, which can be generated with `nsm-nitro-enclave-utils-keygen`.

use coset::{CborSerializable, CoseSign1};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sealed::sealed;
use webpki::types::CertificateDer;
use x509_cert::{der::Decode, Certificate};

mod cert;
use crate::api::nsm::AttestationDoc;
use crate::time::Time;
use cert::ChainVerifier;

pub type VerifyError = crate::Error<ErrorKind>;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
pub enum ErrorKind {
    Cose,
    AttestationDoc,
    Verification,
    EndCertificate,
    RootCertificate,
}

#[sealed]
pub trait AttestationDocVerifierExt {
    fn from_cose(
        cose_attestation_doc: &[u8],
        root_cert: &[u8],
        time: Time,
    ) -> Result<AttestationDoc, VerifyError>;
}

/// [`AttestationDocVerifierExt`] is designed to be work with both authentic AWS-signed attestation documents and ones signed with your own PKI, with the goal of enabling a seamless transition between testing in a local development environment and remote enclave environments.
/// A client that utilizes [`AttestationDocVerifierExt`] must be made aware of the root certificate it expects to verify against.
/// When a client is expecting an authentic AWS-signed attestation document, [`AttestationDocVerifierExt`] should be provided AWS's root certificate, which can be downloaded [from their documentation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#validation-process).
/// When a client is expecting a self-signed attestation document via `nsm-nitro-enclave-utils`' "bring your own pki" support, [`AttestationDocVerifierExt`] should be provided your root certificate, which can be generated with `nsm-nitro-enclave-utils-keygen`.
///
/// #### Verification process
/// This implements the 4 steps outlined in the AWS Nitro Enclaves ["verify root" documentation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)
/// 1. Decode the CBOR object and map it to a COSE_Sign1 structure.
/// 2. Extract the attestation document from the COSE_Sign1 structure.
/// 3. Verify the certificate chain.
/// 4. Ensure that the attestation document is properly signed.
#[sealed]
impl AttestationDocVerifierExt for AttestationDoc {
    fn from_cose(
        cose_attestation_doc: &[u8],
        root_cert_der: &[u8],
        time: Time,
    ) -> Result<AttestationDoc, VerifyError> {
        let cose = CoseSign1::from_slice(cose_attestation_doc)
            .map_err(|err| VerifyError::new(ErrorKind::Cose, err))?;

        let payload = cose.payload.as_ref().ok_or(VerifyError::new(
            ErrorKind::Cose,
            crate::ErrorContext("Missing Cose payload"),
        ))?;

        let attestation_doc = AttestationDoc::from_binary(payload).map_err(|_| {
            VerifyError::new(
                ErrorKind::AttestationDoc,
                crate::ErrorContext(
                    "Failed to decode attestation doc. Cbor deserialization failed.",
                ),
            )
        })?;

        let intermediate_certs = attestation_doc
            .cabundle
            .iter()
            .map(|bytes| CertificateDer::from(bytes.as_slice()))
            .collect::<Vec<CertificateDer>>();
        let end_cert = CertificateDer::from(attestation_doc.certificate.as_slice());
        let root_cert = CertificateDer::from(root_cert_der);

        ChainVerifier::new(&root_cert, intermediate_certs, &end_cert)?.verify(time)?;

        let doc_cert = Certificate::from_der(&attestation_doc.certificate)
            .map_err(|err| VerifyError::new(ErrorKind::AttestationDoc, err))?;
        let doc_cert_pub_key = doc_cert.tbs_certificate.subject_public_key_info;

        doc_cert_pub_key
            .algorithm
            .assert_algorithm_oid(x509_cert::der::oid::db::rfc5912::ID_EC_PUBLIC_KEY)
            .map_err(|err| VerifyError::new(ErrorKind::AttestationDoc, err))?;

        let verifying_key =
            VerifyingKey::from_sec1_bytes(doc_cert_pub_key.subject_public_key.as_bytes().ok_or(
                VerifyError::new(
                    ErrorKind::AttestationDoc,
                    crate::ErrorContext("Attestation doc missing subject_public_key"),
                ),
            )?)
            .map_err(|err| VerifyError::new(ErrorKind::AttestationDoc, err))?;

        cose.verify_signature(&[], |signature, msg| {
            let signature = Signature::try_from(signature)?;
            verifying_key.verify(msg, &signature)
        })
        .map_err(|err| VerifyError::new(ErrorKind::Verification, err))?;

        Ok(attestation_doc)
    }
}

#[cfg(all(test, not(target_arch = "wasm32"), feature = "pki"))]
mod tests {
    use nsm_nitro_enclave_utils_keygen::DerEncodeExt;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::api::nsm::{AttestationDoc, Digest};
    use crate::driver::dev::sign::AttestationDocSignerExt;
    use crate::pcr::Pcrs;
    use crate::time::Time;
    use crate::verify::AttestationDocVerifierExt;

    #[test]
    fn sign_and_verify() {
        let cert_valid_until = Duration::from_secs(60 * 10);
        let cert_chain = nsm_nitro_enclave_utils_keygen::NsmCertChain::generate(cert_valid_until);

        let doc = AttestationDoc {
            module_id: "".to_string(),
            digest: Digest::SHA384,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            pcrs: Pcrs::default().into(),
            certificate: cert_chain.end_signer.cert.to_der().unwrap().into(),
            cabundle: vec![cert_chain.int.to_der().unwrap().into()],
            public_key: None,
            user_data: None,
            nonce: None,
        };

        let doc = doc.sign(cert_chain.end_signer.signing_key).unwrap();

        AttestationDoc::from_cose(&doc, &cert_chain.root.to_der().unwrap(), Time::default())
            .unwrap();
    }
}
