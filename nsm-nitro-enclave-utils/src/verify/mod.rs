use coset::{CborSerializable, CoseSign1};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sealed::sealed;
use webpki::types::CertificateDer;
use x509_cert::{der::Decode, Certificate};

mod cert;
use crate::api::nsm::AttestationDoc;
use crate::time::GetTimestamp;
use cert::ChainVerifier;

/// Captures errors that can occur during attestation document verification.
/// `kind` is a high-level categorization of the error that is defined by the library.
/// `source` is the underlying error that caused the failure. When possible, the source is the error that was returned by the underlying library.
/// If the error returned from the underlying library does not implement [`std::error::Error`], or the error originated due to this library's own assertions, [`ErrorContext`] is used.
#[derive(Debug)]
pub struct VerifierError {
    kind: VerifierErrorKind,
    _backtrace: std::backtrace::Backtrace,
    _source: Box<dyn std::error::Error + Send + Sync>,
}

impl VerifierError {
    fn new<E>(kind: VerifierErrorKind, err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind,
            _backtrace: std::backtrace::Backtrace::capture(),
            _source: Box::new(err),
        }
    }

    pub fn kind(&self) -> &VerifierErrorKind {
        &self.kind
    }
}

/// Used by errors to provide additional context if the error returned from the underlying library does not implement [`std::error::Error`],
/// or the error originated due to this library's own assertions.
#[derive(Debug, PartialEq, Eq, Clone, Hash, PartialOrd, Ord)]
struct ErrorContext(String);

impl std::fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ErrorContext {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
pub enum VerifierErrorKind {
    InvalidEndCertificate,
    InvalidRootCertificate,
    InvalidCose,
    InvalidAttestationDoc,
    Verification,
}

#[sealed]
pub trait AttestationDocVerifierExt {
    fn from_cose(
        cose_attestation_doc: &[u8],
        root_cert: &[u8],
        time: GetTimestamp,
    ) -> Result<AttestationDoc, VerifierError>;
}

/// This implementation implements the 4 steps outlined in the AWS Nitro Enclaves ["verify root" documentation](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)
/// 1. Decode the CBOR object and map it to a COSE_Sign1 structure.
/// 2. Extract the attestation document from the COSE_Sign1 structure.
/// 3. Verify the certificate's chain.
/// 4. Ensure that the attestation document is properly signed.
#[sealed]
impl AttestationDocVerifierExt for AttestationDoc {
    fn from_cose(
        cose_attestation_doc: &[u8],
        root_cert: &[u8],
        time: GetTimestamp,
    ) -> Result<AttestationDoc, VerifierError> {
        let cose = CoseSign1::from_slice(cose_attestation_doc).map_err(|err| {
            VerifierError::new(
                VerifierErrorKind::InvalidCose,
                ErrorContext(format!("Failed to decode COSE: {:?}", err)),
            )
        })?;

        let payload = cose.payload.as_ref().ok_or(VerifierError::new(
            VerifierErrorKind::InvalidCose,
            ErrorContext("Missing Cose payload".into()),
        ))?;

        let attestation_doc = AttestationDoc::from_binary(payload).map_err(|err| {
            VerifierError::new(
                VerifierErrorKind::InvalidAttestationDoc,
                ErrorContext(format!("Failed to decode attestation doc: {:?}", err)),
            )
        })?;

        let intermediate_certs = attestation_doc
            .cabundle
            .iter()
            .map(|bytes| bytes.as_slice())
            .collect::<Vec<&[u8]>>();
        let end_cert = CertificateDer::from(attestation_doc.certificate.as_slice());
        let root_cert = CertificateDer::from(root_cert);

        ChainVerifier::new(&root_cert, &intermediate_certs, &end_cert)?.verify(time)?;

        let doc_cert = Certificate::from_der(&attestation_doc.certificate)
            .map_err(|err| VerifierError::new(VerifierErrorKind::InvalidAttestationDoc, err))?;
        let doc_cert_pub_key = doc_cert.tbs_certificate.subject_public_key_info;

        doc_cert_pub_key
            .algorithm
            .assert_algorithm_oid(x509_cert::der::oid::db::rfc5912::ID_EC_PUBLIC_KEY)
            .map_err(|err| VerifierError::new(VerifierErrorKind::InvalidAttestationDoc, err))?;

        let verifying_key =
            VerifyingKey::from_sec1_bytes(doc_cert_pub_key.subject_public_key.as_bytes().ok_or(
                VerifierError::new(
                    VerifierErrorKind::InvalidAttestationDoc,
                    ErrorContext("Attestation doc missing subject_public_key".into()),
                ),
            )?)
            .map_err(|err| VerifierError::new(VerifierErrorKind::InvalidAttestationDoc, err))?;

        cose.verify_signature(&[], |signature, msg| {
            let signature = Signature::try_from(signature)?;
            verifying_key.verify(msg, &signature)
        })
        .map_err(|err| VerifierError::new(VerifierErrorKind::Verification, err))?;

        Ok(attestation_doc)
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    use crate::time::GetTimestamp;

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

        AttestationDoc::from_cose(&doc, &root_cert.to_der().unwrap(), GetTimestamp::default())
            .unwrap();
    }
}
