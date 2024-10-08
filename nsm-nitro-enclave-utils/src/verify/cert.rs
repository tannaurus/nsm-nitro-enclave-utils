use crate::time::GetTimestamp;
use std::time::Duration;
use webpki::{
    anchor_from_trusted_cert,
    types::{CertificateDer, TrustAnchor, UnixTime},
    EndEntityCert, KeyUsage,
};

use super::{VerifierError, VerifierErrorKind};

#[must_use = "ChainVerifier must be verified"]
pub(crate) struct ChainVerifier<'a> {
    root_cert: TrustAnchor<'a>,
    int_certs: Vec<CertificateDer<'a>>,
    end_cert: EndEntityCert<'a>,
}

impl<'a> ChainVerifier<'a> {
    pub(crate) fn new(
        root_cert: &'a CertificateDer,
        int_certs: &'a [&[u8]],
        end_cert: &'a CertificateDer,
    ) -> Result<Self, VerifierError> {
        let end_cert = EndEntityCert::try_from(end_cert)
            .map_err(|err| VerifierError::new(VerifierErrorKind::InvalidEndCertificate, err))?;
        let int_certs = int_certs
            .iter()
            .map(|cert| CertificateDer::from(*cert))
            .collect();
        let root_cert = anchor_from_trusted_cert(root_cert)
            .map_err(|err| VerifierError::new(VerifierErrorKind::InvalidRootCertificate, err))?;

        Ok(Self {
            root_cert,
            int_certs,
            end_cert,
        })
    }

    /// Verifies the certificate chain
    /// AWS's documentation explicitly requires ["CRL must be disabled when doing the validation"](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html#chain)
    pub(crate) fn verify(self, get_time: GetTimestamp) -> Result<(), VerifierError> {
        self.end_cert
            .verify_for_usage(
                &[webpki::ring::ECDSA_P384_SHA384],
                &[self.root_cert],
                &self.int_certs,
                UnixTime::since_unix_epoch(Duration::from_millis(get_time.time())),
                KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(|err| VerifierError::new(VerifierErrorKind::Verification, err))?;

        Ok(())
    }
}
