use std::time::Duration;
use webpki::{
    anchor_from_trusted_cert, CertRevocationList, EndEntityCert, ExpirationPolicy, KeyUsage,
    RevocationCheckDepth, RevocationOptionsBuilder, UnknownStatusPolicy, types::{CertificateDer, TrustAnchor, UnixTime}
};

#[must_use = "ChainVerifier must be verified"]
pub(crate) struct ChainVerifier<'a> {
    trust_anchor: TrustAnchor<'a>,
    int_certs: Vec<CertificateDer<'a>>,
    end_cert: EndEntityCert<'a>,
}

impl<'a> ChainVerifier<'a> {
    pub(crate) fn new(
        trust_anchor: &'a CertificateDer,
        int_certs: &'a [&[u8]],
        end_cert: &'a CertificateDer,
    ) -> Result<Self, &'static str> {
        let end_cert =
            EndEntityCert::try_from(end_cert).map_err(|_| "Failed to parse EndEntityCert")?;
        let int_certs = int_certs
            .iter()
            .map(|cert| CertificateDer::from(*cert))
            .collect();
        let trust_anchor =
            anchor_from_trusted_cert(&trust_anchor).map_err(|_| "Failed to parse TrustAnchor")?;

        Ok(Self {
            trust_anchor,
            int_certs,
            end_cert,
        })
    }

    pub(crate) fn verify(
        self,
        time: u64,
        crls: Option<&[&CertRevocationList]>,
    ) -> Result<(), &'static str> {
        let revocation_options = crls
            .map(|crls| {
                Ok(RevocationOptionsBuilder::new(crls)
                    .map_err(|_| "Failed to create revocation builder")?
                    .with_expiration_policy(ExpirationPolicy::Enforce)
                    .with_depth(RevocationCheckDepth::Chain)
                    .with_status_policy(UnknownStatusPolicy::Deny)
                    .build())
            })
            .transpose()?;

        self.end_cert
            .verify_for_usage(
                &[webpki::ring::ECDSA_P384_SHA384],
                &[self.trust_anchor],
                &self.int_certs,
                UnixTime::since_unix_epoch(Duration::from_secs(time)),
                KeyUsage::server_auth(),
                revocation_options,
                None,
            )
            .unwrap();

        Ok(())
    }
}
