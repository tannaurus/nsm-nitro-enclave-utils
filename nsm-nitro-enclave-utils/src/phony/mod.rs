use crate::{
    api::{
        nsm::{AttestationDoc, ErrorCode, Request, Response},
        ByteBuf, SecretKey,
    },
    AttestationDocSignerExt, Driver, Nsm,
};
use p384::ecdsa::SigningKey;

mod pcrs;

pub use pcrs::*;
mod time;
pub use time::*;

struct Phony {
    signing_key: SigningKey,
    end_cert: ByteBuf,
    ca_bundle: Vec<ByteBuf>,
    pcrs: Pcrs,
    get_timestamp: GetTimestamp,
}

impl Driver for Phony {
    fn process_request(&self, request: Request) -> Response {
        match request {
            Request::DescribePCR { index } => self.describe_pcr(index),
            Request::Attestation {
                user_data,
                nonce,
                public_key,
            } => self.attestation(user_data, nonce, public_key),
            _ => Response::Error(ErrorCode::InvalidOperation),
        }
    }
}

impl Phony {
    fn describe_pcr(&self, index: u16) -> Response {
        match self.pcrs.checked_get(index.into()) {
            Ok(pcr) => Response::DescribePCR {
                lock: true,
                data: pcr.to_vec(),
            },
            Err(_) => Response::Error(ErrorCode::InvalidIndex),
        }
    }

    fn attestation(
        &self,
        user_data: Option<ByteBuf>,
        nonce: Option<ByteBuf>,
        public_key: Option<ByteBuf>,
    ) -> Response {
        let doc = AttestationDoc {
            module_id: "property-of-nsm-halcyon".to_string(),
            digest: aws_nitro_enclaves_nsm_api::api::Digest::SHA384,
            timestamp: self.get_timestamp.time(),
            pcrs: self.pcrs.clone().into(),
            certificate: self.end_cert.clone(),
            cabundle: self.ca_bundle.clone(),
            user_data,
            nonce,
            public_key,
        };

        if let Ok(document) = doc.sign(self.signing_key.clone()) {
            return Response::Attestation { document };
        }

        Response::Error(ErrorCode::InternalError)
    }
}

/// A builder for [`Phony`]
pub struct PhonyBuilder {
    signing_key: SigningKey,
    end_cert: ByteBuf,
    ca_bundle: Option<Vec<ByteBuf>>,
    pcrs: Pcrs,
    get_timestamp: GetTimestamp,
}

impl PhonyBuilder {
    /// `signing_key`: used to sign the attestation document
    /// `end_cert` a der encoded x509 certificate. Should contain `signing_key`'s public key.
    /// `get_timestamp` must return UTC time when document was created expressed as milliseconds since Unix Epoch
    pub(crate) fn new(
        signing_key: SecretKey,
        end_cert: ByteBuf,
        get_timestamp: GetTimestamp,
    ) -> Self {
        Self {
            signing_key: signing_key.into(),
            end_cert,
            ca_bundle: None,
            pcrs: Pcrs::default(),
            get_timestamp,
        }
    }

    /// Set the attestation document's ca_bundle.
    /// `ca_bundle` should be a list of der encoded intermediate certificates.
    pub fn ca_bundle(self, ca_bundle: Vec<ByteBuf>) -> Self {
        Self {
            ca_bundle: Some(ca_bundle),
            ..self
        }
    }

    /// Set attestation document's PCRs
    pub fn pcrs(self, pcrs: Pcrs) -> Self {
        Self { pcrs, ..self }
    }

    /// Create an [`Nsm`] where [`Phony`] processes the requests
    pub fn build(self) -> Nsm {
        Nsm {
            driver: Box::new(Phony {
                signing_key: self.signing_key,
                end_cert: self.end_cert,
                ca_bundle: self.ca_bundle.unwrap_or(Vec::new()),
                pcrs: self.pcrs,
                get_timestamp: self.get_timestamp,
            }),
        }
    }
}
