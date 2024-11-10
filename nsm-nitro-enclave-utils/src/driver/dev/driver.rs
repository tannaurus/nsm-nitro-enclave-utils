use crate::api::{
    nsm::{AttestationDoc, ErrorCode, Request, Response},
    ByteBuf, SecretKey,
};
use crate::driver::dev::sign::AttestationDocSignerExt;
use crate::driver::Driver;
use crate::pcr::Pcrs;
use crate::time::Time;
use p384::ecdsa::SigningKey;

/// [`DevNitro`] mimics requests to the Nitro Secure Model, allowing you to build features for AWS Nitro Enclaves, without AWS Nitro Enclaves.
pub struct DevNitro {
    ca_bundle: Vec<ByteBuf>,
    signing_key: SigningKey,
    end_cert: ByteBuf,
    pcrs: Pcrs,
    get_timestamp: Time,
}

impl Driver for DevNitro {
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

impl DevNitro {
    /// `signing_key`: used to sign the attestation document
    /// `end_cert` a der encoded x509 certificate. Should contain `signing_key`'s public key.
    pub fn builder(signing_key: SecretKey, end_cert: ByteBuf) -> DevNitroBuilder {
        DevNitroBuilder {
            signing_key: signing_key.into(),
            end_cert,
            ca_bundle: None,
            pcrs: Pcrs::default(),
            get_timestamp: Time::system_time(),
        }
    }

    fn describe_pcr(&self, index: u16) -> Response {
        let index = usize::from(index);
        match index.try_into() {
            Ok(index) => {
                let pcr = self.pcrs.get(index);
                Response::DescribePCR {
                    lock: true,
                    data: pcr.to_vec(),
                }
            }
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
            module_id: "unsecure-development-attestation-document".to_string(),
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

/// A builder for [`DevNitro`]
pub struct DevNitroBuilder {
    signing_key: SigningKey,
    end_cert: ByteBuf,
    ca_bundle: Option<Vec<ByteBuf>>,
    pcrs: Pcrs,
    get_timestamp: Time,
}

impl DevNitroBuilder {
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

    /// Builds a new [`DevNitro`] to processes the requests
    pub fn build(self) -> DevNitro {
        DevNitro {
            signing_key: self.signing_key,
            end_cert: self.end_cert,
            ca_bundle: self.ca_bundle.unwrap_or_default(),
            pcrs: self.pcrs,
            get_timestamp: self.get_timestamp,
        }
    }
}
