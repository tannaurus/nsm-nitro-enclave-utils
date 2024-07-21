use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use coset::{iana::Algorithm, CborSerializable, CoseSign1Builder, HeaderBuilder};
use p384::ecdsa::{signature::Signer, Signature, SigningKey};
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
