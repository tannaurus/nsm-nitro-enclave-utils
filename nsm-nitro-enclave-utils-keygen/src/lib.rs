//! A small collection of utilities used to generated [`NsmCertChain`], which is used by [nsm-nitro-enclave-utils](https://crates.io/crates/nsm-nitro-enclave-utils) to self-sign attestation documents in local development environments.

pub mod encode;

use p384::{
    ecdsa::{DerSignature, SigningKey, VerifyingKey},
    SecretKey,
};
use std::time::Duration;
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    name::Name,
    serial_number::SerialNumber,
    spki::SubjectPublicKeyInfo,
    time::Validity,
};

pub use x509_cert::{
    der::{Decode as DerDecodeExt, Encode as DerEncodeExt, EncodePem as PemEncodeExt},
    Certificate,
};

/// A bundle that comprises every certificate (and an end signing key) that is used by [nsm-nitro-enclave-utils](https://crates.io/crates/nsm-nitro-enclave-utils) to self-sign attestation documents in local development environments.
#[derive(Clone)]
pub struct NsmCertChain {
    pub root: Certificate,
    pub int: Certificate,
    pub end_signer: EndCertificateSigner,
}

/// Contains the end certificate and its associated signing key
#[derive(Clone)]
pub struct EndCertificateSigner {
    pub cert: Certificate,
    pub signing_key: SigningKey,
}

impl NsmCertChain {
    /// Generates an [`NsmCertChain`] that is valid until the specified [`Duration`].
    ///
    /// These functions are not designed to be called inside a server and can theoretically panic, though that isn't expected behavior.
    pub fn generate(valid_until: Duration) -> Self {
        let (root_signing_key, root_public_key) = generate_key();
        let root_cert = build_cert(
            Profile::Root,
            root_signing_key.clone(),
            root_public_key,
            valid_until,
        );

        let (int_key, int_public_key) = generate_key();
        let int_cert = build_cert(
            Profile::SubCA {
                issuer: Default::default(),
                path_len_constraint: None,
            },
            root_signing_key,
            int_public_key,
            valid_until,
        );

        let (end_signing_key, end_public_key) = generate_key();
        let end_cert = build_cert(
            Profile::Leaf {
                issuer: Default::default(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            int_key,
            end_public_key,
            valid_until,
        );

        Self {
            root: root_cert,
            int: int_cert,
            end_signer: EndCertificateSigner {
                cert: end_cert,
                signing_key: end_signing_key,
            },
        }
    }
}

fn build_cert(
    profile: Profile,
    signing_key: SigningKey,
    public_key: VerifyingKey,
    valid_until: Duration,
) -> Certificate {
    let cert = CertificateBuilder::new(
        profile.clone(),
        SerialNumber::new(&[1]).expect("SerialNumber"),
        Validity::from_now(valid_until).expect("Validity"),
        Name::default(),
        SubjectPublicKeyInfo::from_key(public_key).expect("SubjectPublicKeyInfo"),
        &signing_key,
    )
    .unwrap()
    .build::<DerSignature>()
    .unwrap();

    cert
}

fn generate_key() -> (SigningKey, VerifyingKey) {
    let signing_key =
        SigningKey::try_from(SecretKey::random(&mut rand::thread_rng())).expect("SigningKey");
    let verifying_key = VerifyingKey::from(signing_key.clone());
    (signing_key, verifying_key)
}

#[cfg(test)]
mod test {
    use crate::NsmCertChain;
    use std::time::Duration;

    #[test]
    fn generate_chain() {
        let until = Duration::from_secs(0);
        NsmCertChain::generate(until);
    }
}
