//! A collection of test utility functions.
//! Functions declared here are allowed to panic.

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
    Certificate,
};
pub(crate) fn build_cert(
    profile: Profile,
    signing_key: SigningKey,
    public_key: VerifyingKey,
    valid_until: Duration,
) -> Certificate {
    let cert = CertificateBuilder::new(
        profile.clone(),
        SerialNumber::new(&[1]).unwrap(),
        Validity::from_now(valid_until).unwrap(),
        Name::default(),
        SubjectPublicKeyInfo::from_key(public_key).unwrap(),
        &signing_key,
    )
    .unwrap()
    .build::<DerSignature>()
    .unwrap();

    cert
}

pub(crate) fn generate_key() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::try_from(SecretKey::random(&mut rand::thread_rng())).unwrap();
    let verifying_key = VerifyingKey::from(signing_key.clone());
    (signing_key, verifying_key)
}
