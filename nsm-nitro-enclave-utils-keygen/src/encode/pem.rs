//! Provides PEM encoding utilities for [`NsmCertChain`]

use crate::{Certificate, EndCertificateSigner, NsmCertChain};
use p384::ecdsa::SigningKey;
use p384::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use serde::{
    de,
    ser::{self, SerializeStruct},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt::Formatter;
use x509_cert::der::{DecodePem, EncodePem};

/// Can be used in combination with [`pem_decoder`] to serialize and deserialize an [`NsmCertChain`] with PEM encoding.
/// ```
///  use serde::{Serialize, Deserialize};
///  use nsm_nitro_enclave_utils_keygen::{NsmCertChain, encode::pem::{pem_encoder, pem_decoder}};
///  #[derive(Serialize, Deserialize)]
///  struct Example {
///     #[serde(serialize_with = "pem_encoder", deserialize_with = "pem_decoder")]
///     certs: NsmCertChain
///  }
/// ```
pub fn pem_encoder<S>(v: &NsmCertChain, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    PemNsmCertChain(v.clone()).serialize(s)
}

/// Can be used in combination with [`pem_encoder`] to serialize and deserialize an [`NsmCertChain`] with PEM encoding.
/// ```
///  use serde::{Serialize, Deserialize};
///  use nsm_nitro_enclave_utils_keygen::{NsmCertChain, encode::pem::{pem_encoder, pem_decoder}};
///  #[derive(Serialize, Deserialize)]
///  struct Example {
///     #[serde(serialize_with = "pem_encoder", deserialize_with = "pem_decoder")]
///     certs: NsmCertChain
///  }
/// ```
pub fn pem_decoder<'de, D>(deserializer: D) -> Result<NsmCertChain, D::Error>
where
    D: Deserializer<'de>,
{
    PemNsmCertChain::deserialize(deserializer).map(|decoder| decoder.0)
}

#[doc(hidden)]
/// A wrapper for [`NsmCertChain`] that serializes the inner certificates and signing key to PEM strings
pub struct PemNsmCertChain(pub NsmCertChain);

impl Serialize for PemNsmCertChain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("NsmCertChain", 3)?;

        let root_pem = self
            .0
            .root
            .to_pem(LineEnding::default())
            .map_err(|err| ser::Error::custom(err))?;
        s.serialize_field("rootCertificate", &root_pem)?;

        let int_pem = self
            .0
            .int
            .to_pem(LineEnding::default())
            .map_err(|err| ser::Error::custom(err))?;
        s.serialize_field("intCertificate", &int_pem)?;

        let end_cert_pem = self
            .0
            .end_signer
            .cert
            .to_pem(LineEnding::default())
            .map_err(|err| ser::Error::custom(err))?;
        let end_signing_key_pem = self
            .0
            .end_signer
            .signing_key
            .to_pkcs8_pem(LineEnding::default())
            .map_err(|err| ser::Error::custom(err))?;

        s.serialize_field("endCertificate", &end_cert_pem)?;
        s.serialize_field("endSigningKey", end_signing_key_pem.as_str())?;

        s.end()
    }
}
#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "camelCase")]
enum Field {
    RootCertificate,
    IntCertificate,
    EndCertificate,
    EndSigningKey,
}

impl<'de> Deserialize<'de> for PemNsmCertChain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PemEncodedNsmCertChainVisitor;

        impl<'de> de::Visitor<'de> for PemEncodedNsmCertChainVisitor {
            type Value = PemNsmCertChain;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("struct PemEncodedNsmCertChain")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut root_certificate = None;
                let mut int_certificate = None;
                let mut end_certificate = None;
                let mut end_signing_key = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::RootCertificate => {
                            if root_certificate.is_some() {
                                return Err(de::Error::duplicate_field("rootCertificate"));
                            }
                            root_certificate = Some(map.next_value().map(|s: String| {
                                Certificate::from_pem(&s).map_err(|err| de::Error::custom(err))
                            })??);
                        }
                        Field::IntCertificate => {
                            if int_certificate.is_some() {
                                return Err(de::Error::duplicate_field("intCertificate"));
                            }
                            int_certificate = Some(map.next_value().map(|s: String| {
                                Certificate::from_pem(&s).map_err(|err| de::Error::custom(err))
                            })??);
                        }
                        Field::EndCertificate => {
                            if end_certificate.is_some() {
                                return Err(de::Error::duplicate_field("endCertificate"));
                            }
                            end_certificate = Some(map.next_value().map(|s: String| {
                                Certificate::from_pem(&s).map_err(|err| de::Error::custom(err))
                            })??);
                        }
                        Field::EndSigningKey => {
                            if end_signing_key.is_some() {
                                return Err(de::Error::duplicate_field("endSigningKey"));
                            }
                            end_signing_key = Some(map.next_value().map(|s: String| {
                                SigningKey::from_pkcs8_pem(&s).map_err(|err| de::Error::custom(err))
                            })??);
                        }
                    }
                }

                let root_certificate =
                    root_certificate.ok_or_else(|| de::Error::missing_field("rootCertificate"))?;
                let int_certificate =
                    int_certificate.ok_or_else(|| de::Error::missing_field("intCertificate"))?;
                let end_certificate =
                    end_certificate.ok_or_else(|| de::Error::missing_field("endCertificate"))?;
                let end_signing_key =
                    end_signing_key.ok_or_else(|| de::Error::missing_field("endSigningKey"))?;

                Ok(PemNsmCertChain(NsmCertChain {
                    root: root_certificate,
                    int: int_certificate,
                    end_signer: EndCertificateSigner {
                        cert: end_certificate,
                        signing_key: end_signing_key,
                    },
                }))
            }
        }

        const FIELDS: &[&str] = &[
            "rootCertificate",
            "intCertificate",
            "endCertificate",
            "endSigningKey",
        ];
        deserializer.deserialize_struct(
            "DerEncodedNsmCertChain",
            FIELDS,
            PemEncodedNsmCertChainVisitor,
        )
    }
}

#[cfg(test)]
mod test {
    use super::{pem_decoder, pem_encoder, PemNsmCertChain};
    use crate::NsmCertChain;
    use serde::{Deserialize, Serialize};
    use std::sync::LazyLock;
    use std::time::Duration;

    static CERT_CHAIN: LazyLock<NsmCertChain> =
        LazyLock::new(|| NsmCertChain::generate(Duration::from_secs(1)));

    #[test]
    fn pem_encode_decode() {
        let pem = serde_json::to_string(&PemNsmCertChain(CERT_CHAIN.clone())).unwrap();
        println!("{}", pem);
        let _certs: PemNsmCertChain = serde_json::from_str(&pem).unwrap();
    }

    #[test]
    fn der_serialize_deserialize_with() {
        #[derive(Serialize, Deserialize)]
        struct Example {
            #[serde(serialize_with = "pem_encoder", deserialize_with = "pem_decoder")]
            certs: NsmCertChain,
        }

        let example = Example {
            certs: CERT_CHAIN.clone(),
        };

        let json = serde_json::to_string(&example).unwrap();

        let _example: Example = serde_json::from_str(&json).unwrap();
    }
}
