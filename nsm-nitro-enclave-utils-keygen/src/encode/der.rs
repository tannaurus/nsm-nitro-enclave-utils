//! Provides DER encoding utilities for [`NsmCertChain`]

use p384::ecdsa::SigningKey;
use p384::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use serde::{
    de,
    ser::{self, SerializeStruct},
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_bytes::ByteBuf;
use std::fmt::Formatter;

use crate::{Certificate, DerDecodeExt, DerEncodeExt, EndCertificateSigner, NsmCertChain};

/// Can be used in combination with [`der_decoder`] to serialize and deserialize an [`NsmCertChain`] with DER encoding.
/// ```
///  use serde::{Serialize, Deserialize};
///  use nsm_nitro_enclave_utils_keygen::{NsmCertChain, encode::der::{der_encoder, der_decoder}};
///  #[derive(Serialize, Deserialize)]
///  struct Example {
///     #[serde(serialize_with = "der_encoder", deserialize_with = "der_decoder")]
///     certs: NsmCertChain
///  }
/// ```
pub fn der_encoder<S>(v: &NsmCertChain, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    DerNsmCertChain(v.clone()).serialize(s)
}

/// Can be used in combination with [`der_encoder`] to serialize and deserialize an [`NsmCertChain`] with DER encoding.
/// ```
///  use serde::{Serialize, Deserialize};
///  use nsm_nitro_enclave_utils_keygen::{NsmCertChain, encode::der::{der_encoder, der_decoder}};
///  #[derive(Serialize, Deserialize)]
///  struct Example {
///     #[serde(serialize_with = "der_encoder", deserialize_with = "der_decoder")]
///     certs: NsmCertChain
///  }
/// ```
pub fn der_decoder<'de, D>(deserializer: D) -> Result<NsmCertChain, D::Error>
where
    D: Deserializer<'de>,
{
    DerNsmCertChain::deserialize(deserializer).map(|decoder| decoder.0)
}

#[doc(hidden)]
/// A wrapper for [`NsmCertChain`] that serializes the inner certificates and signing key to DER bytes
pub struct DerNsmCertChain(pub NsmCertChain);

impl Serialize for DerNsmCertChain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("NsmCertChain", 3)?;

        let root_der = ByteBuf::from(
            self.0
                .root
                .to_der()
                .map_err(|err| ser::Error::custom(err))?,
        );
        s.serialize_field("rootCertificate", &root_der)?;

        let int_der = ByteBuf::from(self.0.int.to_der().map_err(|err| ser::Error::custom(err))?);
        s.serialize_field("intCertificate", &int_der)?;

        let end_cert_der = ByteBuf::from(
            self.0
                .end_signer
                .cert
                .to_der()
                .map_err(|err| ser::Error::custom(err))?,
        );
        let end_signing_key_der = ByteBuf::from(
            self.0
                .end_signer
                .signing_key
                .to_pkcs8_der()
                .map_err(|err| ser::Error::custom(err))?
                .as_bytes(),
        );

        s.serialize_field("endCertificate", &end_cert_der)?;
        s.serialize_field("endSigningKey", &end_signing_key_der)?;

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

impl<'de> Deserialize<'de> for DerNsmCertChain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DerEncodedNsmCertChainVisitor;

        impl<'de> de::Visitor<'de> for DerEncodedNsmCertChainVisitor {
            type Value = DerNsmCertChain;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("struct DerEncodedNsmCertChain")
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
                            root_certificate =
                                Some(map.next_value().map(|bytes: Vec<u8>| {
                                    Certificate::from_der(&bytes)
                                        .map_err(|err| de::Error::custom(err))
                                })??);
                        }
                        Field::IntCertificate => {
                            if int_certificate.is_some() {
                                return Err(de::Error::duplicate_field("intCertificate"));
                            }
                            int_certificate = Some(map.next_value().map(|bytes: Vec<u8>| {
                                Certificate::from_der(&bytes).map_err(|err| de::Error::custom(err))
                            })??);
                        }
                        Field::EndCertificate => {
                            if end_certificate.is_some() {
                                return Err(de::Error::duplicate_field("endCertificate"));
                            }
                            end_certificate = Some(map.next_value().map(|bytes: Vec<u8>| {
                                Certificate::from_der(&bytes).map_err(|err| de::Error::custom(err))
                            })??);
                        }
                        Field::EndSigningKey => {
                            if end_signing_key.is_some() {
                                return Err(de::Error::duplicate_field("endSigningKey"));
                            }
                            end_signing_key = Some(map.next_value().map(|bytes: Vec<u8>| {
                                SigningKey::from_pkcs8_der(&bytes)
                                    .map_err(|err| de::Error::custom(err))
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

                Ok(DerNsmCertChain(NsmCertChain {
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
            DerEncodedNsmCertChainVisitor,
        )
    }
}

#[cfg(test)]
mod test {
    use super::{der_decoder, der_encoder, DerNsmCertChain};
    use crate::NsmCertChain;
    use serde::{Deserialize, Serialize};
    use std::sync::LazyLock;
    use std::time::Duration;

    static CERT_CHAIN: LazyLock<NsmCertChain> =
        LazyLock::new(|| NsmCertChain::generate(Duration::from_secs(1)));

    #[test]
    fn der_encode_decode() {
        let der = serde_json::to_string(&DerNsmCertChain(CERT_CHAIN.clone())).unwrap();
        println!("{}", der);
        let _certs: DerNsmCertChain = serde_json::from_str(&der).unwrap();
    }

    #[test]
    fn der_serialize_deserialize_with() {
        #[derive(Serialize, Deserialize)]
        struct Example {
            #[serde(serialize_with = "der_encoder", deserialize_with = "der_decoder")]
            certs: NsmCertChain,
        }

        let example = Example {
            certs: CERT_CHAIN.clone(),
        };

        let json = serde_json::to_string(&example).unwrap();

        let _example: Example = serde_json::from_str(&json).unwrap();
    }
}
