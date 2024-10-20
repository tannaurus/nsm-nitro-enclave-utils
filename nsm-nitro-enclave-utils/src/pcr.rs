//! Contains a collection of utilities for working with [Platform Configuration Registers (PCRs)](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#where).
//! The primary goal here is to achieve stronger type safety when working with PCRs, as well as provide abstractions to generate [`Pcrs`] that you can use when self-signing your own attestation documents.
//!
//! [`Pcr`] wraps a single Platform Configuration Register, allowing for stronger type safety across your application.
//! [`Pcrs`] wraps all 6 Platform Configuration Registers returned by the Nitro Secure Module. Each can be infallibly accessed via [`Pcrs::get`].
//! [`Pcrs`] also provides several methods that allow you to initial a collection of Platform Configuration Registers when self-signing attestation documents, some of which require additional feature flags.

use crate::ErrorContext;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use std::ops::Deref;

/// A [`Pcr`] failed to pass length checks.
pub type PcrLengthError = crate::Error<()>;

/// [`Pcrs`] included an [invalid index](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#where)
pub type PcrIndexError = crate::Error<()>;

/// The Nitro Secure Module returns PCRs 0 through 8, with some missing.
/// https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#where
pub(crate) const PCR_INDEXES: [PcrIndex; 6] = [
    PcrIndex::Zero,
    PcrIndex::One,
    PcrIndex::Two,
    PcrIndex::Three,
    PcrIndex::Four,
    PcrIndex::Eight,
];

/// An enum that corresponds to the valid PCR indexes. Used to ensure PCR related operations that are infallible can remain infallible.
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum PcrIndex {
    Zero,
    One,
    Two,
    Three,
    Four,
    Eight,
}

impl From<PcrIndex> for usize {
    fn from(index: PcrIndex) -> Self {
        match index {
            PcrIndex::Zero => 0,
            PcrIndex::One => 1,
            PcrIndex::Two => 2,
            PcrIndex::Three => 3,
            PcrIndex::Four => 4,
            PcrIndex::Eight => 8,
        }
    }
}

impl TryFrom<usize> for PcrIndex {
    type Error = PcrIndexError;

    fn try_from(index: usize) -> Result<Self, Self::Error> {
        match index {
            0 => Ok(PcrIndex::Zero),
            1 => Ok(PcrIndex::One),
            2 => Ok(PcrIndex::Two),
            3 => Ok(PcrIndex::Three),
            4 => Ok(PcrIndex::Four),
            8 => Ok(PcrIndex::Eight),
            _ => Err(PcrIndexError::new(
                (),
                ErrorContext("Invalid PCR index provided"),
            )),
        }
    }
}

/// Sha384 hashes contain 48 bytes
const PCR_LENGTH: usize = 48;

/// Platform Configuration Register
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pcr([u8; PCR_LENGTH]);

impl Deref for Pcr {
    type Target = [u8; PCR_LENGTH];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for Pcr {
    type Error = PcrLengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let inner = value.try_into().map_err(|_| {
            PcrLengthError::new((), ErrorContext("A PCR must have a length of 48."))
        })?;

        Ok(Self(inner))
    }
}

impl From<[u8; PCR_LENGTH]> for Pcr {
    fn from(inner: [u8; PCR_LENGTH]) -> Self {
        Self(inner)
    }
}

/// A complete list of [`Pcr`]s
#[derive(Clone, PartialEq, Debug)]
pub struct Pcrs(BTreeMap<PcrIndex, Pcr>);

impl Default for Pcrs {
    fn default() -> Self {
        Pcrs::zeros()
    }
}

impl Pcrs {
    /// Creates a new `Pcrs` but calling a `Fn` for each index
    fn from_fn<F>(func: F) -> Self
    where
        F: Fn(PcrIndex) -> Pcr,
    {
        let mut pcrs = BTreeMap::new();
        for index in PCR_INDEXES {
            pcrs.insert(index, func(index));
        }
        Self(pcrs)
    }
}

/// Useful if you have pre-generated PCRs you wish to mock.
/// If you don't already have PCRs, you should probably use [`Pcrs`]'s methods to generate what you need.
/// If a given [`PcrIndex`] is omitted in the BTreeMap, it will be replaced with all zeros.
impl From<BTreeMap<PcrIndex, Pcr>> for Pcrs {
    fn from(values: BTreeMap<PcrIndex, Pcr>) -> Self {
        let mut pcrs = Pcrs::zeros();
        for (index, pcr) in values {
            pcrs.set(index, pcr);
        }

        pcrs
    }
}

/// [`aws_nitro_enclaves_nsm_api::api::AttestationDoc`] stores PCRs as a BTreeMap.
impl Into<BTreeMap<usize, ByteBuf>> for Pcrs {
    fn into(self) -> BTreeMap<usize, ByteBuf> {
        let mut map = BTreeMap::new();
        for (index, value) in self.0.into_iter() {
            map.insert(index.into(), ByteBuf::from(*value));
        }

        map
    }
}

/// Generators
impl Pcrs {
    /// All PCRs will be zeros
    /// Example: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    pub fn zeros() -> Self {
        Pcrs::from_fn(|_| [0; PCR_LENGTH].into())
    }

    #[cfg(feature = "rand")]
    /// All PCRs will be randomly generated to mimic SHA386 hashes
    pub fn rand() -> Self {
        use rand::{distributions::Alphanumeric, Rng};
        Pcrs::from_fn(|_| {
            let bytes = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(PCR_LENGTH)
                .collect::<Vec<u8>>();
            Pcr::try_from(bytes).expect("rand must produce valid Pcr")
        })
    }

    #[cfg(feature = "seed")]
    /// All PCRs will be seeded from the provided strings. Each string gets hashed with SHA386.
    /// If a given [`PcrIndex`] is omitted in the BTreeMap, it will be replaced with all zeros.
    pub fn seed(values: BTreeMap<PcrIndex, String>) -> Self {
        use p384::ecdsa::signature::digest::Digest;

        let mut pcrs = Pcrs::zeros();
        for (index, seed) in values {
            let mut hasher = sha2::Sha384::new();
            hasher.update(seed.as_bytes());
            let pcr = hasher
                .finalize()
                .to_vec()
                .try_into()
                .expect("Pcr should accept any Sha384");
            pcrs.set(index, pcr);
        }

        pcrs
    }
}

/// Getters and setters
impl Pcrs {
    pub fn get(&self, index: PcrIndex) -> &Pcr {
        self.0
            .get(&index)
            // The Pcrs api is designed to prevent this from happening.
            .expect("Pcrs were created with invalid indexes")
    }

    pub fn set(&mut self, index: PcrIndex, pcr: Pcr) {
        self.0.insert(index, pcr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_all_zeros(pcrs: Pcrs) {
        let all_zeros = pcrs
            .0
            .into_iter()
            .all(|(_, pcr)| pcr.iter().all(|b| b == &0));
        assert!(all_zeros);
    }

    #[test]
    fn pcrs_defaults_to_zero() {
        let pcrs = Pcrs::default();
        is_all_zeros(pcrs);
    }

    #[test]
    fn pcrs_zeros_is_zeros() {
        let pcrs = Pcrs::zeros();
        is_all_zeros(pcrs);
    }

    #[test]
    fn pcr_string_must_be_96_chars() {
        let too_short = vec![0; PCR_LENGTH - 1];
        Pcr::try_from(too_short).unwrap_err();

        let too_long = vec![0; PCR_LENGTH + 1];
        Pcr::try_from(too_long).unwrap_err();

        let just_right = vec![0; PCR_LENGTH];
        assert!(Pcr::try_from(just_right).is_ok());
    }

    #[test]
    fn reliable_b_tree_map() {
        let pcrs = Pcrs::zeros();
        let map: BTreeMap<usize, ByteBuf> = pcrs.into();
        for index in PCR_INDEXES {
            assert!(map.get(&index.into()).is_some());
        }

        assert!(map.get(&(8 + 1)).is_none());
    }

    #[cfg(feature = "rand")]
    #[test]
    fn rand() {
        let a = Pcrs::rand();
        let b = Pcrs::rand();
        assert_ne!(a, b);
    }

    #[cfg(feature = "seed")]
    #[test]
    fn seed_is_deterministic() {
        let mut seed = BTreeMap::new();
        for index in PCR_INDEXES {
            seed.insert(index.into(), usize::from(index).to_string());
        }
        let a = Pcrs::seed(seed.clone());
        let b = Pcrs::seed(seed);
        assert_eq!(a, b);

        let mut alt_seed = BTreeMap::new();
        for index in PCR_INDEXES {
            alt_seed.insert(index.into(), (usize::from(index) + 1).to_string());
        }
        let c = Pcrs::seed(alt_seed);
        assert_ne!(a, c);
    }
}
