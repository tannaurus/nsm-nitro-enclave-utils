use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use std::ops::Deref;

/// The Nitro Secure Module returns PCRs 0 through 8, with some missing.
/// https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#where
pub(crate) const PCR_INDEXES: [usize; 6] = [0, 1, 2, 3, 4, 8];
/// Sha384 hashes contain 48 bytes
const PCR_LENGTH: usize = 48;

/// Platform Configuration Register
#[derive(Clone, PartialEq, Debug)]
pub(crate) struct Pcr(ByteBuf);

impl Deref for Pcr {
    type Target = ByteBuf;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Into<ByteBuf> for Pcr {
    fn into(self) -> ByteBuf {
        self.0
    }
}

impl TryFrom<Vec<u8>> for Pcr {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != PCR_LENGTH {
            return Err("PCR must be contain 48 bytes.");
        }

        Ok(Self(ByteBuf::from(value)))
    }
}

/// A complete list of [`Pcr`]s
#[derive(Clone, PartialEq, Debug)]
pub struct Pcrs(pub(crate) BTreeMap<usize, Pcr>);

impl Default for Pcrs {
    fn default() -> Self {
        Pcrs::zeros()
    }
}

impl Pcrs {
    /// Creates a new `Pcrs` but calling a `Fn` for each index
    fn from_fn<F>(func: F) -> Self
    where
        F: Fn(usize) -> Pcr,
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
impl TryFrom<BTreeMap<usize, Vec<u8>>> for Pcrs {
    type Error = &'static str;
    fn try_from(values: BTreeMap<usize, Vec<u8>>) -> Result<Self, &'static str> {
        let mut pcrs = BTreeMap::new();

        for (index, value) in values {
            if !PCR_INDEXES.contains(&index) {
                return Err("Invalid PCR index provided");
            }

            let pcr = Pcr::try_from(value)?;

            // Not checking if `index` exists inside `pcrs` because this index originated from another `BTreeMap<usize, _>`
            pcrs.insert(index, pcr);
        }

        Ok(Self(pcrs))
    }
}

/// [`aws_nitro_enclaves_nsm_api::api::AttestationDoc`] stores PCRs as a BTreeMap.
impl Into<BTreeMap<usize, ByteBuf>> for Pcrs {
    fn into(self) -> BTreeMap<usize, ByteBuf> {
        let mut map = BTreeMap::new();
        for (index, value) in self.0.into_iter() {
            map.insert(index, value.into());
        }

        map
    }
}

/// Generators
impl Pcrs {
    /// All PCRs will be zeros
    /// Example: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    pub fn zeros() -> Self {
        Pcrs::from_fn(|_| {
            vec![0; PCR_LENGTH]
                .try_into()
                .expect("zeros must produce valid Pcr")
        })
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
    pub fn seed(values: BTreeMap<usize, String>) -> Result<Self, &'static str> {
        use p384::ecdsa::signature::digest::Digest;
        let mut pcrs = BTreeMap::new();
        for (index, seed) in values {
            if !PCR_INDEXES.contains(&index) {
                return Err("Invalid PCR index provided");
            }

            let mut hasher = sha2::Sha384::new();
            hasher.update(seed.as_bytes());
            let result = hasher.finalize().to_vec().into();
            pcrs.insert(index, Pcr(result));
        }

        Ok(Self(pcrs))
    }
}

/// Getters and setters
impl Pcrs {
    pub fn checked_get(&self, index: usize) -> Result<&[u8], &'static str> {
        if !PCR_INDEXES.contains(&index) {
            return Err("PCR index out of range");
        }
        // This shouldn't ever error. Returning an error here since this function is already fallible.
        Ok(&self.0.get(&index).ok_or("Failed to index PCR")?)
    }

    pub fn checked_set(&mut self, index: usize, pcr: Vec<u8>) -> Result<(), &'static str> {
        if !PCR_INDEXES.contains(&index) {
            return Err("PCR index out of range");
        }

        let pcr = Pcr::try_from(pcr)?;

        self.0.insert(index, pcr);
        Ok(())
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
        assert_eq!(
            Pcr::try_from(vec![0; PCR_LENGTH - 1]).unwrap_err(),
            "PCR must be contain 48 bytes."
        );

        let too_long = vec![0; PCR_LENGTH + 1];
        assert_eq!(
            Pcr::try_from(too_long).unwrap_err(),
            "PCR must be contain 48 bytes."
        );

        let just_right = vec![0; PCR_LENGTH];
        assert!(Pcr::try_from(just_right).is_ok());
    }

    #[test]
    fn checked_get_bounds() {
        let pcrs = Pcrs::zeros();
        for index in PCR_INDEXES {
            pcrs.checked_get(index).expect("Failed to get PCR in range");
        }

        assert_eq!(
            pcrs.checked_get(8 + 1).unwrap_err(),
            "PCR index out of range"
        );
    }

    #[test]
    fn checked_set() {
        let mut pcrs = Pcrs::zeros();
        let updated = vec![1; PCR_LENGTH];
        for index in PCR_INDEXES {
            pcrs.checked_set(index, updated.clone()).unwrap();
            assert_eq!(pcrs.checked_get(index).unwrap(), updated);
        }
    }

    #[test]
    fn checked_set_bounds() {
        let mut pcrs = Pcrs::zeros();
        let updated = vec![1; PCR_LENGTH];
        for index in PCR_INDEXES {
            pcrs.checked_set(index, updated.clone())
                .expect("Failed to set PCR in range");
        }

        assert_eq!(
            pcrs.checked_set(8 + 1, updated).unwrap_err(),
            "PCR index out of range"
        );
    }

    #[test]
    fn reliable_b_tree_map() {
        let pcrs = Pcrs::zeros();
        let map: BTreeMap<usize, ByteBuf> = pcrs.into();
        for index in PCR_INDEXES {
            assert!(map.get(&index).is_some());
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
            seed.insert(index, index.to_string());
        }
        let a = Pcrs::seed(seed.clone()).unwrap();
        let b = Pcrs::seed(seed).unwrap();
        assert_eq!(a, b);

        let mut alt_seed = BTreeMap::new();
        for index in PCR_INDEXES {
            alt_seed.insert(index, (index + 1).to_string());
        }
        let c = Pcrs::seed(alt_seed).unwrap();
        assert_ne!(a, c);
    }
}
