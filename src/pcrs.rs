use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use std::ops::Deref;

/// PCRs from to 0 to 8
pub(crate) const PCR_COUNT: usize = 8;
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
pub struct Pcrs(pub(crate) [Pcr; PCR_COUNT]);

impl Default for Pcrs {
    fn default() -> Self {
        Pcrs::zeros()
    }
}

/// Useful if you have pre-generated PCRs you wish to mock.
/// If you don't already have PCRs, you should probably use [`Pcrs`]'s methods to generate what you need.
impl TryFrom<[Vec<u8>; PCR_COUNT]> for Pcrs {
    type Error = &'static str;
    fn try_from(pcrs: [Vec<u8>; PCR_COUNT]) -> Result<Self, &'static str> {
        let pcrs = pcrs
            .into_iter()
            .map(|pcr| Pcr::try_from(pcr))
            .collect::<Result<Vec<Pcr>, Self::Error>>()?;
        Ok(Self(
            pcrs.try_into().expect("pcrs must have length of PCR_COUNT"),
        ))
    }
}

/// [`aws_nitro_enclaves_nsm_api::api::AttestationDoc`] stores PCRs as a BTreeMap.
impl Into<BTreeMap<usize, ByteBuf>> for Pcrs {
    fn into(self) -> BTreeMap<usize, ByteBuf> {
        let mut map = BTreeMap::new();
        for (index, value) in self.0.into_iter().enumerate() {
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
        Self(core::array::from_fn(|_| {
            vec![0; PCR_LENGTH]
                .try_into()
                .expect("zeros must produce valid Pcr")
        }))
    }

    #[cfg(feature = "rand")]
    /// All PCRs will be randomly generated to mimic SHA386 hashes
    pub fn rand() -> Self {
        use rand::{distributions::Alphanumeric, Rng};
        Self(core::array::from_fn(|_| {
            let bytes = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(PCR_LENGTH)
                .collect::<Vec<u8>>();
            Pcr::try_from(bytes).expect("rand must produce valid Pcr")
        }))
    }

    #[cfg(feature = "seed")]
    /// All PCRs will be seeded from the provided strings. Each string gets hashed with SHA386.
    pub fn seed(values: [String; PCR_COUNT]) -> Result<Self, &'static str> {
        use p384::ecdsa::signature::digest::Digest;
        let values = values
            .into_iter()
            .map(|seed| {
                let mut hasher = sha2::Sha384::new();
                hasher.update(seed.as_bytes());
                let result = hasher.finalize().to_vec().into();
                Pcr(result)
            })
            .collect::<Vec<Pcr>>();

        let values: [Pcr; PCR_COUNT] = values.try_into().expect("PCR_COUNT changed");
        Ok(Self(values))
    }
}

/// Getters and setters
impl Pcrs {
    pub fn checked_get(&self, index: usize) -> Result<&[u8], &'static str> {
        if index > PCR_COUNT {
            return Err("PCR index out of range");
        }
        Ok(&self.0[index].deref())
    }

    pub fn checked_set(&mut self, index: usize, pcr: Vec<u8>) -> Result<(), &'static str> {
        if index > PCR_COUNT {
            return Err("PCR index out of range");
        }

        let pcr = Pcr::try_from(pcr)?;

        self.0[index] = pcr;
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
            .all(|pcr| pcr.to_vec().into_iter().all(|b| b == 0));
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
        for i in 0..PCR_COUNT {
            pcrs.checked_get(i).expect("Failed to get PCR in range");
        }

        assert_eq!(
            pcrs.checked_get(PCR_COUNT + 1).unwrap_err(),
            "PCR index out of range"
        );
    }

    #[test]
    fn checked_set() {
        let mut pcrs = Pcrs::zeros();
        let updated = vec![1; PCR_LENGTH];
        for i in 0..PCR_COUNT {
            pcrs.checked_set(i, updated.clone()).unwrap();
            assert_eq!(pcrs.checked_get(i).unwrap(), updated);
        }
    }

    #[test]
    fn checked_set_bounds() {
        let mut pcrs = Pcrs::zeros();
        let updated = vec![1; PCR_LENGTH];
        for i in 0..PCR_COUNT {
            pcrs.checked_set(i, updated.clone())
                .expect("Failed to set PCR in range");
        }

        assert_eq!(
            pcrs.checked_set(PCR_COUNT + 1, updated).unwrap_err(),
            "PCR index out of range"
        );
    }

    #[test]
    fn reliable_b_tree_map() {
        let pcrs = Pcrs::zeros();
        let map: BTreeMap<usize, ByteBuf> = pcrs.into();
        for i in 0..PCR_COUNT {
            assert!(map.get(&i).is_some());
        }

        assert!(map.get(&(PCR_COUNT + 1)).is_none());
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
        let seed: [String; PCR_COUNT] = core::array::from_fn(|i| format!("pcr{i}"));
        let a = Pcrs::seed(seed.clone()).unwrap();
        let b = Pcrs::seed(seed).unwrap();
        assert_eq!(a, b);

        let alt_seed: [String; PCR_COUNT] = core::array::from_fn(|i| format!("pcr{}", i + 1));
        let c = Pcrs::seed(alt_seed).unwrap();
        assert_ne!(a, c);
    }
}
