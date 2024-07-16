use std::collections::BTreeMap;
use p384::ecdsa::signature::digest::Digest;
use serde_bytes::ByteBuf;

#[derive(Clone)]
pub struct Pcrs(pub(crate) [String; 7]);

/// Generators
impl Pcrs {
    /// All PCRs will be zeros
    /// Example: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    pub fn zeros() -> Self {
        Self(core::array::from_fn(|_| {
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_owned()
        }))
    }

    /// All PCRs will be randomly generated to mimic the SHA386 hashes
    // Todo: generate mimic values
    pub fn mimic() -> Self {
        Self(core::array::from_fn(|_| {
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_owned()
        }))
    }

    /// All PCRs will be seeded from the provided strings. Each string gets hashed with SHA386.
    pub fn seed(mut values: [String; 7]) -> Result<Self, &'static str> {
        for i in 0..7 {
            let mut hasher = sha2::Sha384::new();
            hasher.update(values[i].as_bytes());
            let result = hasher.finalize();
            values[i] = hex::encode(result);
        }

        Ok(Self(values))
    }
}

/// Getters and setters
impl Pcrs {
    pub fn checked_get(&self, index: u16) -> Result<&str, &'static str> {
        if index > 7 {
            return Err("PCR index out of range");
        }
        Ok(&self.0[usize::from(index)])
    }

    pub fn checked_set(&mut self, index: usize, value: String) -> Result<(), &'static str> {
        if index > 7 {
            return Err("PCR index out of range");
        }

        if value.len() != 96 {
            return Err("Provided PCR has invalid length");
        }

        self.0[index] = value;
        Ok(())
    }
}

/// Attempts to turn a [`Vec<String>`] into [`Pcrs`]
/// Useful if you have pre-generated PCRs you wish to mock.
/// If you don't already have PCRs, you should probably use [`Pcrs`]'s methods to generate what you need.
impl TryFrom<Vec<String>> for Pcrs {
    type Error = &'static str;

    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        let value: [String; 7] = value.try_into().map_err(|_| "Invalid manual PCR length.")?;

        let invalid_string_lengths = value.iter().all(|s| s.len() != 96);
        if invalid_string_lengths {
            return Err("All manual PCRs must be 96 characters.");
        }

        Ok(Self(value))
    }
}

impl Into<BTreeMap<usize, ByteBuf>> for Pcrs {
    fn into(self) -> BTreeMap<usize, ByteBuf> {
        let mut map = BTreeMap::new();
        for (index, value) in self.0.into_iter().enumerate() {
            map.insert(index, value.as_bytes().to_vec().into());
        }

        map
    }
}

impl Default for Pcrs {
    fn default() -> Self {
        Pcrs::zeros()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcrs_defaults_to_zero() {
        let pcrs = Pcrs::default();
        let all_zeros = pcrs
            .0
            .into_iter()
            .all(|s| s.chars().all(|s| s.to_string().as_str() == "0"));
        assert!(all_zeros);
    }
}