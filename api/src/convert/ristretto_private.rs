//! Convert to/from external::RistrettoPrivate

use crate::{external, ConversionError};
use mc_crypto_keys::RistrettoPrivate;
use std::convert::TryFrom;

/// Convert RistrettoPrivate --> external::RistrettoPrivate
impl From<&RistrettoPrivate> for external::RistrettoPrivate {
    fn from(other: &RistrettoPrivate) -> Self {
        let mut key = external::RistrettoPrivate::new();
        key.set_data(other.to_bytes().to_vec());
        key
    }
}

/// Convert external::RistrettoPrivate --> RistrettoPrivate.
impl TryFrom<&external::RistrettoPrivate> for RistrettoPrivate {
    type Error = ConversionError;

    fn try_from(source: &external::RistrettoPrivate) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        RistrettoPrivate::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}
