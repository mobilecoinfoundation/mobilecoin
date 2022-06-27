//! Convert to/from external::RistrettoPrivate

use crate::{external, ConversionError};
use mc_crypto_keys::RistrettoPrivate;

/// Convert RistrettoPrivate --> external::RistrettoPrivate
impl From<&RistrettoPrivate> for external::RistrettoPrivate {
    fn from(other: &RistrettoPrivate) -> Self {
        Self {
            data: other.as_bytes().to_vec(),
        }
    }
}

/// Convert external::RistrettoPrivate --> RistrettoPrivate.
impl TryFrom<&external::RistrettoPrivate> for RistrettoPrivate {
    type Error = ConversionError;

    fn try_from(source: &external::RistrettoPrivate) -> Result<Self, Self::Error> {
        let bytes: &[u8] = &source.data;
        RistrettoPrivate::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}
