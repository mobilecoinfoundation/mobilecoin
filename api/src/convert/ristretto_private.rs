// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::RistrettoPrivate

use crate::{external, ConversionError};
use mc_crypto_keys::RistrettoPrivate;

/// Convert RistrettoPrivate --> external::RistrettoPrivate
impl From<&RistrettoPrivate> for external::RistrettoPrivate {
    fn from(other: &RistrettoPrivate) -> Self {
        Self {
            data: other.to_bytes().to_vec(),
        }
    }
}

/// Convert external::RistrettoPrivate --> RistrettoPrivate.
impl TryFrom<&external::RistrettoPrivate> for RistrettoPrivate {
    type Error = ConversionError;

    fn try_from(source: &external::RistrettoPrivate) -> Result<Self, Self::Error> {
        RistrettoPrivate::try_from(source.data.as_slice())
            .map_err(|_| ConversionError::ArrayCastError)
    }
}
