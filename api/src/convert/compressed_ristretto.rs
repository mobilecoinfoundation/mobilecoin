// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::CompressedRistretto.

use crate::{external, ConversionError};
use curve25519_dalek::ristretto::CompressedRistretto;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_transaction_core::CompressedCommitment;

impl From<&CompressedCommitment> for external::CompressedRistretto {
    fn from(source: &CompressedCommitment) -> Self {
        Self {
            data: source.point.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<&external::CompressedRistretto> for CompressedCommitment {
    type Error = ConversionError;

    fn try_from(source: &external::CompressedRistretto) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.data.as_ref();
        let point =
            CompressedRistretto::from_slice(bytes).map_err(|_e| ConversionError::ArrayCastError)?;
        Ok(CompressedCommitment { point })
    }
}

/// Convert external::CompressedRistretto --> RistrettoPublic.
impl TryFrom<&external::CompressedRistretto> for RistrettoPublic {
    type Error = ConversionError;

    fn try_from(source: &external::CompressedRistretto) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.data.as_ref();
        RistrettoPublic::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}

/// Convert CompressedRistrettoPublic --> external::CompressedRistretto
impl From<&CompressedRistrettoPublic> for external::CompressedRistretto {
    fn from(other: &CompressedRistrettoPublic) -> Self {
        Self {
            data: other.as_bytes().to_vec(),
        }
    }
}

/// Convert &RistrettoPublic --> external::CompressedRistretto
impl From<&RistrettoPublic> for external::CompressedRistretto {
    fn from(other: &RistrettoPublic) -> Self {
        Self {
            data: other.to_bytes().to_vec(),
        }
    }
}

/// Convert external::CompressedRistretto --> CompressedRistrettoPublic.
impl TryFrom<&external::CompressedRistretto> for CompressedRistrettoPublic {
    type Error = ConversionError;

    fn try_from(source: &external::CompressedRistretto) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.data.as_ref();
        CompressedRistrettoPublic::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}
