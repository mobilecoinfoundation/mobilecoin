//! Convert to/from external::CompressedRistretto.

use crate::{convert::ConversionError, external};
use curve25519_dalek::ristretto::CompressedRistretto;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_transaction_core::CompressedCommitment;
use std::convert::TryFrom;

impl From<&CompressedCommitment> for external::CompressedRistretto {
    fn from(source: &CompressedCommitment) -> Self {
        let mut compressed_ristretto = external::CompressedRistretto::new();
        compressed_ristretto.set_data(source.point.as_bytes().to_vec());
        compressed_ristretto
    }
}

impl TryFrom<&external::CompressedRistretto> for CompressedCommitment {
    type Error = ConversionError;

    fn try_from(source: &external::CompressedRistretto) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        if bytes.len() != 32 {
            return Err(ConversionError::ArrayCastError);
        }
        let point = CompressedRistretto::from_slice(bytes);
        Ok(CompressedCommitment { point })
    }
}

/// Convert external::CompressedRistretto --> RistrettoPublic.
impl TryFrom<&external::CompressedRistretto> for RistrettoPublic {
    type Error = ConversionError;

    fn try_from(source: &external::CompressedRistretto) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        RistrettoPublic::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}

/// Convert CompressedRistrettoPublic --> external::CompressedRistretto
impl From<&CompressedRistrettoPublic> for external::CompressedRistretto {
    fn from(other: &CompressedRistrettoPublic) -> Self {
        let mut key = external::CompressedRistretto::new();
        key.set_data(other.as_bytes().to_vec());
        key
    }
}

/// Convert &RistrettoPublic --> external::CompressedRistretto
impl From<&RistrettoPublic> for external::CompressedRistretto {
    fn from(other: &RistrettoPublic) -> Self {
        let mut key = external::CompressedRistretto::new();
        key.set_data(other.to_bytes().to_vec());
        key
    }
}

/// Convert external::CompressedRistretto --> CompressedRistrettoPublic.
impl TryFrom<&external::CompressedRistretto> for CompressedRistrettoPublic {
    type Error = ConversionError;

    fn try_from(source: &external::CompressedRistretto) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        CompressedRistrettoPublic::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}
