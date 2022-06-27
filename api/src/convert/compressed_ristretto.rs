//! Convert to/from external::CompressedRistretto.

use crate::{external, ConversionError};
use curve25519_dalek::ristretto::CompressedRistretto;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_transaction_core::CompressedCommitment;

impl From<&CompressedCommitment> for external::CompressedRistretto {
    fn from(source: &CompressedCommitment) -> Self {
        Self {
            data: source.as_ref().to_vec(),
        }
    }
}

impl TryFrom<&external::CompressedRistretto> for CompressedCommitment {
    type Error = ConversionError;

    fn try_from(source: &external::CompressedRistretto) -> Result<Self, Self::Error> {
        let bytes: &[u8] = &source.data;
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
        let bytes: &[u8] = &source.data;
        RistrettoPublic::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}

/// Convert CompressedRistrettoPublic --> external::CompressedRistretto
impl From<&CompressedRistrettoPublic> for external::CompressedRistretto {
    fn from(source: &CompressedRistrettoPublic) -> Self {
        Self {
            data: source.as_bytes().to_vec(),
        }
    }
}

/// Convert &RistrettoPublic --> external::CompressedRistretto
impl From<&RistrettoPublic> for external::CompressedRistretto {
    fn from(source: &RistrettoPublic) -> Self {
        Self {
            data: source.to_bytes().to_vec(),
        }
    }
}

/// Convert external::CompressedRistretto --> CompressedRistrettoPublic.
impl TryFrom<&external::CompressedRistretto> for CompressedRistrettoPublic {
    type Error = ConversionError;

    fn try_from(source: &external::CompressedRistretto) -> Result<Self, Self::Error> {
        let bytes: &[u8] = &source.data;
        CompressedRistrettoPublic::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}
