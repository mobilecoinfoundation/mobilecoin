//! Convert to/from external::CurveScalar

use crate::{external, ConversionError};
use mc_crypto_keys::RistrettoPrivate;
use mc_transaction_core::ring_signature::CurveScalar;

/// Convert RistrettoPrivate --> external::CurveScalar.
impl From<&RistrettoPrivate> for external::CurveScalar {
    fn from(other: &RistrettoPrivate) -> Self {
        Self {
            data: other.as_bytes().to_vec(),
        }
    }
}

/// Convert CurveScalar --> external::CurveScalar.
impl From<&CurveScalar> for external::CurveScalar {
    fn from(other: &CurveScalar) -> Self {
        Self {
            data: other.as_bytes().to_vec(),
        }
    }
}

/// Convert external::CurveScalar --> CurveScalar.
impl TryFrom<&external::CurveScalar> for CurveScalar {
    type Error = ConversionError;

    fn try_from(source: &external::CurveScalar) -> Result<Self, Self::Error> {
        CurveScalar::try_from(&source.data[..]).map_err(|_| ConversionError::ArrayCastError)
    }
}
