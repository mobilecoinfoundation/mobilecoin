// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::CurveScalar

use crate::{external, ConversionError};
use curve25519_dalek::scalar::Scalar;
use mc_crypto_keys::RistrettoPrivate;
use mc_transaction_core::ring_signature::CurveScalar;

/// Convert RistrettoPrivate --> external::CurveScalar.
impl From<&RistrettoPrivate> for external::CurveScalar {
    fn from(other: &RistrettoPrivate) -> Self {
        let mut scalar = external::CurveScalar::new();
        let privbytes: &[u8] = other.as_ref();
        scalar.set_data(Vec::from(privbytes));
        scalar
    }
}

/// Convert CurveScalar --> external::CurveScalar.
impl From<&CurveScalar> for external::CurveScalar {
    fn from(other: &CurveScalar) -> Self {
        let mut scalar = external::CurveScalar::new();
        scalar.set_data(other.as_bytes().to_vec());
        scalar
    }
}

/// Convert external::CurveScalar --> CurveScalar.
impl TryFrom<&external::CurveScalar> for CurveScalar {
    type Error = ConversionError;

    fn try_from(source: &external::CurveScalar) -> Result<Self, Self::Error> {
        let bytes: &[u8] = source.get_data();
        CurveScalar::try_from(bytes).map_err(|_| ConversionError::ArrayCastError)
    }
}

impl From<&Scalar> for external::CurveScalar {
    fn from(source: &Scalar) -> Self {
        let mut scalar = external::CurveScalar::new();
        scalar.set_data(source.to_bytes().to_vec());
        scalar
    }
}

impl TryFrom<&external::CurveScalar> for Scalar {
    type Error = ConversionError;

    fn try_from(source: &external::CurveScalar) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = source
            .get_data()
            .try_into()
            .map_err(|_| ConversionError::ArrayCastError)?;
        Ok(Scalar::from_bits(bytes))
    }
}
