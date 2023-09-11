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
        let maybe_scalar: Option<Scalar> = Scalar::from_canonical_bytes(bytes).into();
        maybe_scalar.ok_or(ConversionError::InvalidContents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    // Test converting between external::CurveScalar and
    // curve25519_dalek::Scalar
    #[test]
    fn test_scalar_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        let scalar = Scalar::random(&mut rng);

        let external_curve_scalar: external::CurveScalar = (&scalar).into();
        let recovered_scalar: Scalar = (&external_curve_scalar).try_into().unwrap();

        assert_eq!(scalar, recovered_scalar);
    }
}
