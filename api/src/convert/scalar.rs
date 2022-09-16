use crate::{external, ConversionError};
use curve25519_dalek::scalar::Scalar;
use std::convert::TryFrom;

impl From<&Scalar> for external::Scalar {
    fn from(source: &Scalar) -> Self {
        let mut scalar = external::Scalar::new();
        scalar.set_data(source.to_bytes().to_vec());
        scalar
    }
}

impl TryFrom<&external::Scalar> for Scalar {
    type Error = ConversionError;

    fn try_from(source: &external::Scalar) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = source
            .get_data()
            .try_into()
            .map_err(|_| ConversionError::ArrayCastError)?;
        Ok(Scalar::from_bits(bytes))
    }
}
