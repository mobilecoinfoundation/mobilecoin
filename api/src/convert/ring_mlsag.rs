//! Convert to/from external::RingMlsag

use crate::{external, ConversionError};
use mc_transaction_core::ring_signature::{CurveScalar, RingMLSAG};

impl From<&RingMLSAG> for external::RingMlsag {
    fn from(source: &RingMLSAG) -> Self {
        Self {
            c_zero: Some((&source.c_zero).into()),
            responses: source
                .responses
                .iter()
                .map(external::CurveScalar::from)
                .collect(),
            key_image: Some((&source.key_image).into()),
        }
    }
}

impl TryFrom<&external::RingMlsag> for RingMLSAG {
    type Error = ConversionError;

    fn try_from(source: &external::RingMlsag) -> Result<Self, Self::Error> {
        let responses = source
            .responses
            .iter()
            .map(CurveScalar::try_from)
            .collect::<Result<_, _>>()?;
        let c_zero = source
            .c_zero
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;
        let key_image = source
            .key_image
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        Ok(RingMLSAG {
            responses,
            c_zero,
            key_image,
        })
    }
}
