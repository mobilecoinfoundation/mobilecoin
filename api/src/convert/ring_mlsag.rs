// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::RingMLSAG

use crate::{external, ConversionError};
use mc_transaction_core::ring_signature::{CurveScalar, RingMLSAG};

impl From<&RingMLSAG> for external::RingMlsag {
    fn from(source: &RingMLSAG) -> Self {
        let responses: Vec<external::CurveScalar> = source
            .responses
            .iter()
            .map(external::CurveScalar::from)
            .collect();
        Self {
            c_zero: external::CurveScalar::from(&source.c_zero).into(),
            responses,
            key_image: external::KeyImage::from(&source.key_image).into(),
        }
    }
}

impl TryFrom<&external::RingMlsag> for RingMLSAG {
    type Error = ConversionError;

    fn try_from(source: &external::RingMlsag) -> Result<Self, Self::Error> {
        let c_zero = source
            .c_zero
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        let responses = source
            .responses
            .iter()
            .map(CurveScalar::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let key_image = source
            .key_image
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;

        Ok(RingMLSAG {
            c_zero,
            responses,
            key_image,
        })
    }
}
