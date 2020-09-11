//! Convert to/from external::RingMLSAG

use crate::{convert::ConversionError, external};
use mc_transaction_core::ring_signature::{CurveScalar, KeyImage, RingMLSAG};
use std::convert::TryFrom;

impl From<&RingMLSAG> for external::RingMLSAG {
    fn from(source: &RingMLSAG) -> Self {
        let mut ring_mlsag = external::RingMLSAG::new();
        ring_mlsag.set_c_zero(external::CurveScalar::from(&source.c_zero));
        let responses: Vec<external::CurveScalar> = source
            .responses
            .iter()
            .map(external::CurveScalar::from)
            .collect();
        ring_mlsag.set_responses(responses.into());
        ring_mlsag.set_key_image(external::KeyImage::from(&source.key_image));
        ring_mlsag
    }
}

impl TryFrom<&external::RingMLSAG> for RingMLSAG {
    type Error = ConversionError;

    fn try_from(source: &external::RingMLSAG) -> Result<Self, Self::Error> {
        let c_zero = CurveScalar::try_from(source.get_c_zero())?;
        let mut responses: Vec<CurveScalar> = Vec::new();
        for response in source.get_responses() {
            responses.push(CurveScalar::try_from(response)?);
        }
        let key_image = KeyImage::try_from(source.get_key_image())?;

        Ok(RingMLSAG {
            c_zero,
            responses,
            key_image,
        })
    }
}
