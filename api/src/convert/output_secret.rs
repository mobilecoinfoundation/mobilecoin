// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_transaction_core::ring_ct::OutputSecret.

use crate::{external, ConversionError};
use mc_transaction_core::ring_ct::OutputSecret;

impl From<&OutputSecret> for external::OutputSecret {
    fn from(source: &OutputSecret) -> Self {
        let mut output_secret = external::OutputSecret::new();
        output_secret.set_amount((&source.amount).into());
        output_secret.set_blinding((&source.blinding).into());
        output_secret
    }
}

impl TryFrom<&external::OutputSecret> for OutputSecret {
    type Error = ConversionError;

    fn try_from(source: &external::OutputSecret) -> Result<Self, Self::Error> {
        Ok(OutputSecret {
            amount: source
                .get_amount()
                .try_into()
                .map_err(|_| ConversionError::KeyCastError)?,
            blinding: source.get_blinding().try_into()?,
        })
    }
}
