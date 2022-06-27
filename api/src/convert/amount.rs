//! Convert to/from external::Amount

use crate::{external, ConversionError};
use mc_transaction_core::MaskedAmount;

impl From<&MaskedAmount> for external::MaskedAmount {
    fn from(source: &MaskedAmount) -> Self {
        Self {
            commitment: Some((&source.commitment).into()),
            masked_value: source.masked_value,
            masked_token_id: source.masked_token_id.clone(),
        }
    }
}

impl TryFrom<&external::MaskedAmount> for MaskedAmount {
    type Error = ConversionError;

    fn try_from(source: &external::MaskedAmount) -> Result<Self, Self::Error> {
        let commitment = source
            .commitment
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        Ok(MaskedAmount {
            commitment,
            masked_value: source.masked_value,
            masked_token_id: source.masked_token_id.clone(),
        })
    }
}
