//! Convert to/from external::Amount

use crate::{convert::ConversionError, external};
use mc_transaction_core::{CompressedCommitment, MaskedAmount};
use mc_util_repr_bytes::ReprBytes;
use std::convert::TryFrom;

impl From<&MaskedAmount> for external::MaskedAmount {
    fn from(source: &MaskedAmount) -> Self {
        let commitment_bytes = source.commitment.to_bytes().to_vec();
        let mut amount = external::MaskedAmount::new();
        amount.mut_commitment().set_data(commitment_bytes);
        amount.set_masked_value(source.masked_value);
        amount.set_masked_token_id(source.masked_token_id.clone());
        amount
    }
}

impl TryFrom<&external::MaskedAmount> for MaskedAmount {
    type Error = ConversionError;

    fn try_from(source: &external::MaskedAmount) -> Result<Self, Self::Error> {
        let commitment = CompressedCommitment::try_from(source.get_commitment())?;
        let masked_value = source.get_masked_value();
        let masked_token_id = source.get_masked_token_id();
        let amount = MaskedAmount {
            commitment,
            masked_value,
            masked_token_id: masked_token_id.to_vec(),
        };
        Ok(amount)
    }
}
