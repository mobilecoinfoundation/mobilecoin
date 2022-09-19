// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::Amount

use crate::{external, ConversionError};
use mc_transaction_core::{
    Amount, CompressedCommitment, MaskedAmount, MaskedAmountV1, MaskedAmountV2,
};
use mc_util_repr_bytes::ReprBytes;

// Note:
// external::MaskedAmount is a proto message
// external::TxOut_oneof_masked_amount is a proto oneof

impl From<&MaskedAmountV1> for external::MaskedAmount {
    fn from(source: &MaskedAmountV1) -> Self {
        let commitment_bytes = source.commitment.to_bytes().to_vec();
        let mut amount = external::MaskedAmount::new();
        amount.mut_commitment().set_data(commitment_bytes);
        amount.set_masked_value(source.masked_value);
        amount.set_masked_token_id(source.masked_token_id.clone());
        amount
    }
}

impl From<&MaskedAmountV2> for external::MaskedAmount {
    fn from(source: &MaskedAmountV2) -> Self {
        let commitment_bytes = source.commitment.to_bytes().to_vec();
        let mut amount = external::MaskedAmount::new();
        amount.mut_commitment().set_data(commitment_bytes);
        amount.set_masked_value(source.masked_value);
        amount.set_masked_token_id(source.masked_token_id.clone());
        amount
    }
}

impl From<&MaskedAmount> for external::TxOut_oneof_masked_amount {
    fn from(source: &MaskedAmount) -> Self {
        match source {
            MaskedAmount::V1(masked_amount) => {
                external::TxOut_oneof_masked_amount::masked_amount_v1(masked_amount.into())
            }
            MaskedAmount::V2(masked_amount) => {
                external::TxOut_oneof_masked_amount::masked_amount_v2(masked_amount.into())
            }
        }
    }
}

impl TryFrom<&external::MaskedAmount> for MaskedAmountV1 {
    type Error = ConversionError;

    fn try_from(source: &external::MaskedAmount) -> Result<Self, Self::Error> {
        let commitment = CompressedCommitment::try_from(source.get_commitment())?;
        let masked_value = source.get_masked_value();
        let masked_token_id = source.get_masked_token_id();
        let amount = MaskedAmountV1 {
            commitment,
            masked_value,
            masked_token_id: masked_token_id.to_vec(),
        };
        Ok(amount)
    }
}

impl TryFrom<&external::MaskedAmount> for MaskedAmountV2 {
    type Error = ConversionError;

    fn try_from(source: &external::MaskedAmount) -> Result<Self, Self::Error> {
        let commitment = CompressedCommitment::try_from(source.get_commitment())?;
        let masked_value = source.get_masked_value();
        let masked_token_id = source.get_masked_token_id().to_vec();
        let amount = MaskedAmountV2 {
            commitment,
            masked_value,
            masked_token_id,
        };
        Ok(amount)
    }
}

impl TryFrom<&external::TxOut_oneof_masked_amount> for MaskedAmount {
    type Error = ConversionError;

    fn try_from(source: &external::TxOut_oneof_masked_amount) -> Result<Self, Self::Error> {
        match source {
            external::TxOut_oneof_masked_amount::masked_amount_v1(masked_amount) => {
                Ok(MaskedAmount::V1(masked_amount.try_into()?))
            }
            external::TxOut_oneof_masked_amount::masked_amount_v2(masked_amount) => {
                Ok(MaskedAmount::V2(masked_amount.try_into()?))
            }
        }
    }
}

impl From<&MaskedAmount> for external::Receipt_oneof_masked_amount {
    fn from(source: &MaskedAmount) -> Self {
        match source {
            MaskedAmount::V1(masked_amount) => {
                external::Receipt_oneof_masked_amount::masked_amount_v1(masked_amount.into())
            }
            MaskedAmount::V2(masked_amount) => {
                external::Receipt_oneof_masked_amount::masked_amount_v2(masked_amount.into())
            }
        }
    }
}

impl TryFrom<&external::Receipt_oneof_masked_amount> for MaskedAmount {
    type Error = ConversionError;

    fn try_from(source: &external::Receipt_oneof_masked_amount) -> Result<Self, Self::Error> {
        match source {
            external::Receipt_oneof_masked_amount::masked_amount_v1(masked_amount) => {
                Ok(MaskedAmount::V1(masked_amount.try_into()?))
            }
            external::Receipt_oneof_masked_amount::masked_amount_v2(masked_amount) => {
                Ok(MaskedAmount::V2(masked_amount.try_into()?))
            }
        }
    }
}

impl From<&Amount> for external::Amount {
    fn from(source: &Amount) -> Self {
        let mut amount = external::Amount::new();
        amount.set_value(source.value);
        amount.set_token_id(*source.token_id);
        amount
    }
}

impl From<&external::Amount> for Amount {
    fn from(source: &external::Amount) -> Self {
        Amount::new(source.get_value(), source.get_token_id().into())
    }
}
