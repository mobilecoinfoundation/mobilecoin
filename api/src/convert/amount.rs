// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::Amount

use crate::{external, external::CompressedRistretto, ConversionError};
use mc_transaction_core::{Amount, MaskedAmount, MaskedAmountV1, MaskedAmountV2};
use mc_util_repr_bytes::ReprBytes;
// Note:
// external::MaskedAmount is a proto message
// external::TxOut_oneof_masked_amount is a proto oneof

impl From<&MaskedAmountV1> for external::MaskedAmount {
    fn from(source: &MaskedAmountV1) -> Self {
        let commitment_bytes = source.commitment.to_bytes().to_vec();
        Self {
            commitment: Some(CompressedRistretto {
                data: commitment_bytes,
            }),
            masked_value: source.masked_value,
            masked_token_id: source.masked_token_id.clone(),
        }
    }
}

impl From<&MaskedAmountV2> for external::MaskedAmount {
    fn from(source: &MaskedAmountV2) -> Self {
        let commitment_bytes = source.commitment.to_bytes().to_vec();
        Self {
            commitment: Some(CompressedRistretto {
                data: commitment_bytes,
            }),
            masked_value: source.masked_value,
            masked_token_id: source.masked_token_id.clone(),
        }
    }
}

impl From<&MaskedAmount> for external::tx_out::MaskedAmount {
    fn from(source: &MaskedAmount) -> Self {
        match source {
            MaskedAmount::V1(masked_amount) => {
                external::tx_out::MaskedAmount::MaskedAmountV1(masked_amount.into())
            }
            MaskedAmount::V2(masked_amount) => {
                external::tx_out::MaskedAmount::MaskedAmountV2(masked_amount.into())
            }
        }
    }
}

impl TryFrom<&external::MaskedAmount> for MaskedAmountV1 {
    type Error = ConversionError;

    fn try_from(source: &external::MaskedAmount) -> Result<Self, Self::Error> {
        let commitment = source
            .commitment
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        let masked_value = source.masked_value;
        let masked_token_id = source.masked_token_id.clone();
        let amount = MaskedAmountV1 {
            commitment,
            masked_value,
            masked_token_id,
        };
        Ok(amount)
    }
}

impl TryFrom<&external::MaskedAmount> for MaskedAmountV2 {
    type Error = ConversionError;

    fn try_from(source: &external::MaskedAmount) -> Result<Self, Self::Error> {
        let commitment = source
            .commitment
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        let masked_value = source.masked_value;
        let masked_token_id = source.masked_token_id.clone();
        let amount = MaskedAmountV2 {
            commitment,
            masked_value,
            masked_token_id,
        };
        Ok(amount)
    }
}

impl TryFrom<&external::tx_out::MaskedAmount> for MaskedAmount {
    type Error = ConversionError;

    fn try_from(source: &external::tx_out::MaskedAmount) -> Result<Self, Self::Error> {
        match source {
            external::tx_out::MaskedAmount::MaskedAmountV1(masked_amount) => {
                Ok(MaskedAmount::V1(masked_amount.try_into()?))
            }
            external::tx_out::MaskedAmount::MaskedAmountV2(masked_amount) => {
                Ok(MaskedAmount::V2(masked_amount.try_into()?))
            }
        }
    }
}

impl From<&MaskedAmount> for external::receipt::MaskedAmount {
    fn from(source: &MaskedAmount) -> Self {
        match source {
            MaskedAmount::V1(masked_amount) => {
                external::receipt::MaskedAmount::MaskedAmountV1(masked_amount.into())
            }
            MaskedAmount::V2(masked_amount) => {
                external::receipt::MaskedAmount::MaskedAmountV2(masked_amount.into())
            }
        }
    }
}

impl TryFrom<&external::receipt::MaskedAmount> for MaskedAmount {
    type Error = ConversionError;

    fn try_from(source: &external::receipt::MaskedAmount) -> Result<Self, Self::Error> {
        match source {
            external::receipt::MaskedAmount::MaskedAmountV1(masked_amount) => {
                Ok(MaskedAmount::V1(masked_amount.try_into()?))
            }
            external::receipt::MaskedAmount::MaskedAmountV2(masked_amount) => {
                Ok(MaskedAmount::V2(masked_amount.try_into()?))
            }
        }
    }
}

impl From<&Amount> for external::Amount {
    fn from(source: &Amount) -> Self {
        Self {
            value: source.value,
            token_id: *source.token_id,
        }
    }
}

impl From<&external::Amount> for Amount {
    fn from(source: &external::Amount) -> Self {
        Amount::new(source.value, source.token_id.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_transaction_core::TokenId;

    // Test converting between external::Amount and
    // mc_transaction_types::Amount
    #[test]
    fn test_amount_conversion() {
        let amount = Amount::new(10000, TokenId::from(10));

        let external_amount: external::Amount = (&amount).into();
        let recovered_amount: Amount = (&external_amount).into();

        assert_eq!(amount, recovered_amount);
    }
}
