// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_transaction_extra::UnsignedTx.

use crate::{external, ConversionError};
use mc_blockchain_types::BlockVersion;
use mc_transaction_core::UnmaskedAmount;
use mc_transaction_extra::UnsignedTx;
use mc_transaction_summary::TxOutSummaryUnblindingData;

impl From<&UnsignedTx> for external::UnsignedTx {
    fn from(source: &UnsignedTx) -> Self {
        Self {
            tx_prefix: Some((&source.tx_prefix).into()),
            rings: source.rings.iter().map(Into::into).collect(),
            block_version: *source.block_version,
            tx_out_unblinding_data: source
                .tx_out_unblinding_data
                .iter()
                .map(Into::into)
                .collect(),
        }
    }
}

impl TryFrom<&external::UnsignedTx> for UnsignedTx {
    type Error = ConversionError;

    fn try_from(source: &external::UnsignedTx) -> Result<Self, Self::Error> {
        let tx_prefix = source
            .tx_prefix
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        Ok(UnsignedTx {
            tx_prefix,
            rings: source
                .rings
                .iter()
                .map(|input| input.try_into())
                .collect::<Result<_, _>>()?,
            tx_out_unblinding_data: source
                .tx_out_unblinding_data
                .iter()
                .map(|data| data.try_into())
                .collect::<Result<_, _>>()?,
            block_version: BlockVersion::try_from(source.block_version)?,
        })
    }
}

impl From<&TxOutSummaryUnblindingData> for external::TxOutSummaryUnblindingData {
    fn from(src: &TxOutSummaryUnblindingData) -> Self {
        Self {
            unmasked_amount: Some((&src.unmasked_amount).into()),
            address: src.address.as_ref().map(Into::into),
            tx_private_key: src.tx_private_key.as_ref().map(Into::into),
        }
    }
}

impl TryFrom<&external::TxOutSummaryUnblindingData> for TxOutSummaryUnblindingData {
    type Error = ConversionError;

    fn try_from(source: &external::TxOutSummaryUnblindingData) -> Result<Self, Self::Error> {
        Ok(TxOutSummaryUnblindingData {
            unmasked_amount: source
                .unmasked_amount
                .as_ref()
                .ok_or_else(|| ConversionError::MissingField("unmasked_amount".into()))?
                .try_into()?,
            address: source.address.as_ref().map(TryInto::try_into).transpose()?,
            tx_private_key: source
                .tx_private_key
                .as_ref()
                .map(TryInto::try_into)
                .transpose()?,
        })
    }
}

impl From<&UnmaskedAmount> for external::UnmaskedAmount {
    fn from(src: &UnmaskedAmount) -> Self {
        Self {
            value: src.value,
            token_id: src.token_id,
            blinding: Some((&src.blinding).into()),
        }
    }
}

impl TryFrom<&external::UnmaskedAmount> for UnmaskedAmount {
    type Error = ConversionError;

    fn try_from(source: &external::UnmaskedAmount) -> Result<Self, Self::Error> {
        let blinding = source
            .blinding
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        Ok(UnmaskedAmount {
            value: source.value,
            token_id: source.token_id,
            blinding,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::AccountKey;
    use mc_fog_report_validation_test_utils::MockFogResolver;
    use mc_transaction_builder::{
        test_utils::get_input_credentials, EmptyMemoBuilder, TransactionBuilder,
    };
    use mc_transaction_core::{tokens::Mob, Amount, Token};
    use rand::{rngs::StdRng, SeedableRng};

    // Test converting between external::UnsignedTx and
    // mc_transaction_builder::UnsignedTx
    #[test]
    fn test_unsigned_tx_conversion() {
        // Generate an UnsignedTx to test with.
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for block_version in BlockVersion::iterator() {
            let alice = AccountKey::random(&mut rng);
            let bob = AccountKey::random(&mut rng);

            let fpr = MockFogResolver::default();

            let mut transaction_builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, Mob::ID),
                fpr.clone(),
            )
            .unwrap();

            transaction_builder.add_input(get_input_credentials(
                block_version,
                Amount::new(65536 + Mob::MINIMUM_FEE, Mob::ID),
                &alice,
                &fpr,
                &mut rng,
            ));
            transaction_builder
                .add_output(
                    Amount::new(65536, Mob::ID),
                    &bob.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            let unsigned_tx = transaction_builder
                .build_unsigned(EmptyMemoBuilder)
                .unwrap();

            // Converting mc_transaction_builder::UnsignedTx -> external::UnsignedTx ->
            // mc_transaction_builder::UnsignedTx should be the identity function.
            {
                let external_unsigned_tx: external::UnsignedTx = (&unsigned_tx).into();
                let recovered_unsigned_tx: UnsignedTx = (&external_unsigned_tx).try_into().unwrap();
                assert_eq!(unsigned_tx, recovered_unsigned_tx);
            }
        }
    }
}
