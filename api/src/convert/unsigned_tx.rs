// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_transaction_std::UnsignedTx.

use crate::{external, ConversionError};
use mc_blockchain_types::BlockVersion;
use mc_transaction_std::UnsignedTx;

impl From<&UnsignedTx> for external::UnsignedTx {
    fn from(source: &UnsignedTx) -> Self {
        let mut unsigned_tx = external::UnsignedTx::new();
        unsigned_tx.set_tx_prefix((&source.tx_prefix).into());
        unsigned_tx.set_rings(protobuf::RepeatedField::from_vec(
            source.rings.iter().map(|input| input.into()).collect(),
        ));
        unsigned_tx.set_output_secrets(protobuf::RepeatedField::from_vec(
            source
                .output_secrets
                .iter()
                .map(|output| output.into())
                .collect(),
        ));
        unsigned_tx.set_block_version(*source.block_version);
        unsigned_tx
    }
}

impl TryFrom<&external::UnsignedTx> for UnsignedTx {
    type Error = ConversionError;

    fn try_from(source: &external::UnsignedTx) -> Result<Self, Self::Error> {
        Ok(UnsignedTx {
            tx_prefix: source.get_tx_prefix().try_into()?,
            rings: source
                .get_rings()
                .iter()
                .map(|input| input.try_into())
                .collect::<Result<_, _>>()?,
            output_secrets: source
                .get_output_secrets()
                .iter()
                .map(|output| output.try_into())
                .collect::<Result<_, _>>()?,
            block_version: BlockVersion::try_from(source.get_block_version())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::AccountKey;
    use mc_fog_report_validation_test_utils::MockFogResolver;
    use mc_transaction_core::{tokens::Mob, Amount, BlockVersion, Token};
    use mc_transaction_std::{
        test_utils::get_input_credentials, DefaultTxOutputsOrdering, EmptyMemoBuilder,
        TransactionBuilder, UnsignedTx,
    };
    use rand::{rngs::StdRng, SeedableRng};

    // Test converting between external::UnsignedTx and
    // mc_transaction_std::UnsignedTx
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
                EmptyMemoBuilder::default(),
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
                .build_unsigned::<StdRng, DefaultTxOutputsOrdering>()
                .unwrap();

            // Converting mc_transaction_std::UnsignedTx -> external::UnsignedTx ->
            // mc_transaction_std::UnsignedTx should be the identity function.
            {
                let external_unsigned_tx: external::UnsignedTx = (&unsigned_tx).into();
                let recovered_unsigned_tx: UnsignedTx = (&external_unsigned_tx).try_into().unwrap();
                assert_eq!(unsigned_tx, recovered_unsigned_tx);
            }
        }
    }
}
