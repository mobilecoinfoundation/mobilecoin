// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::Tx.

use crate::{external, ConversionError};
use mc_transaction_core::tx::Tx;

impl From<&Tx> for external::Tx {
    fn from(source: &Tx) -> Self {
        Self {
            prefix: Some((&source.prefix).into()),
            signature: Some((&source.signature).into()),
        }
    }
}

impl TryFrom<&external::Tx> for Tx {
    type Error = ConversionError;

    fn try_from(source: &external::Tx) -> Result<Self, Self::Error> {
        let prefix = source
            .prefix
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;
        let signature = source
            .signature
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        Ok(Tx { prefix, signature })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::AccountKey;
    use mc_crypto_ring_signature_signer::NoKeysRingSigner;
    use mc_fog_report_validation_test_utils::MockFogResolver;
    use mc_transaction_core::{
        constants::MILLIMOB_TO_PICOMOB, tokens::Mob, tx::Tx, Amount, BlockVersion, Token, TokenId,
    };
    use mc_transaction_std::{
        test_utils::get_input_credentials, EmptyMemoBuilder, ReservedSubaddresses,
        SignedContingentInputBuilder, TransactionBuilder,
    };
    use mc_util_serial::round_trip_message;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    /// Tx --> externalTx --> Tx should be the identity function, for simple tx
    fn test_convert_tx() {
        // Generate a Tx to test with. This is copied from
        // transaction_builder.rs::test_simple_transaction
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

            let tx = transaction_builder
                .build(&NoKeysRingSigner {}, &mut rng)
                .unwrap();

            round_trip_message::<Tx, external::Tx>(&tx);
        }
    }

    #[test]
    /// Tx --> externalTx --> Tx should be the identity function, for tx with
    /// input rules
    fn test_convert_tx_with_input_rules() {
        // Generate a Tx to test with. This is copied from
        // transaction_builder.rs::test_simple_transaction
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        for block_version in BlockVersion::iterator().skip(3) {
            let alice = AccountKey::random(&mut rng);
            let bob = AccountKey::random(&mut rng);
            let charlie = AccountKey::random(&mut rng);

            let token2 = TokenId::from(2);

            let fpr = MockFogResolver::default();

            // Charlie makes a signed contingent input, offering 1000 token2's for 1 MOB
            let input_credentials = get_input_credentials(
                block_version,
                Amount::new(1000, token2),
                &charlie,
                &fpr,
                &mut rng,
            );
            let proofs = input_credentials.membership_proofs.clone();
            let mut sci_builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                fpr.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            sci_builder
                .add_required_output(
                    Amount::new(1000 * MILLIMOB_TO_PICOMOB, Mob::ID),
                    &charlie.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            let mut sci = sci_builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

            // Alice adds proofs to the SCI
            sci.tx_in.proofs = proofs;

            // Alice sends this token2 amount to Bob from Charlie, paying Charlie 1 MOB
            // as he desires, and returning .475 MOB as change to herself.
            let mut transaction_builder = TransactionBuilder::new(
                block_version,
                Amount::new(Mob::MINIMUM_FEE, Mob::ID),
                fpr.clone(),
                EmptyMemoBuilder::default(),
            )
            .unwrap();

            transaction_builder.add_input(get_input_credentials(
                block_version,
                Amount::new(1475 * MILLIMOB_TO_PICOMOB, Mob::ID),
                &alice,
                &fpr,
                &mut rng,
            ));
            transaction_builder.add_presigned_input(sci).unwrap();

            transaction_builder
                .add_output(
                    Amount::new(1000, token2),
                    &bob.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            transaction_builder
                .add_change_output(
                    Amount::new(475 * MILLIMOB_TO_PICOMOB - Mob::MINIMUM_FEE, Mob::ID),
                    &ReservedSubaddresses::from(&alice),
                    &mut rng,
                )
                .unwrap();

            let tx = transaction_builder
                .build(&NoKeysRingSigner {}, &mut rng)
                .unwrap();

            round_trip_message::<Tx, external::Tx>(&tx);
        }
    }
}
