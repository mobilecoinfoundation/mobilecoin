//! Convert to/from external::Tx.

use crate::{convert::ConversionError, external};
use mc_transaction_core::{ring_signature::SignatureRctBulletproofs, tx};
use std::convert::TryFrom;

/// Convert mc_transaction_core::tx::Tx --> external::Tx.
impl From<&tx::Tx> for external::Tx {
    fn from(source: &tx::Tx) -> Self {
        let mut tx = external::Tx::new();
        tx.set_prefix(external::TxPrefix::from(&source.prefix));
        tx.set_signature(external::SignatureRctBulletproofs::from(&source.signature));
        tx
    }
}

/// Convert external::Tx --> mc_transaction_core::tx::Tx.
impl TryFrom<&external::Tx> for tx::Tx {
    type Error = ConversionError;

    fn try_from(source: &external::Tx) -> Result<Self, Self::Error> {
        let prefix = tx::TxPrefix::try_from(source.get_prefix())?;
        let signature = SignatureRctBulletproofs::try_from(source.get_signature())?;
        Ok(tx::Tx { prefix, signature })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::AccountKey;
    use mc_fog_report_validation_test_utils::MockFogResolver;
    use mc_transaction_core::{
        constants::MILLIMOB_TO_PICOMOB, tokens::Mob, tx::Tx, Amount, BlockVersion, Token, TokenId,
    };
    use mc_transaction_std::{
        test_utils::get_input_credentials, ChangeDestination, EmptyMemoBuilder,
        SignedContingentInputBuilder, TransactionBuilder,
    };
    use protobuf::Message;
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

            let tx = transaction_builder.build(&mut rng).unwrap();

            // decode(encode(tx)) should be the identity function.
            {
                let bytes = mc_util_serial::encode(&tx);
                let recovered_tx = mc_util_serial::decode(&bytes).unwrap();
                assert_eq!(tx, recovered_tx);
            }

            // Converting mc_transaction_core::Tx -> external::Tx -> mc_transaction_core::Tx
            // should be the identity function.
            {
                let external_tx: external::Tx = external::Tx::from(&tx);
                let recovered_tx: Tx = Tx::try_from(&external_tx).unwrap();
                assert_eq!(tx, recovered_tx);
            }

            // Encoding with prost, decoding with protobuf should be the identity function.
            {
                let bytes = mc_util_serial::encode(&tx);
                let recovered_tx = external::Tx::parse_from_bytes(&bytes).unwrap();
                assert_eq!(recovered_tx, external::Tx::from(&tx));
            }

            // Encoding with protobuf, decoding with prost should be the identity function.
            {
                let external_tx: external::Tx = external::Tx::from(&tx);
                let bytes = external_tx.write_to_bytes().unwrap();
                let recovered_tx: Tx = mc_util_serial::decode(&bytes).unwrap();
                assert_eq!(tx, recovered_tx);
            }
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
            let mut sci_builder = SignedContingentInputBuilder::new(
                block_version,
                input_credentials,
                vec![59],
                fpr.clone(),
                EmptyMemoBuilder::default(),
            );

            sci_builder
                .add_output(
                    Amount::new(1000 * MILLIMOB_TO_PICOMOB, Mob::ID),
                    &charlie.default_subaddress(),
                    &mut rng,
                )
                .unwrap();

            let sci = sci_builder.build(&mut rng).unwrap();

            // Alice sends this token2 amount to Bob from Charlie, paying Charlie 1000 MOB
            // as he desires.
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
                    &ChangeDestination::from(&alice),
                    &mut rng,
                )
                .unwrap();

            let tx = transaction_builder.build(&mut rng).unwrap();

            // decode(encode(tx)) should be the identity function.
            {
                let bytes = mc_util_serial::encode(&tx);
                let recovered_tx = mc_util_serial::decode(&bytes).unwrap();
                assert_eq!(tx, recovered_tx);
            }

            // Converting mc_transaction_core::Tx -> external::Tx -> mc_transaction_core::Tx
            // should be the identity function.
            {
                let external_tx: external::Tx = external::Tx::from(&tx);
                let recovered_tx: Tx = Tx::try_from(&external_tx).unwrap();
                assert_eq!(tx, recovered_tx);
            }

            // Encoding with prost, decoding with protobuf should be the identity function.
            {
                let bytes = mc_util_serial::encode(&tx);
                let recovered_tx = external::Tx::parse_from_bytes(&bytes).unwrap();
                assert_eq!(recovered_tx, external::Tx::from(&tx));
            }

            // Encoding with protobuf, decoding with prost should be the identity function.
            {
                let external_tx: external::Tx = external::Tx::from(&tx);
                let bytes = external_tx.write_to_bytes().unwrap();
                let recovered_tx: Tx = mc_util_serial::decode(&bytes).unwrap();
                assert_eq!(tx, recovered_tx);
            }
        }
    }
}
