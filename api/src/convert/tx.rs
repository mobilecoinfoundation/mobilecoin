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
    use mc_account_keys::{AccountKey, PublicAddress};
    use mc_crypto_keys::RistrettoPublic;
    use mc_transaction_core::{
        onetime_keys::recover_onetime_private_key,
        tx::{Tx, TxOut, TxOutMembershipProof},
    };
    use mc_transaction_core_test_utils::MockFogResolver;
    use mc_transaction_std::{EmptyMemoBuilder, InputCredentials, TransactionBuilder};
    use protobuf::Message;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    /// Tx --> externalTx --> Tx should be the identity function.
    fn test_convert_tx() {
        // Generate a Tx to test with. This is copied from
        // transaction_builder.rs::test_simple_transaction
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let alice = AccountKey::random(&mut rng);
        let bob = AccountKey::random(&mut rng);
        let charlie = AccountKey::random(&mut rng);

        let minted_outputs: Vec<TxOut> = {
            // Mint an initial collection of outputs, including one belonging to
            // `sender_account`.
            let mut recipient_and_amounts: Vec<(PublicAddress, u64)> = Vec::new();
            recipient_and_amounts.push((alice.default_subaddress(), 65536));

            // Some outputs belonging to this account will be used as mix-ins.
            recipient_and_amounts.push((charlie.default_subaddress(), 65536));
            recipient_and_amounts.push((charlie.default_subaddress(), 65536));
            mc_transaction_core_test_utils::get_outputs(&recipient_and_amounts, &mut rng)
        };

        let mut transaction_builder =
            TransactionBuilder::new(MockFogResolver::default(), EmptyMemoBuilder::default());

        let ring: Vec<TxOut> = minted_outputs.clone();
        let public_key = RistrettoPublic::try_from(&minted_outputs[0].public_key).unwrap();
        let onetime_private_key = recover_onetime_private_key(
            &public_key,
            alice.view_private_key(),
            &alice.default_subaddress_spend_private(),
        );

        let membership_proofs: Vec<TxOutMembershipProof> = ring
            .iter()
            .map(|_tx_out| {
                // TransactionBuilder does not validate membership proofs, but does require one
                // for each ring member.
                TxOutMembershipProof::new(0, 0, Default::default())
            })
            .collect();

        let input_credentials = InputCredentials::new(
            ring.clone(),
            membership_proofs,
            0,
            onetime_private_key,
            *alice.view_private_key(),
        )
        .unwrap();

        transaction_builder.add_input(input_credentials);
        transaction_builder.set_fee(0).unwrap();
        transaction_builder
            .add_output(65536, &bob.default_subaddress(), &mut rng)
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
