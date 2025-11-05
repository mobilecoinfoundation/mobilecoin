// Copyright (c) 2018-2025 The MobileCoin Foundation

//! Convert to/from mc_transaction_builder::TxBlueprint.

use crate::{external, ConversionError};
use mc_transaction_builder::TxBlueprint;
use mc_transaction_core::{ring_ct::InputRing, tx::TxIn, Amount};
use std::convert::{TryFrom, TryInto};

impl From<&TxBlueprint> for external::TxBlueprint {
    fn from(source: &TxBlueprint) -> Self {
        Self {
            inputs: source.inputs.iter().map(|input| input.into()).collect(),
            rings: source.rings.iter().map(|ring| ring.into()).collect(),
            outputs: source.outputs.iter().map(|output| output.into()).collect(),
            fee: Some((&source.fee).into()),
            tombstone_block: source.tombstone_block,
            block_version: *source.block_version,
        }
    }
}

impl TryFrom<&external::TxBlueprint> for TxBlueprint {
    type Error = ConversionError;

    fn try_from(source: &external::TxBlueprint) -> Result<Self, Self::Error> {
        let inputs: Vec<TxIn> = source
            .inputs
            .iter()
            .map(|proto_input| proto_input.try_into())
            .collect::<Result<_, _>>()?;
        let rings: Vec<InputRing> = source
            .rings
            .iter()
            .map(|proto_ring| proto_ring.try_into())
            .collect::<Result<_, _>>()?;
        let outputs = source
            .outputs
            .iter()
            .map(|proto_output| proto_output.try_into())
            .collect::<Result<_, _>>()?;
        let fee: Amount = source.fee.as_ref().unwrap_or(&Default::default()).into();
        let tombstone_block = source.tombstone_block;
        let block_version = source.block_version.try_into()?;

        Ok(TxBlueprint {
            inputs,
            rings,
            outputs,
            fee,
            tombstone_block,
            block_version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::AccountKey;
    use mc_blockchain_types::BlockVersion;
    use mc_crypto_ring_signature_signer::NoKeysRingSigner;
    use mc_fog_report_validation_test_utils::MockFogResolver;
    use mc_transaction_builder::{
        test_utils::get_input_credentials, EmptyMemoBuilder, ReservedSubaddresses,
        SignedContingentInputBuilder, TransactionBuilder,
    };
    use mc_transaction_core::{
        constants::MILLIMOB_TO_PICOMOB, tokens::Mob, Amount, Token, TokenId,
    };
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_tx_blueprint_conversion() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let block_version = BlockVersion::MAX;

        let alice = AccountKey::random(&mut rng);
        let bob = AccountKey::random(&mut rng);
        let charlie = AccountKey::random(&mut rng);

        let token2 = TokenId::from(2);
        let fpr = MockFogResolver::default();

        let input_credentials_sci = get_input_credentials(
            block_version,
            Amount::new(1000, token2),
            &charlie,
            &fpr,
            &mut rng,
        );
        let proofs = input_credentials_sci.membership_proofs.clone();
        let mut sci_builder = SignedContingentInputBuilder::new(
            block_version,
            input_credentials_sci.clone(),
            fpr.clone(),
            EmptyMemoBuilder,
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
        sci.tx_in.proofs = proofs;

        let mut transaction_builder = TransactionBuilder::new(
            block_version,
            Amount::new(Mob::MINIMUM_FEE, Mob::ID),
            fpr.clone(),
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

        let blueprint_orig = transaction_builder.build_blueprint().unwrap();

        let blueprint_proto: external::TxBlueprint = (&blueprint_orig).into();
        let blueprint_recovered: TxBlueprint = (&blueprint_proto).try_into().unwrap();

        assert_eq!(blueprint_orig, blueprint_recovered);
    }
}
