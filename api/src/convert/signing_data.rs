// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_transaction_core::ring_ct::SigningData.

use crate::{external, ConversionError};
use mc_transaction_core::ring_ct::SigningData;

impl From<&SigningData> for external::SigningData {
    fn from(src: &SigningData) -> Self {
        let mut signing_data = external::SigningData::new();
        signing_data.set_extended_message_digest(src.extended_message_digest.clone());
        signing_data.set_pseudo_output_blindings(
            src.pseudo_output_blindings
                .iter()
                .map(|blinding| blinding.into())
                .collect(),
        );
        signing_data.set_pseudo_output_commitments(
            src.pseudo_output_commitments
                .iter()
                .map(|commitment| commitment.into())
                .collect(),
        );
        signing_data.set_range_proof_bytes(src.range_proof_bytes.clone());
        signing_data.set_range_proofs(protobuf::RepeatedField::from_vec(src.range_proofs.clone()));
        signing_data.set_pseudo_output_token_ids(src.pseudo_output_token_ids.clone());
        signing_data.set_output_token_ids(src.output_token_ids.clone());
        signing_data
    }
}

impl TryFrom<&external::SigningData> for SigningData {
    type Error = ConversionError;

    fn try_from(src: &external::SigningData) -> Result<Self, Self::Error> {
        let pseudo_output_blindings = src
            .pseudo_output_blindings
            .iter()
            .map(|blinding| blinding.try_into())
            .collect::<Result<Vec<_>, _>>()?;
        let pseudo_output_commitments = src
            .pseudo_output_commitments
            .iter()
            .map(|commitment| commitment.try_into())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SigningData {
            extended_message_digest: src.extended_message_digest.clone(),
            pseudo_output_blindings,
            pseudo_output_commitments,
            range_proof_bytes: src.range_proof_bytes.clone(),
            range_proofs: src.range_proofs.to_vec(),
            pseudo_output_token_ids: src.pseudo_output_token_ids.clone(),
            output_token_ids: src.output_token_ids.clone(),
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
        TransactionBuilder,
    };
    use rand::{rngs::StdRng, SeedableRng};

    // Test converting between external::SigningData and
    // mc_transaction_core::ring_ct::SigningData
    #[test]
    fn test_signing_data_conversion() {
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

            let signing_data = unsigned_tx.get_signing_data(&mut rng).unwrap();

            // Converting mc_transaction_core::ring_ct::SigningData -> external::UnsignedTx
            // -> mc_transaction_core::ring_ct::SigningData should be the identity
            // function.
            {
                let external_signing_data: external::SigningData = (&signing_data).into();
                let recovered_signing_data: SigningData =
                    (&external_signing_data).try_into().unwrap();
                assert_eq!(signing_data, recovered_signing_data);
            }
        }
    }
}
