// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::SignedContingentInput.

use crate::{external, ConversionError};
use mc_transaction_core::{ring_signature::RingMLSAG, tx::TxIn, UnmaskedAmount};
use mc_transaction_extra::SignedContingentInput;

/// Convert mc_transaction_extra::SignedContingentInput -->
/// external::SignedContingentInput.
impl From<&SignedContingentInput> for external::SignedContingentInput {
    fn from(src: &SignedContingentInput) -> Self {
        let mut sci = external::SignedContingentInput::new();
        sci.set_block_version(src.block_version);
        sci.set_tx_in(external::TxIn::from(&src.tx_in));
        sci.set_mlsag(external::RingMLSAG::from(&src.mlsag));
        sci.set_pseudo_output_amount(external::UnmaskedAmount::from(&src.pseudo_output_amount));
        sci.set_required_output_amounts(
            src.required_output_amounts
                .iter()
                .map(external::UnmaskedAmount::from)
                .collect(),
        );
        sci.set_tx_out_global_indices(src.tx_out_global_indices.clone());

        sci
    }
}

/// Convert external::SignedContingentInput -->
/// mc_transaction_extra::SignedContingentInput.
impl TryFrom<&external::SignedContingentInput> for SignedContingentInput {
    type Error = ConversionError;

    fn try_from(src: &external::SignedContingentInput) -> Result<Self, Self::Error> {
        let block_version = src.get_block_version();
        let tx_in = TxIn::try_from(src.get_tx_in())?;
        let mlsag = RingMLSAG::try_from(src.get_mlsag())?;
        let pseudo_output_amount = UnmaskedAmount::try_from(src.get_pseudo_output_amount())?;
        let required_output_amounts = src
            .get_required_output_amounts()
            .iter()
            .map(UnmaskedAmount::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let tx_out_global_indices = src.get_tx_out_global_indices().to_vec();

        Ok(SignedContingentInput {
            block_version,
            tx_in,
            mlsag,
            pseudo_output_amount,
            required_output_amounts,
            tx_out_global_indices,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_account_keys::AccountKey;
    use mc_crypto_ring_signature_signer::NoKeysRingSigner;
    use mc_fog_report_validation_test_utils::MockFogResolver;
    use mc_transaction_builder::{
        test_utils::get_input_credentials, EmptyMemoBuilder, ReservedSubaddresses,
        SignedContingentInputBuilder,
    };
    use mc_transaction_core::{
        constants::MILLIMOB_TO_PICOMOB, tokens::Mob, Amount, BlockVersion, Token, TokenId,
    };
    use protobuf::Message;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    /// SignedContingentInput --> external::SignedContingentInput -->
    /// SignedContingentInput should be the identity function
    fn test_convert_signed_contingent_input() {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let charlie = AccountKey::random(&mut rng);

        let token2 = TokenId::from(2);

        let fpr = MockFogResolver::default();

        // Charlie makes a signed contingent input, offering 1000 token2's for 1 MOB
        let input_credentials = get_input_credentials(
            BlockVersion::MAX,
            Amount::new(1000, token2),
            &charlie,
            &fpr,
            &mut rng,
        );
        let proofs = input_credentials.membership_proofs.clone();
        let mut sci_builder = SignedContingentInputBuilder::new(
            BlockVersion::MAX,
            input_credentials,
            fpr.clone(),
            EmptyMemoBuilder::default(),
        )
        .unwrap();

        // Originator requests an output worth 1MOB destined to themselves
        sci_builder
            .add_partial_fill_output(
                Amount::new(1000 * MILLIMOB_TO_PICOMOB, Mob::ID),
                &charlie.default_subaddress(),
                &mut rng,
            )
            .unwrap();

        // Change amount matches the input value
        sci_builder
            .add_partial_fill_change_output(
                Amount::new(1000, token2),
                &ReservedSubaddresses::from(&charlie),
                &mut rng,
            )
            .unwrap();
        let mut sci = sci_builder.build(&NoKeysRingSigner {}, &mut rng).unwrap();

        sci.tx_in.proofs = proofs;
        sci.tx_out_global_indices = vec![1, 2, 3, 4];

        // decode(encode(sci)) should be the identity function.
        {
            let bytes = mc_util_serial::encode(&sci);
            let recovered_sci = mc_util_serial::decode(&bytes).unwrap();
            assert_eq!(sci, recovered_sci);
        }

        // Converting mc_transaction_extra::SignedContingentInput ->
        // external::SignedContingentInput ->
        // mc_transaction_extra::SignedContingentInput should be the identity
        // function.
        {
            let external_sci = external::SignedContingentInput::from(&sci);
            let recovered_sci = SignedContingentInput::try_from(&external_sci).unwrap();
            assert_eq!(sci, recovered_sci);
        }

        // Encoding with prost, decoding with protobuf should be the identity function.
        {
            let bytes = mc_util_serial::encode(&sci);
            let recovered_sci = external::SignedContingentInput::parse_from_bytes(&bytes).unwrap();
            assert_eq!(recovered_sci, external::SignedContingentInput::from(&sci));
        }

        // Encoding with protobuf, decoding with prost should be the identity function.
        {
            let external_sci = external::SignedContingentInput::from(&sci);
            let bytes = external_sci.write_to_bytes().unwrap();
            let recovered_sci = mc_util_serial::decode(&bytes).unwrap();
            assert_eq!(sci, recovered_sci);
        }
    }
}
