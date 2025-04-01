// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from mc_transaction_core::ring_ct::InputRing.

use crate::{external, external::input_ring::Ring, ConversionError};
use mc_crypto_ring_signature_signer::SignableInputRing;
use mc_transaction_core::ring_ct::{InputRing, PresignedInputRing};

impl From<&InputRing> for external::InputRing {
    fn from(source: &InputRing) -> Self {
        match source {
            InputRing::Presigned(presigned_input_ring) => presigned_input_ring.into(),
            InputRing::Signable(signable_input_ring) => signable_input_ring.into(),
        }
    }
}

impl TryFrom<&external::InputRing> for InputRing {
    type Error = ConversionError;

    fn try_from(source: &external::InputRing) -> Result<Self, Self::Error> {
        match source
            .ring
            .as_ref()
            .ok_or_else(|| ConversionError::MissingField("ring".to_string()))?
        {
            external::input_ring::Ring::Presigned(presigned) => {
                Ok(InputRing::Presigned((presigned).try_into()?))
            }
            external::input_ring::Ring::Signable(signable) => {
                Ok(InputRing::Signable((signable).try_into()?))
            }
        }
    }
}

impl From<&PresignedInputRing> for external::InputRing {
    fn from(source: &PresignedInputRing) -> Self {
        Self {
            ring: Some(external::input_ring::Ring::Presigned(source.into())),
        }
    }
}

impl From<&PresignedInputRing> for external::PresignedInputRing {
    fn from(source: &PresignedInputRing) -> Self {
        Self {
            mlsag: Some((&source.mlsag).into()),
            pseudo_output_secret: Some((&source.pseudo_output_secret).into()),
        }
    }
}

impl TryFrom<&external::PresignedInputRing> for PresignedInputRing {
    type Error = ConversionError;

    fn try_from(source: &external::PresignedInputRing) -> Result<Self, Self::Error> {
        Ok(PresignedInputRing {
            mlsag: source
                .mlsag
                .as_ref()
                .unwrap_or(&Default::default())
                .try_into()?,
            pseudo_output_secret: source
                .pseudo_output_secret
                .as_ref()
                .unwrap_or(&Default::default())
                .try_into()?,
        })
    }
}

impl From<&SignableInputRing> for external::InputRing {
    fn from(source: &SignableInputRing) -> Self {
        Self {
            ring: Some(Ring::Signable(source.into())),
        }
    }
}

impl From<&SignableInputRing> for external::SignableInputRing {
    fn from(source: &SignableInputRing) -> Self {
        Self {
            members: source.members.iter().map(|member| member.into()).collect(),
            input_secret: Some((&source.input_secret).into()),
            real_input_index: source.real_input_index as u32,
        }
    }
}

impl TryFrom<&external::SignableInputRing> for SignableInputRing {
    type Error = ConversionError;

    fn try_from(source: &external::SignableInputRing) -> Result<Self, Self::Error> {
        let members = source
            .members
            .iter()
            .map(|member| member.try_into())
            .collect::<Result<Vec<_>, _>>()?;
        let input_secret = source
            .input_secret
            .as_ref()
            .unwrap_or(&Default::default())
            .try_into()?;
        let real_input_index = source.real_input_index as usize;
        Ok(SignableInputRing {
            members,
            input_secret,
            real_input_index,
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
    use mc_transaction_core::{tokens::Mob, Amount, BlockVersion, Token};
    use rand::{rngs::StdRng, SeedableRng};

    // Test converting between external::InputRing and
    // mc_transaction_core::ring_signature::InputRing
    #[test]
    fn test_input_ring_conversion() {
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

            let input_ring = unsigned_tx.rings[0].clone();

            // Converting mc_transaction_core::ring_signature::InputRing ->
            // external::InputRing -> mc_transaction_core::ring_signature::
            // InputRing should be the identity function.
            {
                let external_input_ring: external::InputRing = (&input_ring).into();
                let recovered_input_ring: InputRing = (&external_input_ring).try_into().unwrap();
                assert_eq!(input_ring, recovered_input_ring);
            }
        }
    }
}
