use std::convert::{TryFrom, TryInto};

use mc_crypto_ring_signature_signer::SignableInputRing;
use mc_transaction_core::ring_ct::{InputRing, PresignedInputRing};

use crate::{external, ConversionError};

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
            external::InputRing_oneof_ring::presigned(presigned) => {
                Ok(InputRing::Presigned((presigned).try_into()?))
            }
            external::InputRing_oneof_ring::signable(signable) => {
                Ok(InputRing::Signable((signable).try_into()?))
            }
        }
    }
}

impl From<&PresignedInputRing> for external::InputRing {
    fn from(source: &PresignedInputRing) -> Self {
        let mut input_ring = external::InputRing::new();
        input_ring.set_presigned(source.into());
        input_ring
    }
}

impl From<&PresignedInputRing> for external::PresignedInputRing {
    fn from(source: &PresignedInputRing) -> Self {
        let mut presigned_input_ring = external::PresignedInputRing::new();
        presigned_input_ring.set_mlsag((&source.mlsag).into());
        presigned_input_ring.set_pseudo_output_secret((&source.pseudo_output_secret).into());
        presigned_input_ring
    }
}

impl TryFrom<&external::PresignedInputRing> for PresignedInputRing {
    type Error = ConversionError;

    fn try_from(source: &external::PresignedInputRing) -> Result<Self, Self::Error> {
        Ok(PresignedInputRing {
            mlsag: source.get_mlsag().try_into()?,
            pseudo_output_secret: source.get_pseudo_output_secret().try_into()?,
        })
    }
}

impl From<&SignableInputRing> for external::InputRing {
    fn from(source: &SignableInputRing) -> Self {
        let mut input_ring = external::InputRing::new();
        input_ring.set_signable(source.into());
        input_ring
    }
}

impl From<&SignableInputRing> for external::SignableInputRing {
    fn from(source: &SignableInputRing) -> Self {
        let mut ring = external::SignableInputRing::new();
        ring.set_members(protobuf::RepeatedField::from_vec(
            source.members.iter().map(|member| member.into()).collect(),
        ));
        ring.set_input_secret((&source.input_secret).into());
        ring.set_real_input_index(source.real_input_index as u32);
        ring
    }
}

impl TryFrom<&external::SignableInputRing> for SignableInputRing {
    type Error = ConversionError;

    fn try_from(source: &external::SignableInputRing) -> Result<Self, Self::Error> {
        let members = source
            .get_members()
            .iter()
            .map(|member| member.try_into())
            .collect::<Result<Vec<_>, _>>()?;
        let input_secret = source.get_input_secret().try_into()?;
        let real_input_index = source.get_real_input_index() as usize;
        Ok(SignableInputRing {
            members,
            input_secret,
            real_input_index,
        })
    }
}
