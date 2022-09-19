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
