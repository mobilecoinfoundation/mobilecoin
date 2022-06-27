// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert to/from external::SignatureRctBulletproofs

use crate::{external, ConversionError};
use mc_transaction_core::{
    ring_ct::SignatureRctBulletproofs, ring_signature::RingMLSAG, CompressedCommitment,
};

impl From<&SignatureRctBulletproofs> for external::SignatureRctBulletproofs {
    fn from(source: &SignatureRctBulletproofs) -> Self {
        let ring_signatures = source
            .ring_signatures
            .iter()
            .map(external::RingMlsag::from)
            .collect();

        let pseudo_output_commitments = source
            .pseudo_output_commitments
            .iter()
            .map(external::CompressedRistretto::from)
            .collect();

        Self {
            ring_signatures,
            pseudo_output_commitments,
            range_proof_bytes: source.range_proof_bytes.clone(),
            range_proofs: source.range_proofs.clone(),
            pseudo_output_token_ids: source.pseudo_output_token_ids.clone(),
            output_token_ids: source.output_token_ids.clone(),
        }
    }
}

impl TryFrom<&external::SignatureRctBulletproofs> for SignatureRctBulletproofs {
    type Error = ConversionError;

    fn try_from(source: &external::SignatureRctBulletproofs) -> Result<Self, Self::Error> {
        let ring_signatures = source
            .ring_signatures
            .iter()
            .map(RingMLSAG::try_from)
            .collect::<Result<_, _>>()?;
        let pseudo_output_commitments = source
            .pseudo_output_commitments
            .iter()
            .map(CompressedCommitment::try_from)
            .collect::<Result<_, _>>()?;

        Ok(Self {
            ring_signatures,
            pseudo_output_commitments,
            range_proof_bytes: source.range_proof_bytes.clone(),
            range_proofs: source.range_proofs.clone(),
            pseudo_output_token_ids: source.pseudo_output_token_ids.clone(),
            output_token_ids: source.output_token_ids.clone(),
        })
    }
}
