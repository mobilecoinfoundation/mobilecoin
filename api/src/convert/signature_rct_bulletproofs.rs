//! Convert to/from external::SignatureRctBulletproofs

use crate::{convert::ConversionError, external};
use mc_transaction_core::{
    ring_signature::{RingMLSAG, SignatureRctBulletproofs},
    CompressedCommitment,
};
use std::convert::TryFrom;

impl From<&SignatureRctBulletproofs> for external::SignatureRctBulletproofs {
    fn from(source: &SignatureRctBulletproofs) -> Self {
        let mut signature = external::SignatureRctBulletproofs::new();

        let ring_signatures: Vec<external::RingMLSAG> = source
            .ring_signatures
            .iter()
            .map(external::RingMLSAG::from)
            .collect();
        signature.set_ring_signatures(ring_signatures.into());

        let pseudo_output_commitments: Vec<external::CompressedRistretto> = source
            .pseudo_output_commitments
            .iter()
            .map(external::CompressedRistretto::from)
            .collect();
        signature.set_pseudo_output_commitments(pseudo_output_commitments.into());

        signature.set_range_proofs(source.range_proof_bytes.clone());

        signature
    }
}

impl TryFrom<&external::SignatureRctBulletproofs> for SignatureRctBulletproofs {
    type Error = ConversionError;

    fn try_from(source: &external::SignatureRctBulletproofs) -> Result<Self, Self::Error> {
        let mut ring_signatures: Vec<RingMLSAG> = Vec::new();
        for ring_signature in source.get_ring_signatures() {
            ring_signatures.push(RingMLSAG::try_from(ring_signature)?);
        }

        let mut pseudo_output_commitments: Vec<CompressedCommitment> = Vec::new();
        for pseudo_output_commitment in source.get_pseudo_output_commitments() {
            pseudo_output_commitments
                .push(CompressedCommitment::try_from(pseudo_output_commitment)?);
        }

        let range_proof_bytes = source.get_range_proofs().to_vec();

        Ok(SignatureRctBulletproofs {
            ring_signatures,
            pseudo_output_commitments,
            range_proof_bytes,
        })
    }
}
