//! Transaction summary creation

use alloc::{vec::Vec, collections::BTreeMap};

use crate::{
    tx::TxPrefix,
    TxOut,
};

use mc_crypto_keys::CompressedRistrettoPublic;
use mc_crypto_ring_signature::CompressedCommitment;
use mc_util_zip_exact::{zip_exact, ZipExactError};

pub use mc_transaction_types::tx_summary::*;

/// [Summarize] trait for constructing [TxSummary] object from foreign types
pub trait Summarize {
    /// Make a TxSummary for a given TxPrefix and pseudo-output commitments
    fn summarize(
        &self,
    ) -> Result<TxSummary, ZipExactError>;
}

impl Summarize for (&TxPrefix, &[CompressedCommitment]) {
    fn summarize(
        &self,
    ) -> Result<TxSummary, ZipExactError> {
        let (tx_prefix, pseudo_output_commitments) = self;

        // Scratch which helps us associate outputs to inputs with rules
        let mut input_rules_associated_tx_outs: BTreeMap<CompressedRistrettoPublic, TxOut> =
            Default::default();

        // Compute the inputs
        let inputs: Vec<TxInSummary> =
            zip_exact(tx_prefix.inputs.iter(), pseudo_output_commitments.iter())?
                .map(|(input, commitment)| {
                    let mut result = TxInSummary {
                        pseudo_output_commitment: *commitment,
                        ..Default::default()
                    };
                    if let Some(rules) = &input.input_rules {
                        result.input_rules_digest = rules.canonical_digest().to_vec();
                        let mut associated_tx_outs = rules.associated_tx_outs();
                        input_rules_associated_tx_outs.append(&mut associated_tx_outs);
                    }
                    result
                })
                .collect();

        let outputs: Vec<TxOutSummary> = tx_prefix
            .outputs
            .iter()
            .map(|src| TxOutSummary {
                masked_amount: src.masked_amount.clone(),
                target_key: src.target_key,
                public_key: src.public_key,
                // Check if the public key and target key of this TxOutSummary match to a TxOut in
                // the associated_tx_outs list. The masked amount is not necessarily
                // expected to match, and no other fields of TxOut are in the TxOutSummary
                // This should generally agree with `TxOut::eq_ignoring_amount`
                associated_to_input_rules: input_rules_associated_tx_outs
                    .get(&src.public_key)
                    .map(|tx_out| tx_out.target_key == src.target_key)
                    .unwrap_or(false),
            })
            .collect();

        Ok(TxSummary {
            outputs,
            inputs,
            fee: tx_prefix.fee,
            fee_token_id: tx_prefix.fee_token_id,
            tombstone_block: tx_prefix.tombstone_block,
        })
    }
}