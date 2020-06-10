// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::tx_manager::UntrustedInterfaces;
use mc_consensus_enclave::WellFormedTxContext;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_transaction_core::{
    ring_signature::KeyImage,
    tx::{TxHash, TxOutMembershipProof},
    validation::TransactionValidationResult,
};
use std::{collections::BTreeSet, iter::FromIterator};

#[derive(Clone)]
pub struct TrivialTxManagerUntrustedInterfaces;

impl UntrustedInterfaces for TrivialTxManagerUntrustedInterfaces {
    fn well_formed_check(
        &self,
        _highest_indices: &[u64],
        _key_images: &[KeyImage],
        _output_public_keys: &[CompressedRistrettoPublic],
    ) -> TransactionValidationResult<(u64, Vec<TxOutMembershipProof>)> {
        Ok((1, Vec::new()))
    }

    fn is_valid(&self, _context: &WellFormedTxContext) -> TransactionValidationResult<()> {
        Ok(())
    }

    fn combine(
        &self,
        tx_contexts: &[&WellFormedTxContext],
        max_elements: usize,
    ) -> BTreeSet<TxHash> {
        BTreeSet::from_iter(
            tx_contexts
                .iter()
                .take(max_elements)
                .map(|tx_context| tx_context.tx_hash())
                .cloned(),
        )
    }
}
