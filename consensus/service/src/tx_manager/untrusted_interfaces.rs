// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_consensus_enclave::{TxContext, WellFormedTxContext};
use mc_transaction_core::{
    tx::{TxHash, TxOutMembershipProof},
    validation::TransactionValidationResult,
};
use std::sync::Arc;

#[cfg(test)]
use mockall::*;

/// The untrusted (i.e. non-enclave) part of validating and combining
/// transactions.
#[cfg_attr(test, automock)]
pub trait UntrustedInterfaces: Send + Sync {
    /// Performs **only** the untrusted part of the well-formed check.
    ///
    /// Returns the local ledger's block index and membership proofs for each
    /// highest index.
    fn well_formed_check(
        &self,
        tx_context: &TxContext,
    ) -> TransactionValidationResult<(u64, Vec<TxOutMembershipProof>)>;

    /// Checks if a transaction is valid (see definition in validators.rs).
    ///
    /// # Arguments
    /// * `context` - The tx context to validate.
    /// * `timestamp` - The timestamp to validate. ms since Unix epoch. If None,
    ///   then only the validity of the `context` will be checked.
    fn is_valid(
        &self,
        context: Arc<WellFormedTxContext>,
        timestamp: Option<u64>,
    ) -> TransactionValidationResult<()>;

    /// Combines a set of "candidate values" into a "composite value".
    /// This assumes all values are well-formed and safe to append to the ledger
    /// individually.
    ///
    /// # Arguments
    /// * `tx_contexts` - "Candidate" transactions and their proposed timestamp
    ///   in ms since Unix epoch. Each is assumed to be individually valid.
    /// * `max_elements` - Maximal number of elements to output.
    ///
    /// Returns a bounded, deterministically-ordered list of transactions that
    /// are safe to append to the ledger. If there are any duplicate
    /// transactions the ones with the largest timestamp will be returned.
    fn combine(
        &self,
        tx_contexts: &[(Arc<WellFormedTxContext>, u64)],
        max_elements: usize,
    ) -> Vec<(TxHash, u64)>;

    fn get_tx_out_proof_of_memberships(
        &self,
        indexes: &[u64],
    ) -> TransactionValidationResult<Vec<TxOutMembershipProof>>;
}
