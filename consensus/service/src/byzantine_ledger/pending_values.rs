// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A utility object for keeping track of pending transaction hashes.

use crate::tx_manager::TxManager;
use mc_transaction_core::tx::TxHash;
use std::{
    collections::{hash_map::Entry::Vacant, HashMap},
    sync::Arc,
    time::Instant,
};

/// A list of transactions that this node will attempt to submit to consensus.
/// Invariant: each pending transaction is well-formed.
/// Invariant: each pending transaction is valid w.r.t he current ledger.
pub struct PendingValues<TXM: TxManager> {
    // Transaction manager instance, used for validating values.
    tx_manager: Arc<TXM>,

    /// We need to store pending values vec so we can process values
    /// on a first-come first-served basis. However, we want to be able to:
    /// 1) Efficiently see if we already have a given transaction and ignore
    /// duplicates 2) Track how long each transaction took to externalize.
    ///
    /// To accomplish these goals we store, in addition to the queue of pending
    /// values, a map that maps a value to when we first encountered it.
    /// This essentially gives us an ordered HashMap.
    ///
    /// Note that we only store a timestamp for values that were handed to us
    /// directly from a client. That behavior is enforced by
    /// ByzantineLedger. We skip tracking processing times for relayed
    /// values since we want to track the time from when the network first
    /// saw a value, and not when a specific node saw it.
    pending_values: Vec<TxHash>,
    pending_values_map: HashMap<TxHash, Option<Instant>>,
}

impl<TXM: TxManager> PendingValues<TXM> {
    /// Create a new instance of `PendingValues`.
    pub fn new(tx_manager: Arc<TXM>) -> Self {
        Self {
            tx_manager,
            pending_values: Vec::new(),
            pending_values_map: HashMap::new(),
        }
    }

    /// Check whether the list of pending values is empty.
    pub fn is_empty(&self) -> bool {
        // Invariant
        assert_eq!(self.pending_values.len(), self.pending_values_map.len());

        self.pending_values.is_empty()
    }

    /// Get the number of pending values.
    pub fn len(&self) -> usize {
        // Invariant
        assert_eq!(self.pending_values.len(), self.pending_values_map.len());

        self.pending_values.len()
    }

    /// Try and add a pending value, associated with a given timestamp, to the
    /// list. Returns `true` if the value is valid and not already on the
    /// list, false otherwise.
    pub fn push(&mut self, tx_hash: TxHash, timestamp: Option<Instant>) -> bool {
        if let Vacant(entry) = self.pending_values_map.entry(tx_hash) {
            // A new transaction.
            if self.tx_manager.validate(&tx_hash).is_ok() {
                // The transaction is well-formed and valid.
                entry.insert(timestamp);
                self.pending_values.push(tx_hash);
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Iterate over the list of pending values.
    pub fn iter(&self) -> impl Iterator<Item = &TxHash> {
        self.pending_values.iter()
    }

    /// Try and get the timestamp associated with a given value.
    pub fn get_timestamp_for_value(&self, tx_hash: &TxHash) -> Option<Instant> {
        self.pending_values_map.get(tx_hash).cloned().flatten()
    }

    /// Retains only the values specified by the predicate.
    pub fn retain<F>(&mut self, predicate: F)
    where
        F: Fn(&TxHash) -> bool,
    {
        self.pending_values_map
            .retain(|tx_hash, _| predicate(tx_hash));

        // (Help the borrow checker)
        let self_pending_values_map = &self.pending_values_map;
        self.pending_values
            .retain(|tx_hash| self_pending_values_map.contains_key(tx_hash));

        // Invariant
        assert_eq!(self.pending_values_map.len(), self.pending_values.len());
    }

    /// Clear any pending values that are no longer valid.
    pub fn clear_invalid_values(&mut self) {
        let tx_manager = self.tx_manager.clone();
        self.retain(|tx_hash| tx_manager.validate(tx_hash).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_manager::{MockTxManager, TxManagerError};
    use mc_transaction_core::validation::TransactionValidationError;
    use mockall::predicate::eq;
    use std::{collections::HashSet, iter::FromIterator};

    #[test]
    /// Should only allow valid values to be pushed.
    fn test_push_skips_invalid_values() {
        let mut tx_manager = MockTxManager::new();

        // A few test values.
        let values = vec![TxHash([1u8; 32]), TxHash([2u8; 32]), TxHash([3u8; 32])];

        // `validate` should be called one for each pending value.
        tx_manager
            .expect_validate()
            .with(eq(values[0].clone()))
            .return_const(Ok(()));
        // This transaction has expired.
        tx_manager
            .expect_validate()
            .with(eq(values[1].clone()))
            .return_const(Err(TxManagerError::TransactionValidation(
                TransactionValidationError::TombstoneBlockExceeded,
            )));
        tx_manager
            .expect_validate()
            .with(eq(values[2].clone()))
            .return_const(Ok(()));

        let mut pending_values = PendingValues::new(Arc::new(tx_manager));
        assert!(pending_values.push(values[0].clone(), None));
        assert!(!pending_values.push(values[1].clone(), None));
        assert!(pending_values.push(values[2].clone(), None));

        assert_eq!(
            pending_values.pending_values,
            vec![values[0].clone(), values[2].clone(),]
        );
        assert_eq!(
            pending_values.pending_values_map,
            HashMap::from_iter(vec![(values[0].clone(), None), (values[2].clone(), None)])
        );
    }

    #[test]
    /// Should only allow a single instance of each value
    fn test_push_skips_already_present_values() {
        let mut tx_manager = MockTxManager::new();

        // A few test values.
        let values = vec![TxHash([1u8; 32]), TxHash([2u8; 32]), TxHash([3u8; 32])];

        // All values are considered valid for this test.
        tx_manager.expect_validate().return_const(Ok(()));

        let mut pending_values = PendingValues::new(Arc::new(tx_manager));
        assert!(pending_values.push(values[0].clone(), None));
        assert!(pending_values.push(values[1].clone(), None));
        assert!(pending_values.push(values[2].clone(), None));

        assert!(!pending_values.push(values[0].clone(), None));
        assert!(!pending_values.push(values[1].clone(), Some(Instant::now())));
        assert!(!pending_values.push(values[2].clone(), None));

        assert_eq!(pending_values.pending_values, values,);
        assert_eq!(
            pending_values.pending_values_map,
            HashMap::from_iter(vec![
                (values[0].clone(), None),
                (values[1].clone(), None),
                (values[2].clone(), None)
            ])
        );
    }

    #[test]
    /// Should discard values that are no longer valid.
    fn test_clear_invalid_values_discards_invalid_values() {
        let mut tx_manager = MockTxManager::new();

        // A few test values.
        let values = vec![TxHash([1u8; 32]), TxHash([2u8; 32]), TxHash([3u8; 32])];

        // `validate` should be called one for each pending value.
        tx_manager
            .expect_validate()
            .with(eq(values[0].clone()))
            .return_const(Ok(()));
        // This transaction has expired.
        tx_manager
            .expect_validate()
            .with(eq(values[1].clone()))
            .return_const(Err(TxManagerError::TransactionValidation(
                TransactionValidationError::TombstoneBlockExceeded,
            )));
        tx_manager
            .expect_validate()
            .with(eq(values[2].clone()))
            .return_const(Ok(()));

        // Create new PendingValues and forcefully shove the pending values into it in
        // order to skip the validation call done by `push()`.
        let mut pending_values = PendingValues::new(Arc::new(tx_manager));

        pending_values.pending_values = values.clone();
        pending_values.pending_values_map = values
            .iter()
            .cloned()
            .map(|tx_hash| (tx_hash, Some(Instant::now())))
            .collect();

        pending_values.clear_invalid_values();

        // The second transaction is no longer valid and should be removed.
        let expected_pending_values = vec![values[0].clone(), values[2].clone()];
        assert_eq!(pending_values.pending_values, expected_pending_values);
        assert_eq!(
            pending_values.pending_values.len(),
            pending_values.pending_values_map.len()
        );
        assert_eq!(
            pending_values
                .pending_values_map
                .keys()
                .cloned()
                .collect::<HashSet<_>>(),
            HashSet::from_iter(expected_pending_values),
        );
    }
}
