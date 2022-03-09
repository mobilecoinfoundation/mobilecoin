// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A utility object for keeping track of pending transaction hashes.

use crate::{mint_tx_manager::MintTxManager, tx_manager::TxManager};
use mc_peers::ConsensusValue;
use std::{
    collections::{hash_map::Entry::Vacant, HashMap},
    sync::Arc,
    time::Instant,
};

/// A list of transactions that this node will attempt to submit to consensus.
/// Invariant: each pending transaction is well-formed.
/// Invariant: each pending transaction is valid w.r.t he current ledger.
pub struct PendingValues<TXM: TxManager, MTXM: MintTxManager> {
    // Transaction manager instance, used for validating values.
    tx_manager: Arc<TXM>,

    // Mint transaction manager instance, used for validating mint transactions.
    mint_tx_manager: Arc<MTXM>,

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
    pending_values: Vec<ConsensusValue>,
    pending_values_map: HashMap<ConsensusValue, Option<Instant>>,
}

impl<TXM: TxManager, MTXM: MintTxManager> PendingValues<TXM, MTXM> {
    /// Create a new instance of `PendingValues`.
    pub fn new(tx_manager: Arc<TXM>, mint_tx_manager: Arc<MTXM>) -> Self {
        Self {
            tx_manager,
            mint_tx_manager,
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
    pub fn push(&mut self, value: ConsensusValue, timestamp: Option<Instant>) -> bool {
        if let Vacant(entry) = self.pending_values_map.entry(value.clone()) {
            match value {
                ConsensusValue::TxHash(tx_hash) => {
                    // A new transaction.
                    if self.tx_manager.validate(&tx_hash).is_ok() {
                        // The transaction is well-formed and valid.
                        entry.insert(timestamp);
                        self.pending_values.push(value);
                        true
                    } else {
                        false
                    }
                }

                ConsensusValue::SetMintConfigTx(ref set_mint_config_tx) => {
                    if self
                        .mint_tx_manager
                        .validate_set_mint_config_tx(&set_mint_config_tx)
                        .is_ok()
                    {
                        // The transaction is well-formed and valid.
                        entry.insert(timestamp);
                        self.pending_values.push(value);
                        true
                    } else {
                        false
                    }
                }
            }
        } else {
            false
        }
    }

    /// Iterate over the list of pending values.
    pub fn iter(&self) -> impl Iterator<Item = &ConsensusValue> {
        self.pending_values.iter()
    }

    /// Try and get the timestamp associated with a given value.
    pub fn get_timestamp_for_value(&self, tx_hash: &ConsensusValue) -> Option<Instant> {
        self.pending_values_map.get(tx_hash).cloned().flatten()
    }

    /// Retains only the values specified by the predicate.
    pub fn retain<F>(&mut self, predicate: F)
    where
        F: Fn(&ConsensusValue) -> bool,
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
        let mint_tx_manager = self.mint_tx_manager.clone();
        self.retain(|value| match value {
            ConsensusValue::TxHash(tx_hash) => tx_manager.validate(tx_hash).is_ok(),
            ConsensusValue::SetMintConfigTx(ref set_mint_config_tx) => mint_tx_manager
                .validate_set_mint_config_tx(set_mint_config_tx)
                .is_ok(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_manager::{MockTxManager, TxManagerError};
    use mc_transaction_core::{tx::TxHash, validation::TransactionValidationError};
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
        assert!(pending_values.push(values[0].clone().into(), None));
        assert!(!pending_values.push(values[1].clone().into(), None));
        assert!(pending_values.push(values[2].clone().into(), None));

        assert_eq!(
            pending_values.pending_values,
            vec![values[0].clone().into(), values[2].clone().into()]
        );
        assert_eq!(
            pending_values.pending_values_map,
            HashMap::from_iter(vec![
                (values[0].clone().into(), None),
                (values[2].clone().into(), None)
            ])
        );
    }

    #[test]
    /// Should only allow a single instance of each value
    fn test_push_skips_already_present_values() {
        let mut tx_manager = MockTxManager::new();

        // A few test values.
        let values: Vec<ConsensusValue> = vec![
            TxHash([1u8; 32]).into(),
            TxHash([2u8; 32]).into(),
            TxHash([3u8; 32]).into(),
        ];

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
        let tx_hashes = vec![TxHash([1u8; 32]), TxHash([2u8; 32]), TxHash([3u8; 32])];

        let values: Vec<ConsensusValue> = tx_hashes
            .iter()
            .cloned()
            .map(|tx_hash| tx_hash.into())
            .collect();

        // `validate` should be called one for each pending value.
        tx_manager
            .expect_validate()
            .with(eq(tx_hashes[0].clone()))
            .return_const(Ok(()));
        // This transaction has expired.
        tx_manager
            .expect_validate()
            .with(eq(tx_hashes[1].clone()))
            .return_const(Err(TxManagerError::TransactionValidation(
                TransactionValidationError::TombstoneBlockExceeded,
            )));
        tx_manager
            .expect_validate()
            .with(eq(tx_hashes[2].clone()))
            .return_const(Ok(()));

        // Create new PendingValues and forcefully shove the pending tx_hashes into it
        // in order to skip the validation call done by `push()`.
        let mut pending_values = PendingValues::new(Arc::new(tx_manager));

        pending_values.pending_values = values.clone();
        pending_values.pending_values_map = values
            .iter()
            .cloned()
            .map(|value| (value, Some(Instant::now())))
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
