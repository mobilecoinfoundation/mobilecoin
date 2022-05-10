// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Utilities for Stellar Consensus Protocol tests.
pub use mc_consensus_scp_core::test_utils::*;

use crate::{core_types::Value, slot::Slot, QuorumSet, SlotIndex};
use mc_common::{logger::Logger, NodeID};
use std::{fmt, sync::Arc};

/// Error for transaction validation
#[derive(Clone)]
pub struct TransactionValidationError;
impl fmt::Display for TransactionValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("TransactionValidationError")
    }
}

/// Returns Ok.
pub fn trivial_validity_fn<T: Value>(_value: &T) -> Result<(), TransactionValidationError> {
    Ok(())
}

/// Returns `values` in sorted order.
pub fn trivial_combine_fn<V: Value>(values: &[V]) -> Result<Vec<V>, TransactionValidationError> {
    let mut values_as_vec: Vec<V> = values.to_vec();
    values_as_vec.sort();
    values_as_vec.dedup();
    Ok(values_as_vec)
}

/// Returns at most the first `n` values.
#[allow(unused)]
pub fn get_bounded_combine_fn<V: Value>(
    max_elements: usize,
) -> impl Fn(&[V]) -> Result<Vec<V>, TransactionValidationError> {
    move |values: &[V]| -> Result<Vec<V>, TransactionValidationError> {
        trivial_combine_fn(values).map(|mut combined| {
            combined.truncate(max_elements);
            combined
        })
    }
}

/// Creates a new slot.
pub fn get_slot(
    slot_index: SlotIndex,
    node_id: &NodeID,
    quorum_set: &QuorumSet,
    logger: Logger,
) -> Slot<u32, TransactionValidationError> {
    Slot::<u32, TransactionValidationError>::new(
        node_id.clone(),
        quorum_set.clone(),
        slot_index,
        Arc::new(trivial_validity_fn),
        Arc::new(trivial_combine_fn),
        logger,
    )
}
