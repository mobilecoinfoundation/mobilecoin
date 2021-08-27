// Copyright (c) 2018-2021 The MobileCoin Foundation

use alloc::vec::Vec;
use mc_transaction_core::tx::TxOut;
use serde::{Deserialize, Serialize};

/// A *contiguous subset* of a block, which is passed from the ingest server
/// to the enclave for processing.
/// This is necessary because MC-1080, the ingest enclave has bounded memory,
/// but when doing slam, or complicated bootstrap, the blocks can be very large.
/// This is part of the ingest enclave api
/// This is not a user-facing API element
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct TxsForIngest {
    /// The index of the block in the blockchain where this chunk of Txs
    /// appeared
    pub block_index: u64,
    /// The number of txo's appearing in the entire blockchain before this chunk
    /// This is needed to compute TxOutRecord::global_tx_out_index
    pub global_txo_index: u64,
    /// The redacted txs of this chunk
    pub redacted_txs: Vec<TxOut>,
    /// The timestamp of this block
    pub timestamp: u64,
}
