// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_common::ResponderId;
use mc_peers::VerifiedConsensusMsg;
use mc_transaction_core::tx::TxHash;
use std::time::Instant;

#[derive(Debug)]
pub enum TaskMessage {
    /// A tuple of (timestamp, list of client-submitted values). The timestamp
    /// refers to when the list was added to the queue, and is used to
    /// tracking how long it takes to process each value.
    Values(Option<Instant>, Vec<TxHash>),

    /// SCP Statement.
    ConsensusMsg(VerifiedConsensusMsg, ResponderId),

    /// Stop trigger, used for notifying the worker thread to terminate.
    StopTrigger,
}
