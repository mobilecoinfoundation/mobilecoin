// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_common::ResponderId;
use mc_peers::{ConsensusValue, VerifiedConsensusMsg};
use std::time::Instant;

#[derive(Debug)]
pub enum TaskMessage {
    /// A tuple of (timestamp, list of client-submitted values). The timestamp
    /// refers to when the list was added to the queue, and is used to
    /// tracking how long it takes to process each value.
    Values(Option<Instant>, Vec<ConsensusValue>),

    /// SCP Statement.
    ConsensusMsg(VerifiedConsensusMsg, ResponderId),

    /// Stop trigger, used for notifying the worker thread to terminate.
    StopTrigger,
}
