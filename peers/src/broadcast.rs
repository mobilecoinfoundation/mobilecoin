// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Broadcasts messages through the network.

use crate::ConsensusMsg;
use mc_common::ResponderId;
use mockall::*;

#[automock]
pub trait Broadcast: Send {
    /// Broadcasts a consensus message.
    ///
    /// # Arguments
    /// * `msg` - The message to be broadcast.
    /// * `received_from` - The peer the message was received from. This allows
    ///   us to not echo the message back to the peer that handed it to us. Note
    ///   that due to message relaying, this can be a different peer than the
    ///   one that created the message.
    fn broadcast_consensus_msg(&mut self, msg: &ConsensusMsg, received_from: &ResponderId);
}
