// Copyright (c) 2018-2022 The MobileCoin Foundation

//! The Node ID type

use crate::responder_id::ResponderId;
use core::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{Ed25519Public};
use prost::Message;
use serde::{Deserialize, Serialize};

/// Node unique identifier containing a responder_id as well as a unique public
/// key
#[derive(Clone, Deserialize, Digestible, Message, Serialize)]
pub struct NodeID {
    /// The Responder ID for this node
    #[prost(message, required, tag = 1)]
    pub responder_id: ResponderId,
    /// The public message-signing key for this node
    #[prost(message, required, tag = 2)]
    pub public_key: Ed25519Public,
}

impl Display for NodeID {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}:{}", self.responder_id, self.public_key)
    }
}

impl Hash for NodeID {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.public_key.hash(hasher);
    }
}

impl PartialEq for NodeID {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl Eq for NodeID {}

impl PartialOrd for NodeID {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NodeID {
    fn cmp(&self, other: &Self) -> Ordering {
        self.public_key.cmp(&other.public_key)
    }
}

impl From<&NodeID> for ResponderId {
    fn from(src: &NodeID) -> Self {
        src.responder_id.clone()
    }
}

// This is needed for SCPNetworkState's NetworkState implementation.
impl AsRef<ResponderId> for NodeID {
    fn as_ref(&self) -> &ResponderId {
        &self.responder_id
    }
}
