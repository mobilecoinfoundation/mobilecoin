// Copyright (c) 2018-2022 The MobileCoin Foundation

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::{
    hash::{Hash, Hasher},
    str::FromStr,
};
use mc_common::{NodeID, ResponderId};
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::Ed25519Public;
use prost::{Message, Oneof};
use serde::{Deserialize, Serialize};

/// The quorum set defining the trusted set of peers.
#[derive(Clone, Deserialize, Digestible, Message, Ord, PartialOrd, Serialize)]
pub struct QuorumSet {
    /// Threshold (how many members do we need to reach quorum).
    #[prost(uint32, required, tag = 1)]
    pub threshold: u32,

    /// Members.
    #[prost(message, repeated, tag = 2)]
    pub members: Vec<QuorumSetMemberWrapper>,
}

/// This wrapper struct is required because of a peculiarity of `prost`: you
/// cannot have repeated oneof fields (like a `Vec<QuorumSetMember>`), so we
/// wrap [QuorumSetMember] in a struct which implements [prost::Message].
/// Unfortunately protobuf also doesn't allow for required oneof fields, so the
/// inner value has to be optional. In practice we expect it to always be
/// `Some`.
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct QuorumSetMemberWrapper {
    /// The member `oneof`
    #[prost(oneof = "QuorumSetMember", tags = "1,2")]
    pub member: Option<QuorumSetMember>,
}

/// A member in a [QuorumSet]. Can be either a [QuorumNode] or another
/// [QuorumSet].
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Oneof, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(tag = "type", content = "args")]
pub enum QuorumSetMember {
    /// A single trusted entity with an identity.
    #[prost(message, tag = 1)]
    Node(QuorumNode),

    /// A quorum set can also be a member of a quorum set.
    #[prost(message, tag = 2)]
    InnerSet(QuorumSet),
}

/// A Node in a [QuorumSet].
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct QuorumNode {
    /// The Responder ID for this node
    #[prost(message, required, tag = 1)]
    pub responder_id: String,
    /// The public message-signing key for this node
    #[prost(message, required, tag = 2)]
    pub public_key: Ed25519Public,
}

impl QuorumSet {
    /// Create a new quorum set.
    pub fn new(threshold: u32, members: Vec<QuorumSetMember>) -> Self {
        let members = members
            .into_iter()
            .map(QuorumSetMemberWrapper::from)
            .collect();
        Self { threshold, members }
    }

    /// Create a new quorum set from the given node IDs.
    pub fn new_with_node_ids(threshold: u32, node_ids: Vec<QuorumNode>) -> Self {
        Self::new(
            threshold,
            node_ids.into_iter().map(QuorumSetMember::Node).collect(),
        )
    }

    /// Create a new quorum set from the given inner sets.
    pub fn new_with_inner_sets(threshold: u32, inner_sets: Vec<Self>) -> Self {
        Self::new(
            threshold,
            inner_sets
                .into_iter()
                .map(QuorumSetMember::InnerSet)
                .collect(),
        )
    }

    /// A quorum set with no members and a threshold of 0.
    pub fn empty() -> Self {
        Self::new(0, vec![])
    }

    /// Check if a quorum set is valid.
    pub fn is_valid(&self) -> bool {
        // Must have at least `threshold` members.
        if self.threshold > self.members.len() as u32 {
            return false;
        }

        // All of our inner sets must be valid.
        for member in self.members.iter() {
            if let Some(QuorumSetMember::InnerSet(qs)) = &member.member {
                if !qs.is_valid() {
                    return false;
                }
            }
        }

        // QuorumSet is valid
        true
    }

    /// Recursively sort the QS and all inner sets
    pub fn sort(&mut self) {
        for member in self.members.iter_mut() {
            if let Some(QuorumSetMember::InnerSet(qs)) = &mut member.member {
                qs.sort()
            };
        }
        // sort the members after any internal reordering
        self.members.sort();
    }
}

impl PartialEq for QuorumSet {
    fn eq(&self, other: &QuorumSet) -> bool {
        if self.threshold == other.threshold && self.members.len() == other.members.len() {
            // sort before comparing
            let mut self_clone = self.clone();
            let mut other_clone = other.clone();
            self_clone.sort();
            other_clone.sort();
            return self_clone.members == other_clone.members;
        }
        false
    }
}
impl Eq for QuorumSet {}

impl Hash for QuorumSet {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // hash over a sorted copy
        let mut clone = self.clone();
        clone.sort();
        clone.threshold.hash(state);
        clone.members.hash(state);
    }
}

impl From<QuorumSetMember> for QuorumSetMemberWrapper {
    fn from(m: QuorumSetMember) -> Self {
        Self { member: Some(m) }
    }
}

impl From<&NodeID> for QuorumNode {
    fn from(src: &NodeID) -> Self {
        QuorumNode {
            responder_id: src.responder_id.to_string(),
            public_key: src.public_key,
        }
    }
}

impl TryFrom<&QuorumNode> for NodeID {
    type Error = mc_common::ResponderIdParseError;

    fn try_from(src: &QuorumNode) -> Result<Self, Self::Error> {
        Ok(NodeID {
            responder_id: ResponderId::from_str(&src.responder_id)?,
            public_key: src.public_key,
        })
    }
}
