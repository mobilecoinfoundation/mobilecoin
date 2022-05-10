// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert between Rust and proto representations of QuorumSet.

use crate::{
    quorum_set::{
        QuorumSet as QuorumSetProto, QuorumSetMember as QuorumSetMemberProto,
        QuorumSetMember_oneof_member,
    },
    ConversionError,
};
use mc_common::NodeID;
use mc_consensus_scp_core::{QuorumSet, QuorumSetMember};
use std::convert::{Into, TryFrom, TryInto};

// mc_consensus_scp::QuorumSet
impl From<&QuorumSetMember<NodeID>> for QuorumSetMemberProto {
    fn from(member: &QuorumSetMember<NodeID>) -> QuorumSetMemberProto {
        use QuorumSetMember::*;
        let mut proto = QuorumSetMemberProto::new();
        match member {
            Node(id) => proto.set_node(id.into()),
            InnerSet(qs) => proto.set_inner_set(qs.into()),
        }
        proto
    }
}

impl From<&QuorumSet> for QuorumSetProto {
    fn from(qs: &QuorumSet) -> QuorumSetProto {
        let mut proto = QuorumSetProto::new();
        proto.threshold = qs.threshold;
        proto.set_members(qs.members.iter().map(Into::into).collect());
        proto
    }
}

impl TryFrom<&QuorumSetMemberProto> for QuorumSetMember<NodeID> {
    type Error = ConversionError;

    fn try_from(proto: &QuorumSetMemberProto) -> Result<Self, Self::Error> {
        use QuorumSetMember::*;
        use QuorumSetMember_oneof_member::*;
        match proto.member.as_ref() {
            Some(node(id)) => Ok(Node(id.try_into()?)),
            Some(inner_set(qs)) => Ok(InnerSet(qs.try_into()?)),
            None => Err(ConversionError::ObjectMissing),
        }
    }
}

impl TryFrom<&QuorumSetProto> for QuorumSet {
    type Error = ConversionError;

    fn try_from(proto: &QuorumSetProto) -> Result<Self, Self::Error> {
        let members = proto
            .members
            .iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            threshold: proto.threshold,
            members,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_consensus_scp_core::test_utils::three_node_dense_graph;

    #[test]
    fn test_roundtrip() {
        let set = three_node_dense_graph().0 .1;
        assert!(set.is_valid());

        let proto = QuorumSetProto::from(&set);
        let set2 = QuorumSet::try_from(&proto).expect("scp::QuorumSet from proto");
        assert_eq!(set, set2);
        assert!(set2.is_valid());
    }
}
