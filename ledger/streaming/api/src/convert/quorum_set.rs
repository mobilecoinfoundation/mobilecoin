// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert between Rust and proto representations of QuorumSet.

use crate::{
    convert::ConversionError,
    quorum_set::{
        Node as NodeProto, QuorumSet as QuorumSetProto, QuorumSetMember as QuorumSetMemberProto,
    },
};
use mc_common::NodeID;
use mc_consensus_scp::{QuorumSet, QuorumSetMember};
use std::{
    convert::{Into, TryFrom, TryInto},
    str::FromStr,
};

impl From<&NodeID> for NodeProto {
    fn from(node: &NodeID) -> NodeProto {
        let mut proto = NodeProto::new();
        proto.responder_id = node.responder_id.to_string();
        proto.set_public_key((&node.public_key).into());
        proto
    }
}

impl From<&QuorumSetMember<NodeID>> for QuorumSetMemberProto {
    fn from(member: &QuorumSetMember<NodeID>) -> QuorumSetMemberProto {
        let mut proto = QuorumSetMemberProto::new();
        match member {
            QuorumSetMember::Node(id) => proto.set_node(id.into()),
            QuorumSetMember::InnerSet(qs) => proto.set_inner_set(qs.into()),
        }
        proto
    }
}

impl From<&QuorumSet<NodeID>> for QuorumSetProto {
    fn from(qs: &QuorumSet<NodeID>) -> QuorumSetProto {
        let mut proto = QuorumSetProto::new();
        proto.threshold = qs.threshold;
        let members: Vec<QuorumSetMemberProto> = qs.members.iter().map(Into::into).collect();
        proto.set_members(members.into());
        proto
    }
}

impl TryFrom<&NodeProto> for NodeID {
    type Error = ConversionError;

    fn try_from(proto: &NodeProto) -> Result<Self, Self::Error> {
        let responder_id = mc_common::ResponderId::from_str(&proto.responder_id)
            .map_err(|_| ConversionError::InvalidContents)?;
        let public_key = proto.get_public_key().try_into()?;
        Ok(NodeID {
            responder_id,
            public_key,
        })
    }
}

impl TryFrom<&QuorumSetMemberProto> for QuorumSetMember<NodeID> {
    type Error = ConversionError;

    fn try_from(proto: &QuorumSetMemberProto) -> Result<Self, Self::Error> {
        use crate::quorum_set::QuorumSetMember_oneof_member as oneof;
        match proto.member.as_ref() {
            None => Err(ConversionError::InvalidContents),
            Some(m) => match m {
                oneof::node(id) => Ok(QuorumSetMember::Node(id.try_into()?)),
                oneof::inner_set(set) => Ok(QuorumSetMember::InnerSet(set.try_into()?)),
            },
        }
    }
}

impl TryFrom<&QuorumSetProto> for QuorumSet<NodeID> {
    type Error = ConversionError;

    fn try_from(proto: &QuorumSetProto) -> Result<Self, Self::Error> {
        let members = proto
            .members
            .iter()
            .map(TryFrom::try_from)
            .collect::<Result<Vec<_>, Self::Error>>()?;
        Ok(QuorumSet {
            threshold: proto.threshold,
            members,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::make_quorum_set;

    #[test]
    fn test_roundtrip() {
        let set = make_quorum_set();
        let proto = QuorumSetProto::from(&set);
        let set2 = QuorumSet::try_from(&proto).expect("conversion from proto failed");
        assert!(set2.is_valid());
        assert_eq!(set, set2);

        let proto2 = QuorumSetProto::from(&set2);
        assert_eq!(proto, proto2);
    }
}
