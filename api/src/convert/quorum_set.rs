// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert between Rust and proto representations of QuorumSet.

use crate::{
    quorum_set::{
        QuorumSet as QuorumSetProto, QuorumSetMember as QuorumSetMemberProto,
        QuorumSetMember_oneof_member,
    },
    ConversionError,
};
use mc_blockchain_types::{NodeID, QuorumSet, QuorumSetMember, QuorumSetMemberWrapper};

// QuorumSet
impl From<&QuorumSet> for QuorumSetProto {
    fn from(qs: &QuorumSet) -> Self {
        let mut proto = QuorumSetProto::new();
        let members = qs
            .members
            .iter()
            .filter_map(|m| (*m).as_ref().map(Into::into))
            .collect();
        proto.threshold = qs.threshold;
        proto.set_members(members);
        proto
    }
}

impl TryFrom<&QuorumSetProto> for QuorumSet {
    type Error = ConversionError;

    fn try_from(proto: &QuorumSetProto) -> Result<Self, Self::Error> {
        let members = proto
            .members
            .iter()
            .map(|m| {
                Ok(QuorumSetMemberWrapper {
                    member: Some(m.try_into()?),
                })
            })
            .collect::<Result<Vec<_>, ConversionError>>()?;
        let set = Self {
            threshold: proto.threshold,
            members,
        };
        if set.is_valid() {
            Ok(set)
        } else {
            Err(ConversionError::ArrayCastError)
        }
    }
}

// QuorumSetMember
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

impl TryFrom<&QuorumSetMemberProto> for QuorumSetMember<NodeID> {
    type Error = ConversionError;

    fn try_from(proto: &QuorumSetMemberProto) -> Result<Self, Self::Error> {
        match proto.member.as_ref() {
            Some(QuorumSetMember_oneof_member::node(id)) => {
                Ok(QuorumSetMember::Node(id.try_into()?))
            }
            Some(QuorumSetMember_oneof_member::inner_set(qs)) => {
                Ok(QuorumSetMember::InnerSet(qs.try_into()?))
            }
            None => Err(ConversionError::ObjectMissing),
        }
    }
}
