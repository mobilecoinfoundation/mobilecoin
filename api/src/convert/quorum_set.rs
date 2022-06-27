// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert between Rust and proto representations of QuorumSet.

use crate::{
    quorum_set::{
        quorum_set_member, QuorumSet as QuorumSetProto, QuorumSetMember as QuorumSetMemberProto,
    },
    ConversionError,
};
use mc_blockchain_types::{NodeID, QuorumSet, QuorumSetMember, QuorumSetMemberWrapper};

// QuorumSet
impl From<&QuorumSet> for QuorumSetProto {
    fn from(qs: &QuorumSet) -> Self {
        let members = qs
            .members
            .iter()
            .filter_map(|m| (*m).as_ref().map(Into::into))
            .collect();
        QuorumSetProto {
            threshold: qs.threshold,
            members,
        }
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
    fn from(src: &QuorumSetMember<NodeID>) -> QuorumSetMemberProto {
        let member = Some(match src {
            QuorumSetMember::Node(id) => quorum_set_member::Member::Node(id.into()),
            QuorumSetMember::InnerSet(qs) => quorum_set_member::Member::InnerSet(qs.into()),
        });
        QuorumSetMemberProto { member }
    }
}

impl TryFrom<&QuorumSetMemberProto> for QuorumSetMember<NodeID> {
    type Error = ConversionError;

    fn try_from(proto: &QuorumSetMemberProto) -> Result<Self, Self::Error> {
        match proto.member.as_ref() {
            Some(quorum_set_member::Member::Node(id)) => Ok(QuorumSetMember::Node(id.try_into()?)),
            Some(quorum_set_member::Member::InnerSet(qs)) => {
                Ok(QuorumSetMember::InnerSet(qs.try_into()?))
            }
            None => Err(ConversionError::ObjectMissing),
        }
    }
}
