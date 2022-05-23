// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert between Rust and proto representations of NodeID.

use crate::{quorum_set::Node as NodeProto, ConversionError};
use mc_blockchain_types::QuorumNode;
use mc_common::{NodeID, ResponderId};
use std::str::FromStr;

// mc_common::NodeID
impl From<&NodeID> for NodeProto {
    fn from(node: &NodeID) -> NodeProto {
        let mut proto = NodeProto::new();
        proto.responder_id = node.responder_id.to_string();
        proto.set_public_key((&node.public_key).into());
        proto
    }
}

impl TryFrom<&NodeProto> for NodeID {
    type Error = ConversionError;

    fn try_from(proto: &NodeProto) -> Result<Self, Self::Error> {
        let responder_id = ResponderId::from_str(&proto.responder_id)
            .map_err(|_| ConversionError::InvalidContents)?;
        let public_key = proto.get_public_key().try_into()?;
        Ok(NodeID {
            responder_id,
            public_key,
        })
    }
}

// QuorumNode
impl From<&QuorumNode> for NodeProto {
    fn from(node: &QuorumNode) -> NodeProto {
        let mut proto = NodeProto::new();
        proto.responder_id = node.responder_id.to_string();
        proto.set_public_key((&node.public_key).into());
        proto
    }
}

impl TryFrom<&NodeProto> for QuorumNode {
    type Error = ConversionError;

    fn try_from(proto: &NodeProto) -> Result<Self, Self::Error> {
        let responder_id = ResponderId::from_str(&proto.responder_id)
            .map_err(|_| ConversionError::InvalidContents)?
            .to_string();
        let public_key = proto.get_public_key().try_into()?;
        Ok(QuorumNode {
            responder_id,
            public_key,
        })
    }
}
