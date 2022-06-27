// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Convert between Rust and proto representations of NodeID.

use crate::{quorum_set::Node as NodeProto, ConversionError};
use core::str::FromStr;
use mc_common::{NodeID, ResponderId};

impl From<&NodeID> for NodeProto {
    fn from(node: &NodeID) -> NodeProto {
        Self {
            responder_id: node.responder_id.to_string(),
            public_key: Some((&node.public_key).into()),
        }
    }
}

impl TryFrom<&NodeProto> for NodeID {
    type Error = ConversionError;

    fn try_from(proto: &NodeProto) -> Result<Self, Self::Error> {
        let responder_id = ResponderId::from_str(&proto.responder_id)
            .map_err(|_| ConversionError::InvalidContents)?;
        let public_key = proto
            .public_key
            .as_ref()
            .ok_or(ConversionError::ObjectMissing)?
            .try_into()?;

        Ok(NodeID {
            responder_id,
            public_key,
        })
    }
}
