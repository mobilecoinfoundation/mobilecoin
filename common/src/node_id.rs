// Copyright (c) 2018-2021 The MobileCoin Foundation

//! The Node ID type

use crate::responder_id::ResponderId;
use binascii::ConvertError as BinConvertError;
use core::{
    cmp::Ordering,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
};
use displaydoc::Display;
use hex_fmt::HexFmt;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{Ed25519Public, KeyError};
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Copy, Debug, Deserialize, Display, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum NodeIDError {
    /// Could not create NodeID due to serialization failure
    Deserialization,
    /// The input length was too short or not right (padding)
    InvalidInputLength,
    /// The output buffer was too short for the data
    InvalidOutputLength,
    /// The input data contained invalid characters
    InvalidInput,
    /// Could not parse public key for NodeID
    KeyParseError,
}

impl From<BinConvertError> for NodeIDError {
    fn from(src: BinConvertError) -> Self {
        match src {
            BinConvertError::InvalidInputLength => NodeIDError::InvalidInputLength,
            BinConvertError::InvalidOutputLength => NodeIDError::InvalidOutputLength,
            BinConvertError::InvalidInput => NodeIDError::InvalidInput,
        }
    }
}

impl From<KeyError> for NodeIDError {
    fn from(_src: KeyError) -> Self {
        NodeIDError::KeyParseError
    }
}

/// Node unique identifier containing a responder_id as well as a unique public
/// key
#[derive(Clone, Serialize, Deserialize, Digestible)]
pub struct NodeID {
    pub responder_id: ResponderId,
    pub public_key: Ed25519Public,
}

impl Display for NodeID {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let pubkey_bytes: &[u8] = self.public_key.as_ref();
        write!(f, "{}:{:?}", self.responder_id, HexFmt(pubkey_bytes))
    }
}

impl Debug for NodeID {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let pubkey_bytes: &[u8] = self.public_key.as_ref();
        write!(
            f,
            "NodeID({}:{:?})",
            self.responder_id,
            HexFmt(pubkey_bytes)
        )
    }
}

impl Eq for NodeID {}

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

impl Ord for NodeID {
    fn cmp(&self, other: &Self) -> Ordering {
        self.public_key.cmp(&other.public_key)
    }
}

impl PartialOrd for NodeID {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.public_key.partial_cmp(&other.public_key)
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
