// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Core types for MobileCoin's implementation of SCP.
use core::{
    clone::Clone,
    cmp::{Eq, Ord, PartialEq, PartialOrd},
    fmt::{Debug, Display},
    hash::Hash,
};
use mc_crypto_digestible::Digestible;
use serde::{de::DeserializeOwned, Serialize};

/// A generic node identifier.
pub trait GenericNodeId:
    Clone + Debug + Digestible + Display + Eq + Hash + Ord + PartialEq + PartialOrd + Serialize
{
}

impl<T> GenericNodeId for T where
    T: Clone
        + Debug
        + Digestible
        + Display
        + DeserializeOwned
        + Eq
        + Hash
        + Ord
        + PartialEq
        + PartialOrd
        + Serialize
{
}

/// The node identifier is used when reasoning about messages in federated
/// voting.
///
/// For example, in production SCP, a message is signed by the node that emitted
/// it, and the public key is a component of that node's identifier, so that the
/// signature can be verified.
pub trait Identifier: Clone + Debug + Eq + Hash + Ord + PartialEq + PartialOrd + Send {
    /// Get Identifier as bytes.
    fn as_bytes(&self) -> [u8; 4];
}

/// Slot index.
pub type SlotIndex = u64;

/// The value on which to consense.
pub trait Value:
    Clone + Debug + Digestible + Eq + Hash + Ord + PartialEq + PartialOrd + Send + Serialize + 'static
{
}

impl<T> Value for T where
    T: Clone
        + Debug
        + Digestible
        + Eq
        + Hash
        + Ord
        + PartialEq
        + PartialOrd
        + Send
        + Serialize
        + 'static
{
}
