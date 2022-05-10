// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Core types for MobileCoin's implementation of SCP.
use alloc::{sync::Arc, vec::Vec};
use core::{
    clone::Clone,
    cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd},
    fmt,
    fmt::{Debug, Display},
    hash::{BuildHasher, Hash, Hasher},
};
use mc_common::HasherBuilder;
use mc_crypto_digestible::Digestible;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// A generic node identifier.
pub trait GenericNodeId:
    Clone + Debug + Display + Eq + PartialEq + Ord + PartialOrd + Hash + Digestible
{
}
impl<T> GenericNodeId for T where
    T: Clone
        + Debug
        + Display
        + Serialize
        + DeserializeOwned
        + Eq
        + PartialEq
        + Ord
        + PartialOrd
        + Hash
        + Digestible
{
}

/// Application-specific function for combining multiple values. Must be
/// deterministic.
pub type CombineFn<V, E> = Arc<(dyn Fn(&[V]) -> Result<Vec<V>, E> + Sync + Send)>;

/// Application-specific validation of value.
pub type ValidityFn<V, E> = Arc<(dyn Fn(&V) -> Result<(), E> + Sync + Send)>;

/// The node identifier is used when reasoning about messages in federated
/// voting.
///
/// For example, in production SCP, a message is signed by the node that emitted
/// it, and the public key is a component of that node's identifier, so that the
/// signature can be verified.
pub trait Identifier: Hash + Eq + PartialEq + Debug + Clone + PartialOrd + Ord + Send {
    /// Get Identifier as bytes.
    fn as_bytes(&self) -> [u8; 4];
}

/// Slot index.
pub type SlotIndex = u64;

/// The value on which to consense.
pub trait Value:
    Hash + Eq + PartialEq + Debug + Clone + PartialOrd + Ord + Send + Serialize + Digestible + 'static
{
}

impl<T> Value for T where
    T: Hash
        + Eq
        + PartialEq
        + Debug
        + Clone
        + PartialOrd
        + Ord
        + Send
        + Serialize
        + Digestible
        + 'static
{
}

/// The ballot contains the value on which to consense.
///
/// The balloting protocol centers around successively higher ballots
/// which are moving through the phases of the federated voting.
///
/// Ballots are totally ordered, with "counter" more significant than "value."
#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Digestible)]
pub struct Ballot<V: Value> {
    /// Counter.
    pub N: u32,

    /// Values.
    pub X: Vec<V>,
}

impl<V: Value> Ballot<V> {
    /// Create a new Ballot with the given counter and values.
    pub fn new(counter: u32, values: &[V]) -> Self {
        Ballot {
            N: counter,
            X: values.to_vec(),
        }
    }

    /// Check whether the ballot's counter is 0 and values are empty.
    pub fn is_zero(&self) -> bool {
        self.N == 0 && self.X.is_empty()
    }
}

// Ballots are totally ordered with N more significant than X.
impl<V: Value> Ord for Ballot<V> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.N != other.N {
            return self.N.cmp(&other.N);
        }

        self.X.cmp(&other.X)
    }
}

impl<V: Value> PartialOrd for Ballot<V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// This makes debugging easier when looking at large ballots.
impl<V: Value> fmt::Display for Ballot<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut hasher = HasherBuilder::default().build_hasher();
        self.X.hash(&mut hasher);
        let hashed_X_values = hasher.finish();
        write!(f, "<{}, {}:{:x}>", self.N, self.X.len(), hashed_X_values)
    }
}

#[cfg(test)]
mod core_types_tests {
    use super::*;

    #[test]
    fn total_ordering() {
        // Ballots are ordered first by counter `N`.
        {
            let high_ballot: Ballot<u32> = Ballot { N: 13, X: vec![] };
            let low_ballot: Ballot<u32> = Ballot {
                N: 4,
                X: vec![100, 200, 88],
            };
            assert!(high_ballot > low_ballot);
        }

        // Ballots are then ordered lexicographically by `X`.
        {
            let high_ballot: Ballot<u32> = Ballot {
                N: 13,
                X: vec![2000, 1000],
            };
            let low_ballot: Ballot<u32> = Ballot {
                N: 13,
                X: vec![1000, 2001],
            };
            assert!(high_ballot > low_ballot);
        }
    }
}
