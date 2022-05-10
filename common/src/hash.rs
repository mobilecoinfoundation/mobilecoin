// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Hash-based containers and helpers.

use crate::hasher_builder::HasherBuilder;

/// A HashMap that replaces the default hasher with an implementation that
/// relies on mcrand for randomess.
/// See [hashbrown::HashMap] and [HasherBuilder]
pub type HashMap<K, V> = hashbrown::HashMap<K, V, HasherBuilder>;

/// A HashSet that replaces the default hasher with an implementation that
/// relies on mcrand for randomess.
/// See [hashbrown::HashSet] and [HasherBuilder]
pub type HashSet<K> = hashbrown::HashSet<K, HasherBuilder>;

/// Hash type
pub type Hash = [u8; 32];

/// Note: This is only used by servers, for logging (maybe to anonymize logs?)
/// Please don't use it in e.g. transaction validation math, or actual hashing
/// of the blocks in the blockchain, where you should be specific about what
/// hash you are using.
pub fn fast_hash(data: &[u8]) -> Hash {
    use sha3::Digest;

    let hash = sha3::Sha3_256::digest(data);
    let mut output = [0u8; 32];
    output.copy_from_slice(hash.as_slice());
    output
}
