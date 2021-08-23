// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::KeySize;
use aligned_cmov::{
    typenum::{Unsigned, U40},
    GenericArray,
};
use blake2::{digest::Digest, Blake2b};
use core::convert::TryInto;

/// The ExtraMeta is additional bytes we stick onto the end of user-provided
/// metadata, in order to authenticate responses from untrusted
pub type ExtraMetaSize = U40; // 8 + 16 + 16

// The additional metadata that is stored with untrusted, and not provided to us
// by our caller
#[repr(C)]
pub struct ExtraMeta {
    pub block_ctr: u64,
    pub left_child_hash: Hash,
    pub right_child_hash: Hash,
}

// This panics when the size is wrong, but it's also not a public-facing API
impl From<&[u8]> for ExtraMeta {
    fn from(src: &[u8]) -> Self {
        assert_eq!(src.len(), ExtraMetaSize::USIZE);

        Self {
            block_ctr: u64::from_le_bytes(src[0..8].try_into().unwrap()),
            left_child_hash: src[8..24].try_into().unwrap(),
            right_child_hash: src[24..40].try_into().unwrap(),
        }
    }
}

impl From<&ExtraMeta> for GenericArray<u8, ExtraMetaSize> {
    fn from(src: &ExtraMeta) -> Self {
        let mut result = GenericArray::<u8, ExtraMetaSize>::default();
        result[0..8].clone_from_slice(&src.block_ctr.to_le_bytes());
        result[8..24].clone_from_slice(&src.left_child_hash);
        result[24..40].clone_from_slice(&src.right_child_hash);
        result
    }
}

/// A hash computed by "compute_block_hash"
pub type Hash = [u8; 16];

// Compute hash associated to a block, per the docu
pub fn compute_block_hash(
    hash_key: &GenericArray<u8, KeySize>,
    e_data: &[u8],
    block_idx: u64,
    extended_metadata: &[u8],
) -> Hash {
    let mut hasher = Blake2b::new();
    hasher.update("oram");
    hasher.update(hash_key);
    hasher.update(e_data);
    hasher.update(block_idx.to_le_bytes());
    hasher.update(extended_metadata);
    let result = hasher.finalize();
    result[..16].try_into().unwrap()
}
