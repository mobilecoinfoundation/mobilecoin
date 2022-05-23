// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Blockchain data structures.

#![no_std]

// FIXME: Re-enable when prost-generated for `derive(Oneof)` has the necessary
// doc comments: https://github.com/tokio-rs/prost/issues/237
//#![deny(missing_docs)]

extern crate alloc;

pub mod block;
pub mod block_contents;
pub mod block_data;
pub mod block_id;
pub mod block_metadata;
pub mod block_signature;
pub mod crypto;
pub mod error;
pub mod quorum_set;

pub use crate::{
    block::{compute_block_id, Block, BlockIndex, MAX_BLOCK_VERSION},
    block_contents::{BlockContents, BlockContentsHash},
    block_data::BlockData,
    block_id::BlockID,
    block_metadata::{BlockMetadata, BlockMetadataContents},
    block_signature::BlockSignature,
    error::ConvertError,
    quorum_set::{QuorumNode, QuorumSet, QuorumSetMember, QuorumSetMemberWrapper},
};

pub use mc_attest_verifier_types::{VerificationReport, VerificationSignature};
pub use mc_transaction_types::{BlockVersion, BlockVersionError, BlockVersionIterator};
