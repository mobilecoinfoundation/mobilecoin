// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Blockchain data structures.

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

pub mod crypto;

mod block;
mod block_contents;
mod block_data;
mod block_id;
mod block_metadata;
mod block_signature;
mod error;

pub use crate::{
    block::{compute_block_id, Block, BlockIndex, MAX_BLOCK_VERSION},
    block_contents::{BlockContents, BlockContentsHash},
    block_data::BlockData,
    block_id::BlockID,
    block_metadata::{BlockMetadata, BlockMetadataContents},
    block_signature::BlockSignature,
    error::ConvertError,
};

pub use mc_attest_verifier_types::{VerificationReport, VerificationSignature};
pub use mc_common::NodeID;
pub use mc_consensus_scp_types::{QuorumSet, QuorumSetMember, QuorumSetMemberWrapper};
pub use mc_transaction_types::{BlockVersion, BlockVersionError, BlockVersionIterator};
