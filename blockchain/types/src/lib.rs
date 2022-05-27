// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Blockchain data structures.

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

mod block;
mod block_contents;
mod block_data;
mod block_id;
mod block_signature;
mod error;

pub use crate::{
    block::{compute_block_id, Block, BlockIndex, MAX_BLOCK_VERSION},
    block_contents::{BlockContents, BlockContentsHash},
    block_data::BlockData,
    block_id::BlockID,
    block_signature::BlockSignature,
    error::ConvertError,
};

pub use mc_transaction_types::BlockVersion;
