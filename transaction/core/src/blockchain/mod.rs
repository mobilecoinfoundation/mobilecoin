// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Blockchain data structures.

mod block;
mod block_contents;
mod block_data;
mod block_id;
mod block_metadata;
mod block_signature;
mod block_version;

pub use self::{
    block::*,
    block_contents::*,
    block_data::*,
    block_id::*,
    block_metadata::*,
    block_signature::*,
    block_version::{BlockVersion, BlockVersionError},
};

use displaydoc::Display;

#[derive(Debug, Display)]
/// Array conversion errors.
pub enum ConvertError {
    /// Length mismatch. Expected `{0}`, got `{1}`
    LengthMismatch(usize, usize),
}
