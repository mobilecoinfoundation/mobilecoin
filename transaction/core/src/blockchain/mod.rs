// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Blockchain data structures.

mod block;
mod block_contents;
mod block_data;
mod block_id;
mod block_signature;
mod block_version;

pub use block::*;
pub use block_contents::*;
pub use block_data::*;
pub use block_id::*;
pub use block_signature::*;
pub use block_version::{BlockVersion, BlockVersionError};

use displaydoc::Display;

#[derive(Debug, Display)]
/// Array conversion errors.
pub enum ConvertError {
    /// Length mismatch. Expected `{0}`, got `{1}`
    LengthMismatch(usize, usize),
}
