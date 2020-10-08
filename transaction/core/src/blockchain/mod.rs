// Copyright (c) 2018-2020 MobileCoin Inc.

//! Blockchain data structures.

use failure::Fail;

mod block;
mod block_contents;
mod block_data;
mod block_id;
mod block_signature;

pub use block::*;
pub use block_contents::*;
pub use block_data::*;
pub use block_id::*;
pub use block_signature::*;

#[derive(Debug, Fail)]
/// Array conversion errors.
pub enum ConvertError {
    /// Unable to coerce data of the wrong length into an array.
    #[fail(display = "Length mismatch (expected {}, got {})", _0, _1)]
    LengthMismatch(usize, usize),
}
