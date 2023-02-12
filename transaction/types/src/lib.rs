// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Type-safe wrappers for integers used in our transactions, and other
//! low-level types. This crate is intended to have a small footprint
//! and be maximally portable.

#![no_std]
#![deny(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod prelude;

mod block_version;
pub use block_version::{BlockVersion, BlockVersionError, BlockVersionIterator};

mod token;
pub use token::TokenId;

pub mod amount;
pub mod constants;
pub mod domain_separators;

#[cfg(feature = "alloc")]
pub mod masked_amount;

#[cfg(feature = "alloc")]
pub mod tx_summary;

pub mod unmasked_amount;

#[cfg(test)]
pub mod proptest_fixtures;
