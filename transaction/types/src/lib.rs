// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Types and wrappers for used in transactions, and other
//! low-level types. This crate is intended to have a small footprint
//! and be maximally portable.

#![no_std]
#![deny(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub use amount::{Amount, AmountError};
pub use block_version::{BlockVersion, BlockVersionError, BlockVersionIterator};
#[cfg(feature = "alloc")]
pub use masked_amount::{MaskedAmount, MaskedAmountV1, MaskedAmountV2};
pub use token::TokenId;
#[cfg(feature = "alloc")]
pub use tx_summary::{TxInSummary, TxOutSummary, TxSummary};
pub use unmasked_amount::UnmaskedAmount;

pub mod constants;
pub mod domain_separators;
#[cfg(test)]
pub mod proptest_fixtures;

mod amount;
mod block_version;
#[cfg(feature = "alloc")]
mod masked_amount;
mod token;
#[cfg(feature = "alloc")]
mod tx_summary;
mod unmasked_amount;
