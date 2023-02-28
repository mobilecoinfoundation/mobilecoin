// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Types and wrappers for used in transactions, and other
//! low-level types. This crate is intended to have a small footprint
//! and be maximally portable.

#![no_std]
#![deny(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub use crate::{
    amount::{Amount, AmountError},
    block_version::{BlockVersion, BlockVersionError, BlockVersionIterator},
    token::TokenId,
    unmasked_amount::UnmaskedAmount,
};
#[cfg(feature = "alloc")]
pub use crate::{
    masked_amount::{MaskedAmount, MaskedAmountV1, MaskedAmountV2},
    tx_summary::{TxInSummary, TxOutSummary, TxSummary},
};

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
