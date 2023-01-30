// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Type-safe wrappers for integers used in our transactions, and other
//! low-level types. This crate is intended to have a small footprint
//! and be maximally portable.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;


mod block_version;
mod token;
mod unmasked_amount;

pub mod amount;
pub mod constants;
pub mod domain_separators;
pub mod tx_summary;

pub use crate::{
    amount::{Amount, AmountError, MaskedAmount, MaskedAmountV1, MaskedAmountV2},
    block_version::{BlockVersion, BlockVersionError, BlockVersionIterator},
    token::TokenId,
    unmasked_amount::UnmaskedAmount,
};
