// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Type-safe wrappers for integers used in our transactions, and other
//! low-level types. This crate is intended to have a small footprint
//! and be maximally portable.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

mod amount;
mod block_version;
mod token;

pub use crate::{
    amount::Amount,
    block_version::{BlockVersion, BlockVersionError, BlockVersionIterator},
    token::TokenId,
};
