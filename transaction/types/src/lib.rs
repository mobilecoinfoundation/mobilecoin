// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Type-safe wrappers for integers used in our transactions, and other
//! low-level types. This crate is intended to have a small footprint
//! and be maximally portable.

#![no_std]
#![deny(missing_docs)]

mod amount;
mod token;

pub use amount::Amount;
pub use token::TokenId;
