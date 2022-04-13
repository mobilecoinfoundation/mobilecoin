// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin transaction data types, transaction construction and validation
//! routines

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

#[macro_use]
extern crate lazy_static;

pub mod amount;
pub mod blockchain;
pub mod constants;
pub mod domain_separators;
pub mod encrypted_fog_hint;
pub mod fog_hint;
pub mod membership_proofs;
pub mod memo;
pub mod mint;
pub mod onetime_keys;
pub mod range_proofs;
pub mod ring_signature;
pub mod token;
pub mod tx;
pub mod tx_error;
pub mod validation;

#[cfg(test)]
pub mod proptest_fixtures;

pub use self::{
    amount::{Amount, AmountError, Commitment, CompressedCommitment, MaskedAmount},
    blockchain::*,
    memo::{EncryptedMemo, MemoError, MemoPayload},
    token::{tokens, Token, TokenId},
    tx::*,
    tx_error::{NewMemoError, NewTxError, ViewKeyMatchError},
};
