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
pub mod input_rules;
pub mod membership_proofs;
pub mod memo;
pub mod mint;
pub mod onetime_keys;
#[cfg(test)]
pub mod proptest_fixtures;
pub mod range_proofs;
pub mod ring_signature;
pub mod signed_contingent_input;
pub mod token;
pub mod tx;
pub mod tx_error;
pub mod tx_out_gift_code;
pub mod validation;

pub use self::{
    amount::{Amount, AmountError, Commitment, CompressedCommitment, MaskedAmount},
    blockchain::*,
    input_rules::{InputRuleError, InputRules},
    memo::{EncryptedMemo, MemoError, MemoPayload},
    signed_contingent_input::{SignedContingentInput, SignedContingentInputError, UnmaskedAmount},
    token::{tokens, Token, TokenId},
    tx::*,
    tx_error::{NewMemoError, NewTxError, ViewKeyMatchError},
    tx_out_gift_code::TxOutGiftCode,
};
