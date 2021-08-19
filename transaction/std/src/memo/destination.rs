// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Object for 0x0200 Destination memo type
//!
//! This was proposed for standardization in mobilecoinfoundation/mcips/pull/4

use super::RegisteredMemoType;
use crate::impl_memo_type_conversions;
use core::convert::TryInto;
use displaydoc::Display;
use mc_account_keys::ShortAddressHash;

/// A memo that the sender writes to themself to record details of the
/// transaction, and attaches to the change TxOut so that they can recover it
/// later.
///
/// See RFC for extended discussion.
///
/// This memo should be validated by confirming that the TxOut matches to the
/// change subaddress.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct DestinationMemo {
    /// The address hash of the recipient to whom the payment is attributed
    address_hash: ShortAddressHash,
    /// The number of recipients of the transaction (ignoring the change output
    /// and fee). For a typical transaction, this is one, and the address
    /// hash refers to that recipient. When there is more than one
    /// recipient, one of them can be chosen arbitrarily.
    num_recipients: u8,
    /// The total fee paid in the transaction (in picomob)
    ///
    /// Note: We assume that the high order byte of fee is zero, and use this
    /// to compress the memo into 32 bytes. For this assumption not to be
    /// correct, there would have to be a transaction that spends more than
    /// 1% of all of MOB as the fee, which is considered not an important
    /// scenario.
    fee: u64,
    /// The sum of all outlays of the transaction (in picomob)
    /// Here outlay means, sum of amounts of outputs that are not change and
    /// are not the transaction fee.
    /// For a typical transaction with one recipient, this refers to the amount
    /// of a single TxOut.
    ///
    /// This memo is attached to the change TxOut of the transaction, and from
    /// the amount of that, and this memo, the owner can determine the sum of
    /// the inputs spent in the transaction by adding change + fee +
    /// total_outlay
    ///
    /// Note: It is technically possible the total outlay is not representable
    /// as a u64. In that case, the memo builder is responsible to signal an
    /// an error. The client may disable destination memos for this transaction.
    total_outlay: u64,
}

impl RegisteredMemoType for DestinationMemo {
    const MEMO_TYPE_BYTES: [u8; 2] = [0x02, 0x00];
}

impl DestinationMemo {
    /// Create a new destination memo set up for a single recipient
    /// (To create a memo for multiple recipients, use set_num_recipients)
    ///
    /// Returns an error if the data are out of bounds
    pub fn new(
        address_hash: ShortAddressHash,
        total_outlay: u64,
        fee: u64,
    ) -> Result<Self, DestinationMemoError> {
        let mut result = Self {
            address_hash,
            num_recipients: 1,
            total_outlay,
            fee: 0,
        };
        result.set_fee(fee)?;
        Ok(result)
    }

    /// Get the address hash
    pub fn get_address_hash(&self) -> &ShortAddressHash {
        &self.address_hash
    }
    /// Set the address hash
    pub fn set_address_hash(&mut self, val: ShortAddressHash) {
        self.address_hash = val;
    }
    /// Get the number of recipients
    pub fn get_num_recipients(&self) -> u8 {
        self.num_recipients
    }
    /// Set the number of recipients
    pub fn set_num_recipients(&mut self, val: u8) {
        self.num_recipients = val;
    }
    /// Get the fee
    pub fn get_fee(&self) -> u64 {
        self.fee
    }
    /// Set the fee. Returns an error if the fee is too large to be represented.
    pub fn set_fee(&mut self, val: u64) -> Result<(), DestinationMemoError> {
        if val.to_be_bytes()[0] != 0u8 {
            return Err(DestinationMemoError::FeeTooLarge);
        }
        self.fee = val;
        Ok(())
    }
    /// Get the total outlay
    pub fn get_total_outlay(&self) -> u64 {
        self.total_outlay
    }
    /// Set the total outlay
    pub fn set_total_outlay(&mut self, val: u64) {
        self.total_outlay = val;
    }
}

impl From<&[u8; 44]> for DestinationMemo {
    // The layout of the memo data in 32 bytes is:
    // [0-16]: sender_address_hash
    // [16]: num_recipients
    // [17-24]: fee
    // [24-32]: total outlay
    // [32-44]: unused
    fn from(src: &[u8; 44]) -> Self {
        let address_hash: [u8; 16] = src[0..16].try_into().expect("arithmetic error");
        let num_recipients = src[16];
        let fee = {
            let mut fee_bytes = [0u8; 8];
            fee_bytes[1..].copy_from_slice(&src[17..24]);
            u64::from_be_bytes(fee_bytes)
        };
        let total_outlay = u64::from_be_bytes(src[24..32].try_into().expect("arithmetic error"));
        Self {
            address_hash: address_hash.into(),
            num_recipients,
            fee,
            total_outlay,
        }
    }
}

impl From<DestinationMemo> for [u8; 44] {
    fn from(src: DestinationMemo) -> [u8; 44] {
        let mut memo_data = [0u8; 44];
        memo_data[0..16].copy_from_slice(src.address_hash.as_ref());
        memo_data[16..24].copy_from_slice(&src.fee.to_be_bytes());
        memo_data[16] = src.num_recipients;
        memo_data[24..32].copy_from_slice(&src.total_outlay.to_be_bytes());
        memo_data
    }
}

/// An error that can occur when configuring a destination memo
#[derive(Display, Debug)]
pub enum DestinationMemoError {
    /// The fee amount is too large to be represented in the destination memo
    FeeTooLarge,
}

impl_memo_type_conversions! { DestinationMemo }
