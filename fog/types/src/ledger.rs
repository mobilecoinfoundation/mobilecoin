// Copyright (c) 2018-2021 The MobileCoin Foundation

use alloc::vec::Vec;
use core::convert::TryFrom;
use displaydoc::Display;
use mc_transaction_core::{
    ring_signature::KeyImage,
    tx::{TxOut, TxOutMembershipProof},
};
use prost::Message;
use serde::{Deserialize, Serialize};

/// Parameters for a output request. This is the contents of the encrypted
/// payload sent by the client. We need to define this since the client will use
/// the external type to send this.  Eventually we want to use prost to generate
/// this from the external proto, but for now this works.
#[derive(Message, Eq, PartialEq)]
pub struct GetOutputsRequest {
    /// Indices for outputs requested.
    #[prost(fixed64, repeated, tag = "1")]
    pub indices: Vec<u64>,

    /// Block to use as the merkle root of the returned proofs
    #[prost(fixed64, tag = "2")]
    pub merkle_root_block: u64,
}

/// A list of outputs and proofs. This is the contents of the encrypted payload
/// sent to the client. We need to define this since the client will use the
/// external type to read this. We test in the `fog_api` integration tests that
/// this round-trips with the protobuf generated type
#[derive(Clone, Message, Eq, PartialEq, Serialize, Deserialize)]
pub struct GetOutputsResponse {
    /// Outputs
    #[prost(message, repeated, tag = "1")]
    pub results: Vec<OutputResult>,

    /// Number of blocks in the ledger
    #[prost(uint64, tag = "2")]
    pub num_blocks: u64,

    /// Number of txos in the ledger
    #[prost(uint64, tag = "3")]
    pub global_txo_count: u64,
}

#[derive(Clone, Message, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutputResult {
    /// Index that was queried (global index of a txo)
    #[prost(fixed64, tag = "1")]
    pub index: u64,

    /// Result code for this query
    #[prost(fixed32, tag = "2")]
    pub result_code: u32,

    /// The TxOut that was recovered
    #[prost(message, required, tag = "3")]
    pub output: TxOut,

    /// The proof of membership for this TxOut
    #[prost(message, required, tag = "4")]
    pub proof: TxOutMembershipProof,
}

/// A list of key images. This is the contents of the encrypted payload sent by
/// the client. We need to define this since the client will use the external
/// type to send this.  Eventually we want to use prost to generate this from
/// the external proto, but for now this works.
#[derive(Message, Eq, PartialEq)]
pub struct CheckKeyImagesRequest {
    /// Key images.
    #[prost(message, repeated, tag = "1")]
    pub queries: Vec<KeyImageQuery>,
}

/// Query about a particular key image
#[derive(Message, Eq, PartialEq)]
pub struct KeyImageQuery {
    #[prost(message, required, tag = "1")]
    pub key_image: KeyImage,

    #[prost(fixed64, tag = "2")]
    pub start_block: u64,
}

/// A list that says whether in request key images have been spent. This is the
/// contents of the encrypted payload sent to the client.
/// We need to define this since the client will use the external type to send
/// this.  Eventually we want to use prost to generate this from the external
/// proto, but for now this works.
#[derive(Clone, Message, Eq, PartialEq, Serialize, Deserialize)]
pub struct CheckKeyImagesResponse {
    /// Number of blocks in the ledger
    #[prost(uint64, tag = "1")]
    pub num_blocks: u64,

    /// Number of txos in the ledger
    #[prost(uint64, tag = "2")]
    pub global_txo_count: u64,

    /// Results of key image checks
    #[prost(message, repeated, tag = "3")]
    pub results: Vec<KeyImageResult>,
}

/// A result which tells for a given key image, whether it was spent or not
/// and at what height.
#[derive(Clone, Message, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyImageResult {
    #[prost(message, required, tag = "1")]
    pub key_image: KeyImage,
    // Note: We should perhaps add
    // [prost(... , default = "!064")]
    // here to force prost to emit this field even if spent_at = 0, because
    // spent_at = 0 indicates a miss and we don't want to leak that.
    // But it's kind of a hack...
    // proto3 does not support defaults, so this cannot be in the .proto AFAIU
    // There's probably a simpler fix...
    #[prost(fixed64, tag = "2")]
    pub spent_at: u64,

    /// The timestamp of the spent_at block.
    /// Note: The timestamps are based on untrusted reporting of time from the
    /// consensus validators. Represented as seconds of UTC time since Unix
    /// epoch 1970-01-01T00:00:00Z.
    #[prost(fixed64, tag = "3")]
    pub timestamp: u64,

    /// Timestamp result code, indicating whether the timestamp was found, can
    /// be tried again later, or will never be found with the current
    /// watcher configuration.
    #[prost(fixed32, tag = "4")]
    pub timestamp_result_code: u32,

    /// Spent at result code, indicating whether the spent_at block was found.
    #[prost(fixed32, tag = "5")]
    pub key_image_result_code: u32,
}

#[derive(PartialEq, Eq, Debug, Display)]
#[repr(u32)]
pub enum KeyImageResultCode {
    /// The key image was spent in the block indicated by spent_at.
    Spent = 1,
    /// The key image has not been spent.
    NotSpent,
    /// Error occurred when getting key image
    KeyImageError,
}

impl TryFrom<u32> for KeyImageResultCode {
    type Error = ();
    fn try_from(src: u32) -> Result<KeyImageResultCode, ()> {
        if src == KeyImageResultCode::Spent as u32 {
            Ok(KeyImageResultCode::Spent)
        } else if src == KeyImageResultCode::NotSpent as u32 {
            Ok(KeyImageResultCode::NotSpent)
        } else if src == KeyImageResultCode::KeyImageError as u32 {
            Ok(KeyImageResultCode::KeyImageError)
        } else {
            Err(())
        }
    }
}
