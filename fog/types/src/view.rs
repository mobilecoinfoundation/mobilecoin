// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::common::BlockRange;
use alloc::vec::Vec;
use core::convert::TryFrom;
use crc::crc32;
use displaydoc::Display;
use mc_crypto_keys::{CompressedRistrettoPublic, KeyError, RistrettoPrivate, RistrettoPublic};
use mc_transaction_core::{
    encrypted_fog_hint::{EncryptedFogHint, ENCRYPTED_FOG_HINT_LEN},
    tx::TxOut,
    Amount, AmountError, EncryptedMemo, MemoError,
};
use prost::Message;
use serde::{Deserialize, Serialize};

pub use mc_fog_kex_rng::KexRngPubkey;

// User <-> enclave proto schema types
// These are synced with types in fog_api view.proto, and tests enforce that
// they round trip These are NOT expected to be synced with Db schema types

#[derive(Clone, Eq, PartialEq, Message)]
pub struct QueryRequestAAD {
    #[prost(int64, tag = "1")]
    pub start_from_user_event_id: i64,

    /// The first block index to search TXOs in.
    // TODO this is currently unused
    #[prost(uint64, tag = "2")]
    pub start_from_block_index: u64,
}

#[derive(Clone, Eq, PartialEq, Message)]
pub struct QueryRequest {
    #[prost(bytes, repeated, tag = "1")]
    pub get_txos: Vec<Vec<u8>>,
}

#[derive(Clone, Eq, PartialEq, Message)]
pub struct QueryResponse {
    #[prost(uint64, tag = "1")]
    pub highest_processed_block_count: u64,

    #[prost(uint64, tag = "2")]
    pub highest_processed_block_signature_timestamp: u64,

    #[prost(int64, tag = "3")]
    pub next_start_from_user_event_id: i64,

    #[prost(message, repeated, tag = "4")]
    pub missed_block_ranges: Vec<BlockRange>,

    #[prost(message, repeated, tag = "5")]
    pub rng_records: Vec<RngRecord>,

    #[prost(message, repeated, tag = "6")]
    pub decommissioned_ingest_invocations: Vec<DecommissionedIngestInvocation>,

    #[prost(message, repeated, tag = "7")]
    pub tx_out_search_results: Vec<TxOutSearchResult>,

    #[prost(uint64, tag = "8")]
    pub last_known_block_count: u64,

    #[prost(uint64, tag = "9")]
    pub last_known_block_cumulative_txo_count: u64,
}

/// A record that can be used by the user to produce an Rng shared with fog
/// ingest
#[derive(Clone, Eq, PartialEq, Hash, Message, Serialize, Deserialize)]
pub struct RngRecord {
    /// The ingest invocation id that produced this record.
    #[prost(int64, tag = "1")]
    pub ingest_invocation_id: i64,

    /// A key-exchange message to be used by the client to create a
    /// VersionedKexRng
    #[prost(message, required, tag = "2")]
    pub pubkey: KexRngPubkey,

    /// The start block (when fog started using this rng)
    #[prost(uint64, tag = "3")]
    pub start_block: u64,
}

/// Information about a decommissioned ingest invocation.
#[derive(Clone, Eq, PartialEq, Hash, Message, Serialize, Deserialize)]
pub struct DecommissionedIngestInvocation {
    #[prost(int64, tag = "1")]
    pub ingest_invocation_id: i64,

    #[prost(uint64, tag = "2")]
    pub last_ingested_block: u64,
}

/// An enum representing the possible outcomes of a TxOut search
/// 0 is not an option here because we want this to go in the protobuf as
/// fixed32, but in proto3, the default value for fixed32 is 0 and cannot be
/// changed. Default values are omitted in the on-the-wire representation,
/// which would make the ciphertext length
/// reveal something about the result code, which we don't want.
/// Particularly, the Found and NotFound scenarios must be indistinguishable.
///
/// If any values are added they must be synced with the enum in view.proto
#[derive(PartialEq, Eq, Debug, Display)]
#[repr(u32)]
pub enum TxOutSearchResultCode {
    /// The tx was found and the ciphertext is valid
    Found = 1,
    /// The tx was not found and the ciphertext is just padding
    NotFound,
    /// The search key was bad (wrong size)
    BadSearchKey,
    /// The server had an internal error that prevented this lookup
    InternalError,
    /// The server decided not to service this query to satisfy a rate limit
    RateLimited,
}

impl TryFrom<u32> for TxOutSearchResultCode {
    type Error = ();
    fn try_from(src: u32) -> Result<Self, ()> {
        if src == Self::Found as u32 {
            Ok(Self::Found)
        } else if src == Self::NotFound as u32 {
            Ok(Self::NotFound)
        } else if src == Self::BadSearchKey as u32 {
            Ok(Self::BadSearchKey)
        } else if src == Self::InternalError as u32 {
            Ok(Self::InternalError)
        } else if src == Self::RateLimited as u32 {
            Ok(Self::RateLimited)
        } else {
            Err(())
        }
    }
}

/// A struct representing the result of a fog view Txo query
#[derive(Clone, Eq, Hash, PartialEq, Message, Serialize, Deserialize)]
pub struct TxOutSearchResult {
    /// The search key that yielded this result
    #[prost(bytes, tag = "1")]
    pub search_key: Vec<u8>,
    /// This is a TxOutSearchResultCode
    #[prost(fixed32, tag = "2")]
    pub result_code: u32,
    /// The ciphertext payload
    #[prost(bytes, tag = "3")]
    pub ciphertext: Vec<u8>,
}

// TxOutRecord is what information the fog service preserves for a user about
// their TxOut. These are created by the ingest server and then encrypted. The
// encrypted blobs are eventually returned to the user, who must deserialize
// them.
//
// Note: There are conformance tests in fog_api that check that this matches
// proto
#[derive(Clone, Eq, Hash, PartialEq, Message)]
pub struct TxOutRecord {
    /// The (compressed ristretto) bytes of commitment associated to amount
    /// field in the TxOut that was recovered.
    /// Note: These bytes are omitted in latest versions, and only the IEEE
    /// crc32 checksum of these bytes is stored.
    #[prost(bytes, tag = "1")]
    pub tx_out_amount_commitment_data: Vec<u8>,
    /// The masked value associated to amount field in the TxOut that was
    /// recovered
    #[prost(fixed64, required, tag = "2")]
    pub tx_out_amount_masked_value: u64,
    /// The (compressed ristretto) bytes of the target key associated to the
    /// TxOut that was recovered
    #[prost(bytes, required, tag = "3")]
    pub tx_out_target_key_data: Vec<u8>,
    /// The (compressed ristretto) bytes of the public key associated to the
    /// TxOut that was recovered
    #[prost(bytes, required, tag = "4")]
    pub tx_out_public_key_data: Vec<u8>,
    /// Global index within the set of all TxOuts
    #[prost(fixed64, required, tag = "5")]
    pub tx_out_global_index: u64,

    /// Index of block at which this TxOut appeared
    #[prost(fixed64, required, tag = "6")]
    pub block_index: u64,

    /// Timestamp of block at which this TxOut appeared
    /// Note: The timestamps are based on untrusted reporting of time from the
    /// consensus validators. Represented as seconds of UTC time since Unix
    /// epoch 1970-01-01T00:00:00Z.
    #[prost(fixed64, tag = "7")]
    pub timestamp: u64,

    /// The IEEE crc32 bytes of the (omitted) amount commitment data.
    /// This is here so that the client can check that they derived commitment
    /// data successfully.
    #[prost(fixed32, tag = "8")]
    pub tx_out_amount_commitment_data_crc32: u32,

    /// The encrypted memo bytes of the TxOut
    #[prost(bytes, tag = "9")]
    pub tx_out_e_memo_data: Vec<u8>,
}

impl TxOutRecord {
    /// Construct a TxOutRecord from FogTxOut and metadata, in the new way
    /// (omitting compressed commitment)
    ///
    /// Arguments:
    /// * FogTxOut: The representation of a TxOut preserved in the TxOutRecord
    /// * FogTxOutMetadata: The additional data not from the TxOut itself that
    ///   we preserve in TxOutRecord
    pub fn new(fog_tx_out: FogTxOut, meta: FogTxOutMetadata) -> Self {
        Self {
            tx_out_amount_commitment_data: Default::default(),
            tx_out_amount_commitment_data_crc32: fog_tx_out.amount_commitment_data_crc32,
            tx_out_amount_masked_value: fog_tx_out.amount_masked_value,
            tx_out_target_key_data: fog_tx_out.target_key.as_bytes().to_vec(),
            tx_out_public_key_data: fog_tx_out.public_key.as_bytes().to_vec(),
            tx_out_e_memo_data: fog_tx_out
                .e_memo
                .map(|e_memo| e_memo.into())
                .unwrap_or_default(),
            tx_out_global_index: meta.global_index,
            block_index: meta.block_index,
            timestamp: meta.timestamp,
        }
    }

    /// Extract a FogTxOut object from the (flattened) TxOutRecord object
    /// Note that this discards some metadata (timestamp, block_index,
    /// global_index).
    pub fn get_fog_tx_out(&self) -> Result<FogTxOut, FogTxOutError> {
        Ok(FogTxOut {
            target_key: CompressedRistrettoPublic::try_from(&self.tx_out_target_key_data[..])?,
            public_key: CompressedRistrettoPublic::try_from(&self.tx_out_public_key_data[..])?,
            amount_masked_value: self.tx_out_amount_masked_value,
            amount_commitment_data_crc32: self.get_amount_data_crc32()?,
            e_memo: self.get_e_memo()?,
        })
    }

    // Helper: Get the amount data crc32, resolving the two cases (full amount data
    // and only the crc32)
    fn get_amount_data_crc32(&self) -> Result<u32, KeyError> {
        // There are two cases: TxOutRecord with full amount data, and TxOutRecord with
        // only commitment data crc32 and masked value.
        if self.tx_out_amount_commitment_data.is_empty() {
            Ok(self.tx_out_amount_commitment_data_crc32)
        } else if self.tx_out_amount_commitment_data.len() == 32 {
            // If we are provided with a commitment, then we should compute crc32 of it and
            // discard those bytes, in order to unify early to one code path.
            Ok(crc32::checksum_ieee(&self.tx_out_amount_commitment_data))
        } else {
            // This is a malformed record
            Err(KeyError::LengthMismatch(
                32,
                self.tx_out_amount_commitment_data.len(),
            ))
        }
    }

    // Helper: Get the amount data crc32, resolving the two cases (full amount data
    // and only the crc32)
    fn get_e_memo(&self) -> Result<Option<EncryptedMemo>, MemoError> {
        // There are two cases: TxOutRecord with full memo data of the right length,
        // and no memo data.
        if self.tx_out_e_memo_data.is_empty() {
            Ok(None)
        } else {
            Ok(Some(EncryptedMemo::try_from(&self.tx_out_e_memo_data[..])?))
        }
    }
}

// FogTxOut is a redacted version of the TxOut, removing the fog hint, and with
// reduced data about Amount. The hint is only used during ingest, so we don't
// need to persist it.
#[derive(Clone, Eq, Hash, PartialEq, Debug, Default)]
pub struct FogTxOut {
    /// The one-time public address of this output.
    pub target_key: CompressedRistrettoPublic,

    /// The per output tx public key
    pub public_key: CompressedRistrettoPublic,

    /// The tx out masked amount
    pub amount_masked_value: u64,

    /// The crc32 of the tx out amount commitment bytes
    pub amount_commitment_data_crc32: u32,

    /// The encrypted memo, if present
    pub e_memo: Option<EncryptedMemo>,
}

// Convert a TxOut to a FogTxOut in the efficient way (omitting compressed
// commitment)
impl core::convert::From<&TxOut> for FogTxOut {
    #[inline]
    fn from(src: &TxOut) -> Self {
        Self {
            target_key: src.target_key,
            public_key: src.public_key,
            amount_masked_value: src.amount.masked_value,
            amount_commitment_data_crc32: crc32::checksum_ieee(
                src.amount.commitment.point.as_bytes(),
            ),
            e_memo: src.e_memo,
        }
    }
}

impl FogTxOut {
    /// Try to recover a TxOut from a FogTxOut and the user's private view key.
    ///
    /// * The amount commitment data is reconstructed, then we check if the
    ///   reconstructed data matches the crc32 provided.
    /// * The encrypted fog hint data is zeroed since it is not reconstructible
    ///   and isn't needed by the client.
    ///
    /// Arguments:
    /// * view_key: the private view key of the recipient of this TxOut
    ///
    /// Returns:
    /// * TxOut,
    /// Or
    /// * An error if recovery failed
    pub fn try_recover_tx_out(&self, view_key: &RistrettoPrivate) -> Result<TxOut, FogTxOutError> {
        // Reconstruct compressed commitment based on our view key.
        // The first step is reconstructing the TxOut shared secret
        let public_key = RistrettoPublic::try_from(&self.public_key)?;
        let tx_out_shared_secret =
            mc_transaction_core::get_tx_out_shared_secret(view_key, &public_key);

        // The next step is unblinding the amount value
        let value =
            self.amount_masked_value ^ mc_transaction_core::get_value_mask(&tx_out_shared_secret);

        // Now we can rebuild the Amount object from the value and shared secret
        let amount = Amount::new(value, &tx_out_shared_secret)?;

        // Check that the crc32 of amount compressed commitment matches
        if self.amount_commitment_data_crc32
            != crc32::checksum_ieee(amount.commitment.point.as_bytes())
        {
            return Err(FogTxOutError::ChecksumMismatch);
        }

        Ok(TxOut {
            amount,
            target_key: self.target_key,
            public_key: self.public_key,
            e_fog_hint: EncryptedFogHint::from(&[0u8; ENCRYPTED_FOG_HINT_LEN]),
            e_memo: self.e_memo,
        })
    }
}

/// An error that occurs when trying to convert a FogTxOut to a TxOut
#[derive(Display, Debug)]
pub enum FogTxOutError {
    /// CompressedCommitment crc32 mismatch
    ChecksumMismatch,
    /// An invalid amount: {0}
    Amount(AmountError),
    /// An invalid key: {0}
    Key(KeyError),
    /// An invalid memo: {0}
    Memo(MemoError),
}

impl From<AmountError> for FogTxOutError {
    fn from(src: AmountError) -> Self {
        Self::Amount(src)
    }
}

impl From<KeyError> for FogTxOutError {
    fn from(src: KeyError) -> Self {
        Self::Key(src)
    }
}

impl From<MemoError> for FogTxOutError {
    fn from(src: MemoError) -> Self {
        Self::Memo(src)
    }
}

/// A collection of metadata about a TxOut that fog preserves in the TxOutRecord
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct FogTxOutMetadata {
    /// The global index of this TxOut in the set of all TxOut's in the
    /// blockchain
    pub global_index: u64,
    /// The index of the block in which this TxOut appeared
    pub block_index: u64,
    /// The timestamp of the block in which this TxOut appeared, in seconds
    /// since the Unix epoch.
    pub timestamp: u64,
}
