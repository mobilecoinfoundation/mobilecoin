// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Transaction Summary types, see [mc_transaction_core::tx_summary::Summarize]
//! for summary details.

use alloc::vec::Vec;

use crate::masked_amount::MaskedAmount;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_crypto_ring_signature::CompressedCommitment;

#[cfg(feature = "prost")]
use prost::Message;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A subset of the data in a Tx which enables efficient verification (e.g. by a
/// HW wallet) of the inputs and outputs of a transaction being signed.
#[derive(Clone, Digestible, Eq, Hash, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "prost", derive(Message))]
#[cfg_attr(not(feature = "prost"), derive(Default))]
pub struct TxSummary {
    /// The outputs which will be added to the blockchain as a result of this
    /// transaction
    #[cfg_attr(feature = "prost", prost(message, repeated, tag = "1"))]
    pub outputs: Vec<TxOutSummary>,

    /// Data in the summary associated to each real input
    #[cfg_attr(feature = "prost", prost(message, repeated, tag = "2"))]
    pub inputs: Vec<TxInSummary>,

    /// Fee paid to the foundation for this transaction
    #[cfg_attr(feature = "prost", prost(uint64, tag = "3"))]
    pub fee: u64,

    /// Token id for the fee output of this transaction
    #[cfg_attr(feature = "prost", prost(uint64, tag = "4"))]
    pub fee_token_id: u64,

    /// The block index at which this transaction is no longer valid.
    #[cfg_attr(feature = "prost", prost(uint64, tag = "5"))]
    pub tombstone_block: u64,
}

/// A subset of the data of a TxOut.
///
/// Fog hint and memo are omitted to reduce size and complexity on HW device,
/// which can't really do much with those and isn't very interested in them
/// anyways.
#[derive(Clone, Digestible, Eq, Hash, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "prost", derive(Message))]
pub struct TxOutSummary {
    /// The amount being sent.
    // Note: These tags must match those of MaskedAmount enum in transaction-core
    #[cfg_attr(feature = "prost", prost(oneof = "MaskedAmount", tags = "1, 6"))]
    pub masked_amount: Option<MaskedAmount>,

    /// The one-time public address of this output.
    #[cfg_attr(feature = "prost", prost(message, required, tag = "2"))]
    pub target_key: CompressedRistrettoPublic,

    /// The per output tx public key
    #[cfg_attr(feature = "prost", prost(message, required, tag = "3"))]
    pub public_key: CompressedRistrettoPublic,

    /// Whether or not this output is associated to an input with rules
    #[cfg_attr(feature = "prost", prost(bool, tag = "4"))]
    pub associated_to_input_rules: bool,
}

/// Data in a TxSummary associated to a transaction input.
///
/// This includes only the pseudo output commitment and the InputRules if any,
/// omitting the Ring and the proofs of membership.
#[derive(Clone, Digestible, Eq, Hash, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "prost", derive(Message))]
#[cfg_attr(not(feature = "prost"), derive(Debug, Default))]
pub struct TxInSummary {
    /// Commitment of value equal to the real input.
    #[cfg_attr(feature = "prost", prost(message, required, tag = "1"))]
    pub pseudo_output_commitment: CompressedCommitment,

    /// If there are input rules associated to this input, the canonical digest
    /// of these (per MCIP 52). If not, then this field is empty.
    #[cfg_attr(feature = "prost", prost(bytes, tag = "2"))]
    pub input_rules_digest: Vec<u8>,
}
