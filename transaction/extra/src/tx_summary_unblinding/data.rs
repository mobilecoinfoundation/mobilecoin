// Copyright (c) 2018-2022 The MobileCoin Foundation

use alloc::vec::Vec;
use mc_account_keys::PublicAddress;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::RistrettoPrivate;
use mc_transaction_core::UnmaskedAmount;
use prost::Message;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Unblinding data correpsonding to a TxSummary. This reveals the amounts of
/// all inputs and outputs in a way that can be confirmed against the TxSummary.
#[derive(Clone, Deserialize, Digestible, Eq, Message, PartialEq, Serialize, Zeroize)]
pub struct TxSummaryUnblindingData {
    /// The block version targetted by the outputs of this Tx
    #[prost(uint32, tag = "1")]
    pub block_version: u32,

    /// A TxOutSummaryUnblindingData, one for each transaction output
    #[prost(message, repeated, tag = "2")]
    pub outputs: Vec<TxOutSummaryUnblindingData>,

    /// An unmasked amount, one for each transaction input, corresponding to
    /// the pseudo-output commitment
    #[prost(message, repeated, tag = "3")]
    pub inputs: Vec<UnmaskedAmount>,
}

/// Unblinding data corresponding to a TxOutSummary. This reveals the amount
/// and, usually, the Public Address to which this TxOut is addressed.
#[derive(Clone, Deserialize, Digestible, Eq, Message, PartialEq, Serialize, Zeroize)]
pub struct TxOutSummaryUnblindingData {
    /// An unmasked amount, corresponding to the MaskedAmount field
    /// The block vesion appears in the TxSummaryUnblindingData.
    #[prost(message, required, tag = "1")]
    pub unmasked_amount: UnmaskedAmount,

    /// The public address to which this TxOut is addressed.
    /// If this output comes from an SCI then we may not know the public
    /// address.
    #[prost(message, optional, tag = "2")]
    pub address: Option<PublicAddress>,

    /// The tx_private_key generated for this TxOut. This is an entropy source
    /// which introduces randomness into the cryptonote stealth addresses
    /// (tx_public_key and tx_target_key) of the TxOut.
    ///
    /// If this output comes from an SCI then we may not know this.
    #[prost(message, optional, tag = "3")]
    pub tx_private_key: Option<RistrettoPrivate>,
}
