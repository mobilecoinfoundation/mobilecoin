// Copyright (c) 2018-2022 The MobileCoin Foundation

use alloc::vec::Vec;

use mc_account_keys::PublicAddress;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::RistrettoPrivate;
use mc_transaction_types::UnmaskedAmount;

#[cfg(feature = "prost")]
use prost::Message;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Unblinding data correpsonding to a TxSummary. This reveals the amounts of
/// all inputs and outputs in a way that can be confirmed against the TxSummary.
#[derive(Clone, Digestible, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature="serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "prost", derive(Message))]
#[cfg_attr(not(feature = "prost"), derive(Debug))]
pub struct TxSummaryUnblindingData {
    /// The block version targetted by the outputs of this Tx
    #[cfg_attr(feature="prost", prost(uint32, tag = "1"))]
    pub block_version: u32,

    /// A TxOutSummaryUnblindingData, one for each transaction output
    #[cfg_attr(feature="prost", prost(message, repeated, tag = "2"))]
    pub outputs: Vec<TxOutSummaryUnblindingData>,

    /// An unmasked amount, one for each transaction input, corresponding to
    /// the pseudo-output commitment
    #[cfg_attr(feature="prost", prost(message, repeated, tag = "3"))]
    pub inputs: Vec<UnmaskedAmount>,
}

/// Unblinding data corresponding to a TxOutSummary. This reveals the amount
/// and, usually, the Public Address to which this TxOut is addressed.
#[derive(Clone, Digestible, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature="serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "prost", derive(Message))]
#[cfg_attr(not(feature = "prost"), derive(Debug))]
pub struct TxOutSummaryUnblindingData {
    /// An unmasked amount, corresponding to the MaskedAmount field
    /// The block vesion appears in the TxSummaryUnblindingData.
    #[cfg_attr(feature="prost", prost(message, required, tag = "1"))]
    pub unmasked_amount: UnmaskedAmount,

    /// The public address to which this TxOut is addressed.
    /// If this output comes from an SCI then we may not know the public
    /// address.
    #[cfg_attr(feature="prost", prost(message, optional, tag = "2"))]
    pub address: Option<PublicAddress>,

    /// The tx_private_key generated for this TxOut. This is an entropy source
    /// which introduces randomness into the cryptonote stealth addresses
    /// (tx_public_key and tx_target_key) of the TxOut.
    ///
    /// If this output comes from an SCI then we may not know this.
    #[cfg_attr(feature="prost", prost(message, optional, tag = "3"))]
    pub tx_private_key: Option<RistrettoPrivate>,
}
