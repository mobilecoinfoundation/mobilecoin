// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Minting transactions.

use crate::domain_separators::MINT_TX_PREFIX_DOMAIN_TAG;
use alloc::vec::Vec;
use core::fmt;
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_keys::{Ed25519Signature, RistrettoPublic};
use mc_crypto_multisig::MultiSig;
use mc_util_serial::Message;
use serde::{Deserialize, Serialize};

/// The contents of a mint-tx, which is a transaction to mint new tokens.
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct MintTxPrefix {
    /// Token ID we are minting.
    #[prost(uint32, tag = "1")]
    pub token_id: u32,

    /// Amount we are minting.
    #[prost(uint64, tag = "2")]
    pub amount: u64,

    /// The destination's public subaddress view key 'C'.
    #[prost(message, required, tag = "3")]
    pub view_public_key: RistrettoPublic,

    /// The destination's public subaddress spend key `D`.
    #[prost(message, required, tag = "4")]
    pub spend_public_key: RistrettoPublic,

    /// Nonce, to prevent replay attacks.
    /// Must be exactly 64 bytes long (see constant constants::NONCE_LENGTH).
    #[prost(bytes, tag = "5")]
    pub nonce: Vec<u8>,

    /// The block index at which this transaction is no longer valid.
    #[prost(uint64, tag = "6")]
    pub tombstone_block: u64,
}

impl MintTxPrefix {
    /// Digestible-crate hash of `self` using Merlin
    pub fn hash(&self) -> [u8; 32] {
        self.digest32::<MerlinTranscript>(MINT_TX_PREFIX_DOMAIN_TAG.as_bytes())
    }
}

/// A mint transaction coupled with a signature over it.
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct MintTx {
    /// The transaction contents.
    #[prost(message, required, tag = "1")]
    pub prefix: MintTxPrefix,

    /// The transaction signature.
    #[prost(message, required, tag = "2")]
    pub signature: MultiSig<Ed25519Signature>,
}

impl fmt::Display for MintTx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex_fmt::HexFmt(&self.prefix.nonce))
    }
}
