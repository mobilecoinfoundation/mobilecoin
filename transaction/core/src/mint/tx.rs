// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Minting transactions.

use crate::{domain_separators::MINT_TX_PREFIX_DOMAIN_TAG, encrypted_fog_hint::EncryptedFogHint};
use alloc::vec::Vec;
use core::fmt;
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_keys::{Ed25519Signature, RistrettoPublic};
use mc_crypto_multisig::MultiSig;

#[cfg(feature = "prost")]
use prost::Message;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The contents of a mint-tx, which is a transaction to mint new tokens.
#[derive(
    Clone, Digestible, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
#[cfg_attr(feature = "prost", derive(Message))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MintTxPrefix {
    /// Token ID we are minting.
    #[cfg_attr(feature="prost", prost(uint64, tag = "1"))]
    pub token_id: u64,

    /// Amount we are minting.
    #[cfg_attr(feature="prost", prost(uint64, tag = "2"))]
    pub amount: u64,

    /// The destination's public subaddress view key 'C'.
    #[cfg_attr(feature="prost", prost(message, required, tag = "3"))]
    pub view_public_key: RistrettoPublic,

    /// The destination's public subaddress spend key `D`.
    #[cfg_attr(feature="prost", prost(message, required, tag = "4"))]
    pub spend_public_key: RistrettoPublic,

    /// Nonce, to prevent replay attacks.
    /// Must be exactly 64 bytes long (see constant constants::NONCE_LENGTH).
    #[cfg_attr(feature="prost", prost(bytes, tag = "5"))]
    pub nonce: Vec<u8>,

    /// The block index at which this transaction is no longer valid.
    #[cfg_attr(feature="prost", prost(uint64, tag = "6"))]
    pub tombstone_block: u64,

    /// Optional, encrypted fog hint, if you are trying to mint to a fog user.
    #[cfg_attr(feature="prost", prost(message, tag = "7"))]
    pub e_fog_hint: Option<EncryptedFogHint>,
}

impl MintTxPrefix {
    /// Digestible-crate hash of `self` using Merlin
    pub fn hash(&self) -> [u8; 32] {
        self.digest32::<MerlinTranscript>(MINT_TX_PREFIX_DOMAIN_TAG.as_bytes())
    }
}

/// A mint transaction coupled with a signature over it.
#[derive(
    Clone, Digestible, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
#[cfg_attr(feature = "prost", derive(Message))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct MintTx {
    /// The transaction contents.
    #[cfg_attr(feature="prost", prost(message, required, tag = "1"))]
    pub prefix: MintTxPrefix,

    /// The transaction signature.
    #[cfg_attr(feature="prost", prost(message, required, tag = "2"))]
    pub signature: MultiSig<Ed25519Signature>,
}

impl fmt::Display for MintTx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex_fmt::HexFmt(&self.prefix.nonce))
    }
}
