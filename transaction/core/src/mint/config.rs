// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Minting transaction configuration.

use crate::domain_separators::MINT_CONFIG_TX_PREFIX_DOMAIN_TAG;
use alloc::vec::Vec;
use core::fmt;
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_keys::{Ed25519Public, Ed25519Signature};
use mc_crypto_multisig::{MultiSig, SignerSet};
use mc_util_serial::Message;
use serde::{Deserialize, Serialize};

/// A minting configuration for a single token ID.
/// The minting configuration specifies who is allowed to submit mint
/// transactions, for which token and at what total limit.
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct MintConfig {
    /// Token ID this configuration applies to.
    #[prost(uint32, tag = "1")]
    pub token_id: u32,

    /// The set of keys that can sign a minting transaction.
    #[prost(message, required, tag = "2")]
    pub signer_set: SignerSet<Ed25519Public>,

    /// The maximal amount this configuration can mint from the moment it has
    /// been applied.
    #[prost(uint64, tag = "3")]
    pub mint_limit: u64,
}

/// The contents of a mint-config transaction. This transaction alters the
/// minting configuration for a single token ID.
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct MintConfigTxPrefix {
    /// Token ID we are replacing the configuration set for.
    #[prost(uint32, tag = "1")]
    pub token_id: u32,

    /// The new configuration.
    #[prost(message, repeated, tag = "2")]
    pub configs: Vec<MintConfig>,

    /// Nonce, to prevent replay attacks.
    /// Must be exactly 64 bytes long (see constant constants::NONCE_LENGTH).
    #[prost(bytes, tag = "3")]
    pub nonce: Vec<u8>,

    /// The block index at which this transaction is no longer valid.
    #[prost(uint64, tag = "4")]
    pub tombstone_block: u64,

    /// The maximal amount that can be minted from the moment this configuration
    /// is applied. This amount is shared amongst all configs.
    #[prost(uint64, tag = "5")]
    pub mint_limit: u64,
}

impl MintConfigTxPrefix {
    /// Digestible-crate hash of `self` using Merlin
    pub fn hash(&self) -> [u8; 32] {
        self.digest32::<MerlinTranscript>(MINT_CONFIG_TX_PREFIX_DOMAIN_TAG.as_bytes())
    }
}

/// A mint-config transaction coupled with a signature over it.
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct MintConfigTx {
    /// The transaction contents.
    #[prost(message, required, tag = "1")]
    pub prefix: MintConfigTxPrefix,

    /// The transaction signature.
    #[prost(message, required, tag = "2")]
    pub signature: MultiSig<Ed25519Signature>,
}

impl fmt::Display for MintConfigTx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex_fmt::HexFmt(&self.prefix.nonce))
    }
}

/// A mint-config transaction coupled with the data used to validate it.
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct ValidatedMintConfigTx {
    /// The transaction that was validated.
    #[prost(message, required, tag = "1")]
    pub mint_config_tx: MintConfigTx,

    /// The signer set used to validate the transaction's signature.
    #[prost(message, required, tag = "2")]
    pub signer_set: SignerSet<Ed25519Public>,
}
