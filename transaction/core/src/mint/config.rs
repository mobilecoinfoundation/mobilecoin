// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Minting transaction configuration.

use alloc::vec::Vec;
use mc_crypto_digestible::Digestible;
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

/// The contents of a set-mint-config transaction. This transaction alters the
/// minting configuration for a single token ID.
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct SetMintConfigTxPrefix {
    /// Token ID we are replacing the configuration set for.
    #[prost(uint32, tag = "1")]
    pub token_id: u32,

    /// The new configuration.
    #[prost(message, repeated, tag = "2")]
    pub configs: Vec<MintConfig>,

    /// Nonce, to prevent replay attacks.
    #[prost(bytes, tag = "3")]
    pub nonce: Vec<u8>,

    /// The block index at which this transaction is no longer valid.
    #[prost(uint64, tag = "4")]
    pub tombstone_block: u64,
}

/// A set-mint-config transaction coupled with a signature over it.
#[derive(
    Clone, Deserialize, Digestible, Eq, Hash, Message, Ord, PartialEq, PartialOrd, Serialize,
)]
pub struct SetMintConfigTx {
    #[prost(message, required, tag = "1")]
    pub prefix: SetMintConfigTxPrefix,

    #[prost(message, required, tag = "2")]
    pub signature: MultiSig<Ed25519Signature>,
}
