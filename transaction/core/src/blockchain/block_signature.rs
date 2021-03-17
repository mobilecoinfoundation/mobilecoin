// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::Block;
use core::fmt::{Display, Formatter, Result as FmtResult};
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_keys::{
    Ed25519Pair, Ed25519Public, Ed25519Signature, Ed25519SignatureError, Signer, Verifier,
};
use prost::Message;
use serde::{Deserialize, Serialize};

/// A block signature.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Message)]
pub struct BlockSignature {
    /// The actual signature of the block.
    #[prost(message, required, tag = "1")]
    signature: Ed25519Signature,

    /// The public key of the keypair used to generate the signature.
    #[prost(message, required, tag = "2")]
    signer: Ed25519Public,

    /// An approximate time in which the block was signed.
    /// Represented as seconds of UTC time since Unix epoch
    /// 1970-01-01T00:00:00Z.
    #[prost(uint64, tag = "3")]
    signed_at: u64,
}

impl BlockSignature {
    /// Create a new BlockSignature from an existing signature.
    ///
    /// # Arguments
    /// * `signature` - A block signature.
    /// * `signer` - The signer of the signature.
    /// * `signed_at` - The approximate time in which the block was signed,
    ///   represented at seconds of UTC time since Unix epoch
    ///   1970-01-01T00:00:00Z.
    pub fn new(signature: Ed25519Signature, signer: Ed25519Public, signed_at: u64) -> Self {
        Self {
            signature,
            signer,
            signed_at,
        }
    }

    /// Create a new BlockSignature by signing a block.
    /// Since is generally done inside an enclave, time is not available. As
    /// such, `signed_at` is being initialized to zero. It can then be set
    /// by calling `set_signed_at`.
    pub fn from_block_and_keypair(
        block: &Block,
        keypair: &Ed25519Pair,
    ) -> Result<Self, Ed25519SignatureError> {
        let digest = block.digest32::<MerlinTranscript>(b"block-sig");
        let signature = keypair.try_sign(&digest)?;

        let signer = keypair.public_key();

        Ok(Self {
            signature,
            signer,
            signed_at: 0,
        })
    }

    /// Set the value of `signed_at`.
    pub fn set_signed_at(&mut self, signed_at: u64) {
        self.signed_at = signed_at;
    }

    /// Get the signature.
    pub fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }

    /// Get the signer.
    pub fn signer(&self) -> &Ed25519Public {
        &self.signer
    }

    /// Get the signed at timestamp.
    pub fn signed_at(&self) -> u64 {
        self.signed_at
    }

    /// Verify that this signature is over a given block.
    pub fn verify(&self, block: &Block) -> Result<(), Ed25519SignatureError> {
        let digest = block.digest32::<MerlinTranscript>(b"block-sig");

        self.signer.verify(&digest, &self.signature)
    }
}

impl Display for BlockSignature {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "{}:{}",
            hex_fmt::HexFmt(&self.signature),
            hex_fmt::HexFmt(&self.signer)
        )
    }
}
