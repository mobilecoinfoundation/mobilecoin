use crate::Block;
use core::fmt::{Debug, Display, Formatter, Result as FmtResult};
use digestible::Digestible;
use keys::{
    DigestSigner, DigestVerifier, Ed25519Pair, Ed25519Public, Ed25519Signature,
    Ed25519SignatureError,
};
use serde::{Deserialize, Serialize};
use sha2::Sha512;

/// A block signature.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockSignature {
    /// The actual signature of the block.
    signature: Ed25519Signature,

    /// The public key of the keypair used to generate the signature.
    signer: Ed25519Public,
}

impl BlockSignature {
    /// Create a new BlockSignature from an existing signature.
    ///
    /// # Arguments
    /// * `signature` - A block signature.
    /// * `signer` - The signer of the signature.
    pub fn new(signature: Ed25519Signature, signer: Ed25519Public) -> Self {
        Self { signature, signer }
    }

    /// Create a new BlockSignature by signing a block.
    pub fn from_block_and_keypair(
        block: &Block,
        keypair: &Ed25519Pair,
    ) -> Result<Self, Ed25519SignatureError> {
        // SHA512 is used for compatibility with Ed25519ph.
        let mut hasher = Sha512::default();
        block.digest(&mut hasher);
        let signature = keypair.try_sign_digest(hasher)?;

        let signer = keypair.public_key();

        Ok(Self { signature, signer })
    }

    /// Get the signature.
    pub fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }

    /// Get the signer.
    pub fn signer(&self) -> &Ed25519Public {
        &self.signer
    }

    /// Verify that this signature is over a given block.
    pub fn verify(&self, block: &Block) -> Result<(), Ed25519SignatureError> {
        let mut hasher = Sha512::default();
        block.digest(&mut hasher);

        self.signer.verify_digest(hasher, &self.signature)
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

impl Debug for BlockSignature {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "BlockSignature({}:{})",
            hex_fmt::HexFmt(&self.signature),
            hex_fmt::HexFmt(&self.signer)
        )
    }
}
