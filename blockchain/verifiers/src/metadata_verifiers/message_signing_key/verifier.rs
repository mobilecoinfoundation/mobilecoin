// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Message signing key verifier.

use super::MessageSigningKeyValidityMap;
use crate::VerificationError;
use mc_blockchain_types::BlockIndex;
use mc_crypto_keys::Ed25519Public;

/// Verifier that checks that a given key is used within a configured range
/// of indexes.
#[derive(Clone, Debug)]
pub struct MessageSigningKeyVerifier {
    config: MessageSigningKeyValidityMap,
}

impl MessageSigningKeyVerifier {
    /// Instantiate a validator with the given key validity ranges.
    pub fn new(config: MessageSigningKeyValidityMap) -> Self {
        Self { config }
    }

    /// Verifies that the given signing key is allowed at the given block index.
    pub fn verify(
        &self,
        message_signing_key: &Ed25519Public,
        block_index: BlockIndex,
    ) -> Result<(), VerificationError> {
        let ranges = self
            .config
            .get(message_signing_key)
            .ok_or(VerificationError::UnknownMessageSigningKey)?;

        if ranges.iter().any(|range| range.contains(&block_index)) {
            Ok(())
        } else {
            Err(VerificationError::InvalidMessageSigningKey)
        }
    }
}
