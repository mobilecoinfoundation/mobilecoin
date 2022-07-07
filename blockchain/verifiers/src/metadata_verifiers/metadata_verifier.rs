// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A [BlockMetadata] verifier.

use crate::{
    metadata_verifiers::{avr::AvrVerifier, message_signing_key::MessageSigningKeyVerifier},
    VerificationError,
};
use mc_blockchain_types::{BlockData, BlockIndex, BlockMetadata};
use mc_common::ResponderId;

/// A [BlockMetadata] verifier that verifies metadata signatures, signing
/// keys, and AVRs.
pub struct MetadataVerifier {
    /// Message signing key & metadata signature verifier
    pub message_signing_key_verifier: MessageSigningKeyVerifier,

    /// AVR & block signing key verifier
    pub avr_verifier: AvrVerifier,
}

impl MetadataVerifier {
    /// Instantiate a verifier.
    pub fn new(
        message_signing_key_verifier: MessageSigningKeyVerifier,
        avr_verifier: AvrVerifier,
    ) -> Self {
        Self {
            message_signing_key_verifier,
            avr_verifier,
        }
    }

    /// Verify block metadata signature, signing keys, and AVRs
    ///
    /// # Args:
    ///
    /// * `block_data` - [BlockData] for the block we want to verify AVRs,
    /// signing keys, and metadata signatures for.
    /// * `responder_id` - Optional [ResponderId] to verify historical AVRs
    /// against. Each [AvrVerificationRecord] includes a BlockRange and
    /// ResponderId an AVR was valid for. If this arg is provided, the function
    /// additionally ensures that the ResponderId matches the ResponderId in
    /// the record.
    pub fn verify(
        &self,
        block_data: &BlockData,
        responder_id: &Option<ResponderId>,
    ) -> Result<(), VerificationError> {
        let block_index = block_data.block().index;

        self.verify_block_signing_key_and_avr(block_data, responder_id)?;
        block_data.metadata().map_or(Ok(()), |metadata| {
            self.verify_block_signing_key_and_metadata_signature(metadata, block_index)
        })
    }

    /// Verify the Block Signing Key and Attestation Verification Report
    /// for a block
    ///
    /// # Args:
    ///
    /// * `block_data` - [BlockData] for the block we want to verify an AVR
    /// and block signing key for.
    /// * `responder_id` - Optional [ResponderId] to verify historical AVRs
    /// against. Each [AvrVerificationRecord] includes a BlockRange and
    /// ResponderId an AVR was valid for. If this arg is provided, the function
    /// additionally ensures that the ResponderId matches the ResponderId in
    /// the record.
    pub fn verify_block_signing_key_and_avr(
        &self,
        block_data: &BlockData,
        responder_id: &Option<ResponderId>,
    ) -> Result<(), VerificationError> {
        self.avr_verifier
            .verify_block_signing_key_and_avr(block_data, responder_id)
    }

    /// Verify that the given metadata is valid at the given block index.
    ///
    /// # Args:
    ///
    /// `metadata` - [BlockMetadata] to verify
    /// `block_index` - [BlockIndex] to verify metadata at
    pub fn verify_block_signing_key_and_metadata_signature(
        &self,
        metadata: &BlockMetadata,
        block_index: BlockIndex,
    ) -> Result<(), VerificationError> {
        self.message_signing_key_verifier
            .verify(metadata.node_key(), block_index)?;
        metadata.verify()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{make_metadata, make_verifier};
    use mc_crypto_keys::Ed25519Signature;

    #[test]
    fn test_metadata_verification_of_valid_signing_key_and_metadata_signature() {
        let verifier = make_verifier();
        let metadata = make_metadata(1);
        assert_eq!(
            verifier.verify_block_signing_key_and_metadata_signature(&metadata, 0),
            Ok(())
        );
        assert_eq!(
            verifier.verify_block_signing_key_and_metadata_signature(&metadata, 10),
            Ok(())
        );
        assert_eq!(
            verifier.verify_block_signing_key_and_metadata_signature(&metadata, 100),
            Ok(())
        );
        assert_eq!(
            verifier.verify_block_signing_key_and_metadata_signature(&metadata, 1000),
            Ok(())
        );
    }

    #[test]
    fn test_metadata_verification_with_unrecognized_key() {
        let verifier = make_verifier();
        let metadata = make_metadata(10);
        assert_eq!(
            verifier.verify_block_signing_key_and_metadata_signature(&metadata, 0),
            Err(VerificationError::UnknownMessageSigningKey)
        );
    }

    #[test]
    fn test_metadata_verification_with_expired_key() {
        let verifier = make_verifier();
        let metadata = make_metadata(2);
        assert_eq!(
            verifier.verify_block_signing_key_and_metadata_signature(&metadata, 11),
            Err(VerificationError::InvalidMessageSigningKey)
        );
        assert_eq!(
            verifier.verify_block_signing_key_and_metadata_signature(&metadata, 10),
            Ok(())
        );
    }

    #[test]
    fn test_metadata_verification_with_premature_key() {
        let verifier = make_verifier();
        let metadata = make_metadata(3);
        assert_eq!(
            verifier.verify_block_signing_key_and_metadata_signature(&metadata, 1),
            Err(VerificationError::InvalidMessageSigningKey)
        );
        assert_eq!(
            verifier.verify_block_signing_key_and_metadata_signature(&metadata, 9),
            Err(VerificationError::InvalidMessageSigningKey)
        );
        assert_eq!(
            verifier.verify_block_signing_key_and_metadata_signature(&metadata, 10),
            Ok(())
        );
    }

    #[test]
    fn test_metadata_verification_with_bad_metadata_signature() {
        let verifier = make_verifier();
        let ok_metadata = make_metadata(1);
        assert_eq!(
            verifier.verify_block_signing_key_and_metadata_signature(&ok_metadata, 0),
            Ok(())
        );

        let mut signature_bytes = ok_metadata.signature().to_bytes();
        signature_bytes[0] += 1;
        let metadata = BlockMetadata::new(
            ok_metadata.contents().clone(),
            *ok_metadata.node_key(),
            Ed25519Signature::new(signature_bytes),
        );

        assert!(matches!(
            verifier.verify_block_signing_key_and_metadata_signature(&metadata, 0),
            Err(VerificationError::BlockMetadataSignature(_))
        ));
    }
}
