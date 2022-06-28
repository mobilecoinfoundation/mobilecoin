// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A [BlockMetadata] validator.

pub mod avr;
pub mod key_range;

use crate::{metadata::avr::AvrValidator, ParseError, ValidationError};
use key_range::KeyRangeValidator;
use mc_blockchain_types::{BlockData, BlockIndex, BlockMetadata};
use mc_common::ResponderId;
use std::path::Path;

/// A [BlockMetadata] validator that validates metadata signatures, signing
/// keys, and AVRs.
pub struct MetadataValidator {
    /// Message signing key & metadata signature validator
    pub key_range: KeyRangeValidator,

    /// AVR & block signing key validator
    pub avr: AvrValidator,
}

impl MetadataValidator {
    /// Instantiate a validator.
    ///
    /// Args:
    /// `signers_config`: Path to `metadata-signers.toml`
    pub fn new(
        signers_config: impl AsRef<Path>,
        avr_history: impl AsRef<Path>,
    ) -> Result<Self, ParseError> {
        let key_range = KeyRangeValidator::load(signers_config)?;
        let avr = AvrValidator::load(avr_history)?;
        Ok(Self { key_range, avr })
    }

    /// Validate block metadata signature, signing keys, and AVRs
    ///
    /// Args:
    /// block_data: Block data for the block we want to validate metadata for
    /// responder_id: Optional responder id to validate metadata for. If None,
    /// validation of ResponderId will be skipped.
    pub fn validate(
        &self,
        block_data: &BlockData,
        responder_id: &Option<ResponderId>,
    ) -> Result<(), ValidationError> {
        let block_index = block_data.block().index;

        self.validate_block_signing_key_and_avr(block_data, responder_id)?;
        block_data.metadata().as_ref().map_or(Ok(()), |metadata| {
            self.validate_block_signing_key_and_metadata_signature(metadata, block_index)
        })
    }

    /// Validate the Block Signing Key and Attestation Verification Report
    /// for a block
    pub fn validate_block_signing_key_and_avr(
        &self,
        block_data: &BlockData,
        responder_id: &Option<ResponderId>,
    ) -> Result<(), ValidationError> {
        self.avr
            .validate_block_signing_key_and_avr(block_data, responder_id)
    }

    /// Validate that the given metadata is valid at the given block index.
    pub fn validate_block_signing_key_and_metadata_signature(
        &self,
        metadata: &BlockMetadata,
        block_index: BlockIndex,
    ) -> Result<(), ValidationError> {
        self.key_range.validate(metadata.node_key(), block_index)?;
        metadata.verify()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{make_key, make_metadata};
    use mc_crypto_keys::Ed25519Signature;

    const IAS_HISTORY: &str = "src/metadata/avr/data/sample_ias_records.toml";

    fn make_validator() -> MetadataValidator {
        let avr_data_path = Path::new(IAS_HISTORY);
        let key_range = KeyRangeValidator::new(
            [
                // Key #1 is always valid.
                (make_key(1), vec![0..=BlockIndex::MAX]),
                // Key #2 is only valid for the first 11 blocks.
                (make_key(2), vec![0..=10]),
                // Key #3 is valid from block index 10 onward.
                (make_key(3), vec![10..=BlockIndex::MAX]),
            ]
            .into(),
        );

        let avr = AvrValidator::load(avr_data_path).unwrap();

        MetadataValidator { key_range, avr }
    }

    #[test]
    fn happy_path() {
        let validator = make_validator();
        let metadata = make_metadata(1);
        assert_eq!(
            validator.validate_block_signing_key_and_metadata_signature(&metadata, 0),
            Ok(())
        );
        assert_eq!(
            validator.validate_block_signing_key_and_metadata_signature(&metadata, 10),
            Ok(())
        );
        assert_eq!(
            validator.validate_block_signing_key_and_metadata_signature(&metadata, 100),
            Ok(())
        );
        assert_eq!(
            validator.validate_block_signing_key_and_metadata_signature(&metadata, 1000),
            Ok(())
        );
    }

    #[test]
    fn unrecognized_key() {
        let validator = make_validator();
        let metadata = make_metadata(10);
        assert_eq!(
            validator.validate_block_signing_key_and_metadata_signature(&metadata, 0),
            Err(ValidationError::UnknownPubKey)
        );
    }

    #[test]
    fn expired_key() {
        let validator = make_validator();
        let metadata = make_metadata(2);
        assert_eq!(
            validator.validate_block_signing_key_and_metadata_signature(&metadata, 11),
            Err(ValidationError::InvalidPubKey)
        );
        assert_eq!(
            validator.validate_block_signing_key_and_metadata_signature(&metadata, 10),
            Ok(())
        );
    }

    #[test]
    fn premature_key() {
        let validator = make_validator();
        let metadata = make_metadata(3);
        assert_eq!(
            validator.validate_block_signing_key_and_metadata_signature(&metadata, 1),
            Err(ValidationError::InvalidPubKey)
        );
        assert_eq!(
            validator.validate_block_signing_key_and_metadata_signature(&metadata, 9),
            Err(ValidationError::InvalidPubKey)
        );
        assert_eq!(
            validator.validate_block_signing_key_and_metadata_signature(&metadata, 10),
            Ok(())
        );
    }

    #[test]
    fn bad_metadata_signature() {
        let validator = make_validator();
        let ok_metadata = make_metadata(1);
        assert_eq!(
            validator.validate_block_signing_key_and_metadata_signature(&ok_metadata, 0),
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
            validator.validate_block_signing_key_and_metadata_signature(&metadata, 0),
            Err(ValidationError::Signature(_))
        ));
    }
}
