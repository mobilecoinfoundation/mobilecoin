// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A [BlockMetadata] validator.

pub mod key_range;

use crate::{ParseError, ValidationError};
use key_range::KeyRangeValidator;
use mc_blockchain_types::{BlockIndex, BlockMetadata};
use std::path::Path;

/// A [BlockMetadata] validator that validates metadata signatures, signing
/// keys, and AVRs.
pub struct MetadataValidator {
    key_range: KeyRangeValidator,
}

impl MetadataValidator {
    /// Instantiate a validator.
    ///
    /// Args:
    /// `signers_config`: Path to `metadata-signers.toml`
    pub fn new(signers_config: impl AsRef<Path>) -> Result<Self, ParseError> {
        let key_range = KeyRangeValidator::load(signers_config)?;

        Ok(Self { key_range })
    }

    /// Validate that the given metadata is valid at the given block index.
    pub fn validate(
        &self,
        metadata: &BlockMetadata,
        block_index: BlockIndex,
    ) -> Result<(), ValidationError> {
        self.key_range.validate(metadata.node_key(), block_index)?;
        // TODO: Validate AVR.
        metadata.verify()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{make_key, make_metadata};
    use mc_crypto_keys::Ed25519Signature;

    fn make_validator() -> MetadataValidator {
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

        MetadataValidator { key_range }
    }

    #[test]
    fn happy_path() {
        let validator = make_validator();
        let metadata = make_metadata(1);
        assert_eq!(validator.validate(&metadata, 0), Ok(()));
        assert_eq!(validator.validate(&metadata, 10), Ok(()));
        assert_eq!(validator.validate(&metadata, 100), Ok(()));
        assert_eq!(validator.validate(&metadata, 1000), Ok(()));
    }

    #[test]
    fn unrecognized_key() {
        let validator = make_validator();
        let metadata = make_metadata(10);
        assert_eq!(
            validator.validate(&metadata, 0),
            Err(ValidationError::UnknownPubKey)
        );
    }

    #[test]
    fn expired_key() {
        let validator = make_validator();
        let metadata = make_metadata(2);
        assert_eq!(
            validator.validate(&metadata, 11),
            Err(ValidationError::InvalidPubKey)
        );
        assert_eq!(validator.validate(&metadata, 10), Ok(()));
    }

    #[test]
    fn premature_key() {
        let validator = make_validator();
        let metadata = make_metadata(3);
        assert_eq!(
            validator.validate(&metadata, 1),
            Err(ValidationError::InvalidPubKey)
        );
        assert_eq!(
            validator.validate(&metadata, 9),
            Err(ValidationError::InvalidPubKey)
        );
        assert_eq!(validator.validate(&metadata, 10), Ok(()));
    }

    #[test]
    fn bad_metadata_signature() {
        let validator = make_validator();
        let ok_metadata = make_metadata(1);
        assert_eq!(validator.validate(&ok_metadata, 0), Ok(()));

        let mut signature_bytes = ok_metadata.signature().to_bytes();
        signature_bytes[0] += 1;
        let metadata = BlockMetadata::new(
            ok_metadata.contents().clone(),
            *ok_metadata.node_key(),
            Ed25519Signature::new(signature_bytes),
        );

        assert!(matches!(
            validator.validate(&metadata, 0),
            Err(ValidationError::Signature(_))
        ));
    }
}
