// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Common validation code shared between different mint transaction types.

use crate::{
    mint::{constants::NONCE_LENGTH, validation::error::Error},
    validation::{
        validate_tombstone as transaction_validate_tombstone, TransactionValidationError,
    },
    BlockVersion, TokenId,
};

/// A wrapper around crate::validation::validate_tombstone that maps to our
/// error type.
///
/// # Arguments
/// * `current_block_index` - The index of the block currently being built.
/// * `tombstone_block_index` - The block index at which this transaction is no
///   longer considered valid.
pub fn validate_tombstone(
    current_block_index: u64,
    tombstone_block_index: u64,
) -> Result<(), Error> {
    transaction_validate_tombstone(current_block_index, tombstone_block_index).map_err(|err| {
        match err {
            TransactionValidationError::TombstoneBlockExceeded => Error::TombstoneBlockExceeded,
            TransactionValidationError::TombstoneBlockTooFar => Error::TombstoneBlockTooFar,
            _ => Error::Unknown, /* This should never happen since validate_tombstone only
                                  * returns one of the two error types above */
        }
    })
}

/// The current block version being built must support minting.
///
/// # Arguments
/// * `block_version` - The block version of the block currently being built.
pub fn validate_block_version(block_version: BlockVersion) -> Result<(), Error> {
    if !block_version.mint_transactions_are_supported() || BlockVersion::MAX < block_version {
        return Err(Error::InvalidBlockVersion(block_version));
    }

    Ok(())
}

/// The token id being minted must be supported.
///
/// Arguments:
/// * `token_id` - The token id being minted.
pub fn validate_token_id(token_id: u32) -> Result<(), Error> {
    if token_id == *TokenId::MOB {
        return Err(Error::InvalidTokenId(token_id));
    }

    Ok(())
}

/// The nonce must be of the correct length.
///
/// # Arguments
/// `nonce` - The nonce to validate.
pub fn validate_nonce(nonce: &[u8]) -> Result<(), Error> {
    if nonce.len() != NONCE_LENGTH {
        return Err(Error::InvalidNonceLength(nonce.len()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_block_version_accepts_valid_block_versions() {
        assert!(validate_block_version(BlockVersion::TWO).is_ok());
        assert!(validate_block_version(BlockVersion::MAX).is_ok());
    }

    #[test]
    fn validate_block_version_rejects_unsupported_block_versions() {
        assert_eq!(
            validate_block_version(BlockVersion::ONE),
            Err(Error::InvalidBlockVersion(BlockVersion::ONE))
        );
        assert_eq!(
            validate_block_version(BlockVersion::ZERO),
            Err(Error::InvalidBlockVersion(BlockVersion::ZERO))
        );
    }

    #[test]
    fn validate_token_id_accepts_valid_token_ids() {
        assert!(validate_token_id(1).is_ok());
        assert!(validate_token_id(10).is_ok());
    }

    #[test]
    fn validate_token_id_rejects_invalid_token_ids() {
        assert_eq!(validate_token_id(0), Err(Error::InvalidTokenId(0)));
    }

    #[test]
    fn validate_nonce_accepts_valid_nonces() {
        validate_nonce(&[1u8; NONCE_LENGTH]).unwrap();
    }

    #[test]
    fn validate_nonce_rejects_invalid_nonces() {
        assert_eq!(validate_nonce(&[]), Err(Error::InvalidNonceLength(0)));
        assert_eq!(
            validate_nonce(&[1u8; NONCE_LENGTH - 1]),
            Err(Error::InvalidNonceLength(NONCE_LENGTH - 1))
        );
        assert_eq!(
            validate_nonce(&[1u8; NONCE_LENGTH + 1]),
            Err(Error::InvalidNonceLength(NONCE_LENGTH + 1))
        );
    }
}
