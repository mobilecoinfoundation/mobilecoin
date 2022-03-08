// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Common validation code shared between different mint transaction types.

use crate::{
    mint::{
        constants::{NONCE_MAX_LENGTH, NONCE_MIN_LENGTH},
        validation::error::Error,
    },
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
pub fn validate_block_version(block_version: BlockVersion) -> Result<(), Error> {
    // TODO this should actually be block version THREE!
    if block_version < BlockVersion::TWO || BlockVersion::MAX < block_version {
        return Err(Error::BlockVersion(block_version));
    }

    Ok(())
}

/// The token id being minted must be supported.
pub fn validate_token_id(token_id: u32) -> Result<(), Error> {
    if token_id == *TokenId::MOB {
        return Err(Error::TokenId(token_id));
    }

    Ok(())
}

/// The nonce must be within the hardcoded lenght limit.
pub fn validate_nonce(nonce: &[u8]) -> Result<(), Error> {
    if nonce.len() < NONCE_MIN_LENGTH || nonce.len() > NONCE_MAX_LENGTH {
        return Err(Error::NonceLength(nonce.len()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_block_version_accepts_valid_block_versions() {
        assert!(validate_block_version(BlockVersion::TWO).is_ok()); // TODO needs to be three
        assert!(validate_block_version(BlockVersion::MAX).is_ok()); // TODO needs to be three
    }

    #[test]
    fn validate_block_version_rejects_unsupported_block_versions() {
        assert_eq!(
            validate_block_version(BlockVersion::ONE),
            Err(Error::BlockVersion(BlockVersion::ONE))
        );
    }

    #[test]
    fn validate_token_id_accepts_valid_token_ids() {
        assert!(validate_token_id(1).is_ok());
        assert!(validate_token_id(10).is_ok());
    }

    #[test]
    fn validate_token_id_rejects_invalid_token_ids() {
        assert_eq!(validate_token_id(0), Err(Error::TokenId(0)));
    }

    #[test]
    fn validate_nonce_accepts_valid_nonces() {
        validate_nonce(&[1u8; NONCE_MIN_LENGTH]).unwrap();
        validate_nonce(&[1u8; NONCE_MIN_LENGTH + 1]).unwrap();
        validate_nonce(&[1u8; NONCE_MAX_LENGTH]).unwrap();
    }

    #[test]
    fn validate_nonce_rejects_valid_nonces() {
        assert_eq!(validate_nonce(&[]), Err(Error::NonceLength(0)));
        assert_eq!(
            validate_nonce(&[1u8; NONCE_MIN_LENGTH - 1]),
            Err(Error::NonceLength(NONCE_MIN_LENGTH - 1))
        );
        assert_eq!(
            validate_nonce(&[1u8; NONCE_MAX_LENGTH + 1]),
            Err(Error::NonceLength(NONCE_MAX_LENGTH + 1))
        );
    }
}
