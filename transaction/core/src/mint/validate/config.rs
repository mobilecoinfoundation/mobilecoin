// Copyright (c) 2018-2022 The MobileCoin Foundation

//! SetMintConfigTx transaction validation.

use crate::{
    mint::{
        config::{MintConfig, SetMintConfigTx},
        constants::{NONCE_MAX_LENGTH, NONCE_MIN_LENGTH},
    },
    validation::{validate_tombstone, TransactionValidationError},
    BlockVersion, TokenId,
};
use displaydoc::Display;
use mc_crypto_keys::Ed25519Public;
use mc_crypto_multisig::SignerSet;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Error {
    /// Invalid block version: {0}
    BlockVersion(BlockVersion),

    /// Invalid token id: {0}
    TokenId(u32),

    /// Invalid nonce length: {0}
    NonceLength(usize),

    /// Invalid signer set
    SignerSet,

    /// Invalid signature
    Signature,

    /// Number of blocks in ledger exceeds the tombstone block number
    TombstoneBlockExceeded,

    /// Tombstone block is too far in the future
    TombstoneBlockTooFar,

    /// Unknown error (should never happen)
    Unknown,
}

/// TODO document
pub fn validate_set_mint_config_tx(
    tx: &SetMintConfigTx,
    current_block_index: u64,
    block_version: BlockVersion,
    signer_set: &SignerSet<Ed25519Public>,
) -> Result<(), Error> {
    validate_block_version(block_version)?;

    validate_token_id(tx.prefix.token_id)?;

    validate_configs(tx.prefix.token_id, &tx.prefix.configs)?;

    validate_nonce(&tx.prefix.nonce)?;

    validate_tombstone(current_block_index, tx.prefix.tombstone_block).map_err(
        |err| match err {
            TransactionValidationError::TombstoneBlockExceeded => Error::TombstoneBlockExceeded,
            TransactionValidationError::TombstoneBlockTooFar => Error::TombstoneBlockTooFar,
            _ => Error::Unknown, /* This should never happen since validate_tombstone only
                                  * returns one of the two error types above */
        },
    )?;

    validate_signature(&tx, signer_set)?;

    Ok(())
}

fn validate_block_version(block_version: BlockVersion) -> Result<(), Error> {
    // TODO this should actually be block version THREE!
    if block_version < BlockVersion::TWO || BlockVersion::MAX < block_version {
        return Err(Error::BlockVersion(block_version));
    }

    Ok(())
}

fn validate_token_id(token_id: u32) -> Result<(), Error> {
    if token_id == *TokenId::MOB {
        return Err(Error::TokenId(token_id));
    }

    Ok(())
}

fn validate_configs(token_id: u32, configs: &[MintConfig]) -> Result<(), Error> {
    for config in configs {
        if config.token_id != token_id {
            return Err(Error::TokenId(token_id));
        }

        let num_signers = config.signer_set.signers().len();
        if num_signers == 0 || num_signers < config.signer_set.threshold() as usize {
            return Err(Error::SignerSet);
        }
    }

    Ok(())
}

fn validate_nonce(nonce: &[u8]) -> Result<(), Error> {
    if nonce.len() < NONCE_MIN_LENGTH || nonce.len() > NONCE_MAX_LENGTH {
        return Err(Error::NonceLength(nonce.len()));
    }

    Ok(())
}

fn validate_signature(
    tx: &SetMintConfigTx,
    signer_set: &SignerSet<Ed25519Public>,
) -> Result<(), Error> {
    let message = tx.prefix.hash();

    signer_set
        .verify(&message[..], &tx.signature)
        .map_err(|_| Error::Signature)
        .map(|_| ())
}
