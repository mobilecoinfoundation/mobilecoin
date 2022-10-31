// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use mc_consensus_service_config::{SignerIdentity, SignerIdentityError, SignerIdentityMap};
use mc_transaction_core::{mint::MintConfigTxPrefix, TokenId};
use serde::{Deserialize, Serialize};
use serde_json::Error as JsonError;
use std::{fs, io::Error as IoError, path::Path};

/// A MintConfig in a human readable format. This is meant to be JSON
/// serialized.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MintConfig {
    /// The maximum amount that this configuration is allowed to mint during the
    /// time it is active.
    pub mint_limit: u64,

    /// Signer identities - this allows the configuration to contain a human
    /// readable mapping of names to signer identities.
    #[serde(default)]
    pub signer_identities: SignerIdentityMap,

    /// Governors - the set of keys that can sign mint transactions.
    pub minters: SignerIdentity,
}

/// A file format for serializing/deserializing a MintConfigTx in a human
/// readable format. This is meant to be JSON serialized.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MintConfigTxFile {
    /// Token id being configured.
    pub token_id: TokenId,

    /// Mint configurations
    pub configs: Vec<MintConfig>,

    /// Nonce, which is optional in the case we want this tool to auto-generate
    /// one.
    pub nonce: Option<Vec<u8>>,

    /// Tombstone block, which is optional in case we want this tool to populate
    /// it.
    pub tombstone_block: Option<u64>,

    /// The maximal amount that can be minted by configurations specified in
    /// this tx. This amount is shared amongst all configs.
    pub total_mint_limit: u64,
}

impl MintConfigTxFile {
    /// Load a [MintConfigFile] from a JSON file.
    pub fn from_json_file<P: AsRef<Path>>(path: P) -> Result<Self, MintConfigTxFileError> {
        let json = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }
}

impl TryFrom<&MintConfigTxFile> for MintConfigTxPrefix {
    type Error = MintConfigTxFileError;

    fn try_from(src: &MintConfigTxFile) -> Result<Self, Self::Error> {
        let nonce = src
            .nonce
            .as_ref()
            .ok_or(MintConfigTxFileError::MissingNonce)?
            .clone();

        let tombstone_block = src
            .tombstone_block
            .ok_or(MintConfigTxFileError::MissingTombstoneBlock)?;

        let configs = src
            .configs
            .iter()
            .map(|config| {
                let signer_set = config
                    .minters
                    .try_into_signer_set(&config.signer_identities)?;
                Ok(mc_transaction_core::mint::MintConfig {
                    token_id: *src.token_id,
                    signer_set,
                    mint_limit: config.mint_limit,
                })
            })
            .collect::<Result<Vec<_>, Self::Error>>()?;

        Ok(Self {
            token_id: *src.token_id,
            configs,
            nonce,
            tombstone_block,
            total_mint_limit: src.total_mint_limit,
        })
    }
}

/// Error data type
#[derive(Debug, Display)]
pub enum MintConfigTxFileError {
    /// Missing nonce
    MissingNonce,

    /// Missing tombstone block
    MissingTombstoneBlock,

    /// IO error: {0}
    Io(IoError),

    /// JSON error: {0}
    Json(JsonError),

    /// Signer identity error: {0}
    SignerIdentity(SignerIdentityError),
}

impl From<IoError> for MintConfigTxFileError {
    fn from(src: IoError) -> Self {
        Self::Io(src)
    }
}

impl From<JsonError> for MintConfigTxFileError {
    fn from(src: JsonError) -> Self {
        Self::Json(src)
    }
}

impl From<SignerIdentityError> for MintConfigTxFileError {
    fn from(src: SignerIdentityError) -> Self {
        Self::SignerIdentity(src)
    }
}
