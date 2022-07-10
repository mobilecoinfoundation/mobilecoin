// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Configuration for the avr history bootstrap file.

use crate::{
    error::ParseError,
};


use mc_blockchain_types::{BlockIndex, VerificationReport};
use mc_common::ResponderId;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

/// Struct for reading historical Intel Attestation Verification Report
/// (AVR) data from a configuration file.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AvrHistoryConfig {
    // List of AvrHistoryRecord objects sorted by ResponderId and block range
    node: Vec<AvrHistoryRecord>,
}

/// Stores a historical AVR record (or lack thereof) for a given
/// [ResponderId] and block range
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AvrHistoryRecord {
    /// Uri of the consensus node
    pub responder_id: ResponderId,

    /// Block the AVR Report for the signing key becomes valid
    pub first_block_index: BlockIndex,

    /// Final block the AVR Report for the signing key is valid
    pub last_block_index: BlockIndex,

    /// AVR Report (or lack thereof) for the node & block ranges
    //#[serde(default, with = "mc_attest_core::serial")]
    pub avr: Option<VerificationReport>,
}

impl AvrHistoryConfig {
    /// Load the [AvrHistoryConfig] from a .json or .toml file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the configuration file containing
    /// the history of AVRs generated MobileCoin consensus node
    /// enclaves
    pub fn try_from_file(path: impl AsRef<Path>) -> Result <AvrHistoryConfig, ParseError>{
        let data = fs::read_to_string(path)?;

        if let Ok(mut config ) = serde_json::from_str(&data) : Result<AvrHistoryConfig, _>{
            config.node.sort();
            Ok(config)
        }else if let Ok(mut config ) = toml::from_str(&data) : Result<AvrHistoryConfig, _>{
            config.node.sort();
            Ok(config)
        }
        else{
            Err(ParseError::UnsuportedFileFormat)
        }
    }
}


