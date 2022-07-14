// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Configuration for the avr history bootstrap file.

use crate::error::ParseError;

use mc_blockchain_types::{BlockIndex, VerificationReport, VerificationSignature};
use mc_common::ResponderId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{hex, serde_as, DeserializeAs, SerializeAs};
use std::{fs, option::Option, path::Path};

/// Struct for reading historical Intel Attestation Verification Report
/// (AVR) data from a configuration file.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AvrHistoryConfig {
    // List of AvrHistoryRecord objects sorted by ResponderId and block range
    node: Vec<AvrHistoryRecord>,
}

/// Stores a historical AVR record (or lack thereof) for a given
/// [ResponderId] and block range
#[serde_as]
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AvrHistoryRecord {
    /// Uri of the consensus node
    pub responder_id: ResponderId,

    /// Block the AVR Report for the signing key becomes valid
    pub first_block_index: BlockIndex,

    /// Final block the AVR Report for the signing key is valid
    pub last_block_index: BlockIndex,

    /// AVR Report (or lack thereof) for the node & block ranges
    #[serde_as(as = "Option<VerificationReportShadow>")]
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
    pub fn try_from_file(path: impl AsRef<Path>) -> Result<AvrHistoryConfig, ParseError> {
        let data = fs::read_to_string(path)?;

        if let Ok(mut config) = serde_json::from_str(&data): Result<AvrHistoryConfig, _> {
            config.node.sort();
            Ok(config)
        } else if let Ok(mut config) = toml::from_str(&data): Result<AvrHistoryConfig, _> {
            config.node.sort();
            Ok(config)
        } else {
            Err(ParseError::UnsuportedFileFormat)
        }
    }
}

#[serde_as]
#[derive(Deserialize, Serialize)]
#[serde(remote = "VerificationReport")]
/// Struct to shadow the mc_blockchain_types's VerificationReport for
/// serialization purposes
pub struct VerificationReportShadow {
    /// Report Signature bytes, from the X-IASReport-Signature HTTP header.
    #[serde_as(as = "hex::Hex")]
    pub sig: VerificationSignature,

    /// Attestation Report Signing Certificate Chain, as an array of
    /// DER-formatted bytes, from the X-IASReport-Signing-Certificate HTTP
    /// header.
    #[serde_as(as = "Vec<hex::Hex>")]
    pub chain: Vec<Vec<u8>>,

    /// The raw report body JSON, as a byte sequence
    pub http_body: String,
}

// SerializeAs and Deserialize are needed to get VerificationReportShadow (serde
// remote) to work with container types (ie. Option<VerificationReport> )
impl SerializeAs<VerificationReport> for VerificationReportShadow {
    fn serialize_as<S>(source: &VerificationReport, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        VerificationReportShadow::serialize(source, serializer)
    }
}

impl<'de> DeserializeAs<'de, VerificationReport> for VerificationReportShadow {
    fn deserialize_as<D>(deserializer: D) -> Result<VerificationReport, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper(#[serde(with = "VerificationReportShadow")] VerificationReport);
        let helper = Helper::deserialize(deserializer)?;
        let Helper(v) = helper;
        Ok(v)
    }
}
