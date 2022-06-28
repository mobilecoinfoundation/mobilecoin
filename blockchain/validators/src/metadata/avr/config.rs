// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Facilities for creating an AVR verifier object from a configuration file.

use crate::{
    error::ParseError,
    metadata::avr::{AvrValidationRecord, AvrValidator},
    ValidationError,
};
use mc_attest_core::serial;
use mc_attest_verifier::{Verifier, DEBUG_ENCLAVE};
use mc_blockchain_types::{BlockIndex, VerificationReport};
use mc_common::ResponderId;
use mc_crypto_keys::Ed25519Public;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ffi::OsStr, fs, path::Path};
use TryFrom;

const IAS_ANCHORS: &[&str] = &[include_str!(
    "../../../../../attest/verifier/data/AttestationReportSigningCACert.pem"
)];

/// Struct for holding reading historical Intel Attestation Verification
/// data from a configuration file.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AvrConfig {
    /// AVR Records
    #[serde(rename = "node")]
    pub avr_records: Vec<AvrConfigRecord>,
}

impl AvrConfig {
    /// Returns the AVR Report for the given block index, if it exists
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ParseError> {
        let path = path.as_ref();
        let bytes = fs::read(path)?;
        let config: AvrConfig = match path.extension().and_then(OsStr::to_str) {
            Some("toml") => Ok(toml::from_slice(&bytes)?),
            Some("json") => Ok(serde_json::from_slice(&bytes)?),
            _ => Err(ParseError::UnrecognizedExtension(path.into())),
        }?;
        Ok(config)
    }

    /// Parse records recovered from toml and pre-validate avrs. Consumes self
    pub fn create_avr_validator(&mut self) -> Result<AvrValidator, ValidationError> {
        let mut avr_history = HashMap::new();
        let mut avr_verifier = Verifier::new(IAS_ANCHORS)?;
        avr_verifier.debug(DEBUG_ENCLAVE);
        let mut responder_id_to_empty_last_blocks = HashMap::new();
        for record in &self.avr_records {
            let last_block_index = match record.last_block_index.as_ref() {
                Some(last_block_index) => {
                    if let Some(start_index) =
                        responder_id_to_empty_last_blocks.get(&record.responder_id)
                    {
                        if start_index < last_block_index {
                            return Err(ValidationError::Other(format!(
                                "Intermediate AVR record starting at {} missing last block index",
                                start_index
                            )));
                        }
                    }
                    *last_block_index
                }
                None => {
                    if let Some(start_index) =
                        responder_id_to_empty_last_blocks.get(&record.responder_id)
                    {
                        return Err(ValidationError::Other(format!(
                            "Intermediate AVR record starting at {} missing last block index",
                            start_index
                        )));
                    }
                    responder_id_to_empty_last_blocks
                        .insert(record.responder_id.clone(), record.first_block_index);
                    u64::MAX
                }
            };
            if let Some(avr) = record.avr.as_ref() {
                let verification_data = avr_verifier.verify(avr)?;
                let signing_key =
                    Ed25519Public::try_from(verification_data.signing_key_bytes()?.as_slice())?;
                let validation_record = AvrValidationRecord {
                    block_range: record.first_block_index..=last_block_index,
                    responder_id: record.responder_id.clone(),
                    avr: avr.clone(),
                };
                avr_history.insert(signing_key, validation_record);
            }
        }
        Ok(AvrValidator {
            avr_history,
            avr_verifier,
        })
    }
}

/// Stores a historical AVR record (or lack thereof) for a given
/// ResponderId and block range
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AvrConfigRecord {
    /// Uri of the consensus node
    pub responder_id: ResponderId,

    /// Block the AVR Report for the signing key becomes valid
    pub first_block_index: BlockIndex,

    /// Final block the AVR Report for the signing key is valid
    pub last_block_index: Option<BlockIndex>,

    /// AVR Report (or lack thereof) for the node & block ranges
    #[serde(default, with = "serial")]
    pub avr: Option<VerificationReport>,
}

impl AvrConfigRecord {
    /// Create new AVRConfigRecord
    pub fn new(
        responder_id: &ResponderId,
        first_block_index: BlockIndex,
        last_block_index: Option<BlockIndex>,
        avr: Option<VerificationReport>,
    ) -> Self {
        Self {
            responder_id: responder_id.clone(),
            first_block_index,
            last_block_index,
            avr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IAS_FULL: &str = include_str!("../../../../../attest/core/data/test/ias_full.toml");
    const IAS_HISTORY: &str = "src/metadata/avr/data/sample_ias_records.toml";

    #[test]
    fn test_avr_history_serialization_works() {
        // Create sample ResponderIds
        let responderid_1 = ResponderId("mc://peer1.test.mobilecoin.com".to_string());
        let responderid_2 = ResponderId("mc://peer2.test.mobilecoin.com".to_string());
        let report: VerificationReport = toml::from_str(IAS_FULL).unwrap();

        // Create sample historical records
        let record_1 = AvrConfigRecord::new(&responderid_1, 0, Some(1), None);
        let record_2 = AvrConfigRecord::new(&responderid_1, 2, Some(4), Some(report.clone()));
        let record_3 = AvrConfigRecord::new(&responderid_1, 5, Some(1000), Some(report.clone()));
        let record_4 = AvrConfigRecord::new(&responderid_2, 0, Some(1), None);
        let record_5 = AvrConfigRecord::new(&responderid_2, 1, None, Some(report.clone()));

        let mut avr_records = Vec::new();
        avr_records.push(record_1);
        avr_records.push(record_2);
        avr_records.push(record_3);
        avr_records.push(record_4);
        avr_records.push(record_5);
        let records = AvrConfig { avr_records };

        let toml_str = toml::to_string_pretty(&records).unwrap();
        let json_str = serde_json::to_string_pretty(&records).unwrap();
        let toml_records: AvrConfig = toml::from_str(toml_str.as_str()).unwrap();
        let json_records: AvrConfig = serde_json::from_str(json_str.as_str()).unwrap();
        assert_eq!(records, toml_records);
        assert_eq!(records, json_records)
    }

    #[test]
    fn test_avr_validator_loads_from_valid_records() {
        // Load test records
        let path = Path::new(IAS_HISTORY);
        let config = AvrConfig::load(path).unwrap();
        let avr_count = config
            .avr_records
            .iter()
            .filter(|rec| rec.avr.is_some())
            .count();

        let validator = AvrValidator::load(path).unwrap();
        assert_eq!(validator.avr_history.len(), avr_count);
    }

    #[test]
    fn test_avr_validator_creation_fails_if_intermediate_ranges_are_missing() {
        let path = Path::new(IAS_HISTORY);
        let mut avr_config = AvrConfig::load(path).unwrap();
        avr_config.avr_records[1].last_block_index = None;

        // Assert that the validator fails to load a last_block on an intermediate
        // range is missing.
        assert!(matches!(
            avr_config.create_avr_validator(),
            Err(ValidationError::Other(_))
        ));
    }
}
