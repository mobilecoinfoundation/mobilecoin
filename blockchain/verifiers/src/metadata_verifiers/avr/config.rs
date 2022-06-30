// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Configuration for the avr verifier.

use crate::{
    error::ParseError,
    get_signing_key_from_verification_report_data,
    metadata_verifiers::avr::{AvrVerificationRecord, AvrVerifier},
    VerificationError,
};
use mc_attest_core::serial;
use mc_attest_verifier::Verifier;
use mc_blockchain_types::{BlockIndex, VerificationReport};
use mc_common::ResponderId;
use mc_crypto_keys::Ed25519Public;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, ffi::OsStr, fs, path::Path};

/// Struct for holding reading historical Intel Attestation Verification
/// data from a configuration file.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AvrConfig {
    /// AVR Records
    #[serde(rename = "node")]
    avr_records: Vec<AvrConfigRecord>,
}

impl AvrConfig {
    /// Create new AVR config from a list of AVR records
    pub fn new(avr_records: Vec<AvrConfigRecord>) -> Self {
        let mut records = Self { avr_records };
        records.avr_records.sort();
        records
    }

    /// Returns the AVR Report for the given block index, if it exists
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ParseError> {
        let path = path.as_ref();
        let bytes = fs::read(path)?;
        let mut config: AvrConfig = match path.extension().and_then(OsStr::to_str) {
            Some("toml") => Ok(toml::from_slice(&bytes)?),
            Some("json") => Ok(serde_json::from_slice(&bytes)?),
            _ => Err(ParseError::UnrecognizedExtension(path.into())),
        }?;
        config.avr_records.sort();
        Ok(config)
    }

    /// Verify historical records, don't have duplicate signing keys or
    /// overlapping/invalid ranges. If no issues are found, return an
    /// avr verifier object.
    pub fn verify_data(&self) -> Result<AvrVerifier, VerificationError> {
        let mut avr_history: HashMap<Ed25519Public, AvrVerificationRecord> = HashMap::new();
        let avr_verifier = Verifier::default();
        for (i, record) in self.avr_records.iter().enumerate() {
            if record.first_block_index > record.last_block_index {
                return Err(VerificationError::InvalidRange(
                    record.first_block_index,
                    record.last_block_index,
                    record.responder_id.clone(),
                ));
            }
            if i > 0
                && self.avr_records[i - 1].responder_id == record.responder_id
                && self.avr_records[i - 1].last_block_index >= record.first_block_index
            {
                return Err(VerificationError::ResponderRangeOverlap(
                    record.first_block_index,
                    record.last_block_index,
                    self.avr_records[i - 1].first_block_index,
                    self.avr_records[i - 1].last_block_index,
                    record.responder_id.clone(),
                ));
            }
            if let Some(avr) = record.avr.as_ref() {
                let verification_data = avr_verifier.verify(avr)?;
                let signing_key =
                    get_signing_key_from_verification_report_data(&verification_data)?;
                if let Some(rec) = avr_history.get(&signing_key) {
                    return Err(VerificationError::DuplicateBlockSigningKey(
                        hex::encode(signing_key),
                        record.first_block_index,
                        record.last_block_index,
                        *rec.block_range.start(),
                        *rec.block_range.end(),
                    ));
                }
                let verification_record = AvrVerificationRecord {
                    block_range: record.first_block_index..=record.last_block_index,
                    responder_id: record.responder_id.clone(),
                    avr: avr.clone(),
                };
                avr_history.insert(signing_key, verification_record);
            }
        }
        Ok(AvrVerifier {
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
    pub last_block_index: BlockIndex,

    /// AVR Report (or lack thereof) for the node & block ranges
    #[serde(default, with = "serial")]
    pub avr: Option<VerificationReport>,
}

impl AvrConfigRecord {
    /// Create new AVRConfigRecord
    pub fn new(
        responder_id: &ResponderId,
        first_block_index: BlockIndex,
        last_block_index: BlockIndex,
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
    use crate::test_utils::{
        get_avr_config, get_ias_report, SAMPLE_AVR_HISTORY_JSON, SAMPLE_AVR_HISTORY_TOML,
    };
    use std::str::FromStr;
    use tempfile::TempDir;

    #[test]
    fn test_avr_history_serialization_roundtrip_works() {
        let avr_history = get_avr_config();
        let toml_str = toml::to_string_pretty(&avr_history).unwrap();
        let json_str = serde_json::to_string_pretty(&avr_history).unwrap();
        let toml_records: AvrConfig = toml::from_str(toml_str.as_str()).unwrap();
        let json_records: AvrConfig = serde_json::from_str(json_str.as_str()).unwrap();
        assert_eq!(avr_history, toml_records);
        assert_eq!(avr_history, json_records);
    }

    #[test]
    fn test_avr_history_load_from_disk() {
        // Get control not loaded from disk
        let control_avr_history = get_avr_config();

        // Write JSON and TOML to disk
        let temp = TempDir::new().unwrap();
        let path_json = temp.path().join("avr-history.json");
        let path_toml = temp.path().join("avr-history.toml");
        fs::write(&path_json, SAMPLE_AVR_HISTORY_JSON).unwrap();
        fs::write(&path_toml, SAMPLE_AVR_HISTORY_TOML).unwrap();

        let avr_history_from_json = AvrConfig::load(path_json).unwrap();
        let avr_history_from_toml = AvrConfig::load(path_toml).unwrap();

        // Check that the loaded AvrConfigs are the same as the control AvrConfig
        assert_eq!(control_avr_history, avr_history_from_json);
        assert_eq!(control_avr_history, avr_history_from_toml);
    }

    #[test]
    fn test_avr_history_fails_for_invalid_ranges() {
        // Get control not loaded from disk
        let avr = get_ias_report();

        // Create configs with invalid ranges
        let responder_id = ResponderId::from_str("node1.prod.mobilecoinww.com::8843").unwrap();
        let rec1 = AvrConfigRecord::new(&responder_id, 0, 1, None);
        let rec2 = AvrConfigRecord::new(&responder_id, 1, 300, None);
        let rec3 = AvrConfigRecord::new(&responder_id, 301, 123000, Some(avr));
        let overlapping_range_config = AvrConfig::new(vec![rec1, rec2, rec3]);
        let rec4 = AvrConfigRecord::new(&responder_id, 0, 1, None);
        let rec5 = AvrConfigRecord::new(&responder_id, 300, 2, None);
        let reversed_range_config = AvrConfig::new(vec![rec4, rec5]);

        // Serialize & deserialize configs with invalid ranges
        let overlapping = toml::to_string_pretty(&overlapping_range_config).unwrap();
        let reversed = toml::to_string_pretty(&reversed_range_config).unwrap();
        let temp = TempDir::new().unwrap();
        let overlapping_path = temp.path().join("overlapping.toml");
        let reversed_path = temp.path().join("reversed.toml");
        fs::write(&overlapping_path, overlapping).unwrap();
        fs::write(&reversed_path, reversed).unwrap();
        let overlapping_history = AvrConfig::load(overlapping_path).unwrap();
        let reversed_history = AvrConfig::load(reversed_path).unwrap();

        // Check that the errors covering both cases are triggered
        assert!(matches!(
            overlapping_history.verify_data(),
            Err(VerificationError::ResponderRangeOverlap(_, _, _, _, _))
        ));
        assert!(matches!(
            reversed_history.verify_data(),
            Err(VerificationError::InvalidRange(_, _, _))
        ));
    }

    #[test]
    fn test_avr_history_fails_for_duplicate_block_signing_keys() {
        let avr = get_ias_report();

        // Create config with duplicate block signing keys
        let responder_id = ResponderId::from_str("node1.prod.mobilecoinww.com::8843").unwrap();
        let rec1 = AvrConfigRecord::new(&responder_id, 0, 1, None);
        let rec2 = AvrConfigRecord::new(&responder_id, 2, 300, Some(avr.clone()));
        let rec3 = AvrConfigRecord::new(&responder_id, 301, 123000, Some(avr));
        let duplicate_config = AvrConfig::new(vec![rec1, rec2, rec3]);

        // Serialize & deserialize config with duplicate block signing keys
        let duplicate_key_config = toml::to_string_pretty(&duplicate_config).unwrap();
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("duplicate.toml");
        fs::write(&path, duplicate_key_config).unwrap();
        let duplicate_key_history = AvrConfig::load(path).unwrap();

        // Check that the errors covering both cases are triggered
        assert!(matches!(
            duplicate_key_history.verify_data(),
            Err(VerificationError::DuplicateBlockSigningKey(_, _, _, _, _))
        ));
    }
}
