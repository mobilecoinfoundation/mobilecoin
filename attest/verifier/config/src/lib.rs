// Copyright (c) 2018-2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs)]

extern crate alloc;

use alloc::{borrow::ToOwned, collections::BTreeMap, string::String, vec::Vec};
use displaydoc::Display;
use mc_attest_core::{MrEnclave, MrSigner};
use mc_attest_verifier::{MrEnclaveVerifier, MrSignerVerifier, Verifier, DEBUG_ENCLAVE};
use serde::{Deserialize, Serialize};

/// Defines a json schema for an individual attestation status verifier.
/// This is either a MRENCLAVE or MRSIGNER type, and the type is inferred by
/// the presence of these fields.
/// Unknown fields are flagged as an error.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum StatusVerifierConfig {
    /// A MRENCLAVE-based status verifier
    Mrenclave {
        /// The hex-encoded bytes of the MRENCLAVE measurement. This is
        /// enclavehash in the .css file
        #[serde(with = "hex", rename = "MRENCLAVE")]
        mr_enclave: [u8; 32],
        /// The list of config advisories that are known to be mitigated in
        /// software at this enclave revision.
        #[serde(default)]
        mitigated_config_advisories: Vec<String>,
        /// The list of hardening advisories that are known to be mitigated in
        /// software at this enclave revision.
        #[serde(default)]
        mitigated_hardening_advisories: Vec<String>,
    },
    /// A MRSIGNER-based status verifier
    Mrsigner {
        /// The hex-encoded bytes of the MRSIGNER measurement. This is a digest
        /// of the modulus in the .css file. Use a tool to see what it is.
        #[serde(with = "hex", rename = "MRSIGNER")]
        mr_signer: [u8; 32],
        /// The product id that this verifier checks for.
        product_id: u16,
        /// The minimum security version number that is considered valid by this
        /// verifier.
        minimum_svn: u16,
        /// The list of config advisories that are known to be mitigated in
        /// software at this enclave revision.
        #[serde(default)]
        mitigated_config_advisories: Vec<String>,
        /// The list of hardening advisories that are known to be mitigated in
        /// software at this enclave revision.
        #[serde(default)]
        mitigated_hardening_advisories: Vec<String>,
    },
}

impl StatusVerifierConfig {
    /// Build status verifier corresponding to ourself, and add it to a given
    /// verifier
    pub fn add_to_verifier(&self, verifier: &mut Verifier) {
        match self {
            Self::Mrenclave {
                mr_enclave,
                mitigated_config_advisories,
                mitigated_hardening_advisories,
            } => {
                let mut mr_enclave_verifier = MrEnclaveVerifier::new(MrEnclave::from(*mr_enclave));
                for advisory in mitigated_config_advisories.iter() {
                    mr_enclave_verifier.allow_config_advisory(advisory);
                }
                for advisory in mitigated_hardening_advisories.iter() {
                    mr_enclave_verifier.allow_hardening_advisory(advisory);
                }
                verifier.mr_enclave(mr_enclave_verifier);
            }
            Self::Mrsigner {
                mr_signer,
                product_id,
                minimum_svn,
                mitigated_config_advisories,
                mitigated_hardening_advisories,
            } => {
                let mut mr_signer_verifier =
                    MrSignerVerifier::new(MrSigner::from(*mr_signer), *product_id, *minimum_svn);
                for advisory in mitigated_config_advisories.iter() {
                    mr_signer_verifier.allow_config_advisory(advisory);
                }
                for advisory in mitigated_hardening_advisories.iter() {
                    mr_signer_verifier.allow_hardening_advisory(advisory);
                }
                verifier.mr_signer(mr_signer_verifier);
            }
        }
    }
}

/// Defines a json schema for a "trusted-measurements.json" file.
/// See README.md for example.
///
/// The outermost string key of this is the release version number. This is not
/// interpreted by the software, but could be added as a debug string or
/// something, and helps with maintenance of the file.
///
/// The second string key, within a release, is the name of the enclave that
/// this is a measurement for.
///
/// The VerifierConfig object contains measurement and hardening advisory data
/// for that enclave at that release.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct TrustedMeasurementSet {
    table: BTreeMap<String, BTreeMap<String, StatusVerifierConfig>>,
}

// Allow TrustedMeasurementSet to be logged nicely in json format
impl core::fmt::Display for TrustedMeasurementSet {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            fmt,
            "{}",
            serde_json::to_string_pretty(&self.table)
                .expect("json string formatting not expected to fail here")
        )
    }
}

impl TrustedMeasurementSet {
    /// Create a verifier from this measurement set for a given enclave name.
    pub fn create_verifier(&self, enclave_name: impl AsRef<str>) -> Result<Verifier, Error> {
        let enclave_name = enclave_name.as_ref();
        let mut count = 0usize;

        let mut verifier = Verifier::default();
        verifier.debug(DEBUG_ENCLAVE);

        for measurements in self.table.values() {
            if let Some(measurement) = measurements.get(enclave_name) {
                // TODO: it would be nice to add the release name in also as like
                // a debug string somewhere that would show up in error messages
                // when attestation fails?
                measurement.add_to_verifier(&mut verifier);
                count += 1;
            }
        }

        if count == 0 {
            return Err(Error::NoMeasurementsFound(enclave_name.to_owned()));
        }

        Ok(verifier)
    }
}

/// An error which can occur when trying to build an attestation verifier from a
/// TrustedMeasurementSet
#[derive(Display, Debug)]
pub enum Error {
    /// No measurements found for enclave name "{0}"
    NoMeasurementsFound(String),
}

#[cfg(test)]
mod tests {

    use super::*;

    use alloc::{string::ToString, vec};
    use hex_literal::hex;

    const TEST_DATA: &str = r#"{
    "v3": {
       "consensus": {
           "MRENCLAVE": "207c9705bf640fdb960034595433ee1ff914f9154fbe4bc7fc8a97e912961e5c",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"]
       },
       "fog-ingest": {
           "MRENCLAVE": "3370f131b41e5a49ed97c4188f7a976461ac6127f8d222a37929ac46b46d560e",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"]
       },
       "fog-ledger": {
           "MRENCLAVE": "fd4c1c82cca13fa007be15a4c90e2b506c093b21c2e7021a055cbb34aa232f3f",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"]
       },
       "fog-view": {
           "MRENCLAVE": "dca7521ce4564cc2e54e1637e533ea9d1901c2adcbab0e7a41055e719fb0ff9d",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"]
       }
    },
    "v4": {
       "consensus": {
           "MRENCLAVE": "e35bc15ee92775029a60a715dca05d310ad40993f56ad43bca7e649ccc9021b5",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"]
       },
       "fog-ingest": {
           "MRENCLAVE": "a8af815564569aae3558d8e4e4be14d1bcec896623166a10494b4eaea3e1c48c",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"]
       },
       "fog-ledger": {
           "MRENCLAVE": "da209f4b24e8f4471bd6440c4e9f1b3100f1da09e2836d236e285b274901ed3b",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"]
       },
       "fog-view": {
           "MRENCLAVE": "8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"]
       }
    }
}"#;

    #[test]
    fn test_loading() {
        let tms: TrustedMeasurementSet = serde_json::from_str(TEST_DATA).unwrap();

        assert_eq!(tms.table.len(), 2);
        let v3 = tms.table.get("v3").unwrap();
        assert_eq!(v3.len(), 4);
        let v3_consensus = v3.get("consensus").unwrap();
        let expected_consensus = StatusVerifierConfig::Mrenclave {
            mr_enclave: hex!("207c9705bf640fdb960034595433ee1ff914f9154fbe4bc7fc8a97e912961e5c"),
            mitigated_config_advisories: vec![],
            mitigated_hardening_advisories: vec![
                "INTEL-SA-00334".to_string(),
                "INTEL-SA-00615".to_string(),
            ],
        };
        assert_eq!(v3_consensus, &expected_consensus);
        let v3_fog_view = v3.get("fog-view").unwrap();
        let expected_fog_view = StatusVerifierConfig::Mrenclave {
            mr_enclave: hex!("dca7521ce4564cc2e54e1637e533ea9d1901c2adcbab0e7a41055e719fb0ff9d"),
            mitigated_config_advisories: vec![],
            mitigated_hardening_advisories: vec![
                "INTEL-SA-00334".to_string(),
                "INTEL-SA-00615".to_string(),
            ],
        };
        assert_eq!(v3_fog_view, &expected_fog_view);

        let v4 = tms.table.get("v4").unwrap();
        assert_eq!(v4.len(), 4);
        let v4_consensus = v4.get("consensus").unwrap();
        let expected_consensus = StatusVerifierConfig::Mrenclave {
            mr_enclave: hex!("e35bc15ee92775029a60a715dca05d310ad40993f56ad43bca7e649ccc9021b5"),
            mitigated_config_advisories: vec![],
            mitigated_hardening_advisories: vec![
                "INTEL-SA-00334".to_string(),
                "INTEL-SA-00615".to_string(),
                "INTEL-SA-00657".to_string(),
            ],
        };
        assert_eq!(v4_consensus, &expected_consensus);

        let v4_fog_view = v4.get("fog-view").unwrap();
        let expected_fog_view = StatusVerifierConfig::Mrenclave {
            mr_enclave: hex!("8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3"),
            mitigated_config_advisories: vec![],
            mitigated_hardening_advisories: vec![
                "INTEL-SA-00334".to_string(),
                "INTEL-SA-00615".to_string(),
                "INTEL-SA-00657".to_string(),
            ],
        };
        assert_eq!(v4_fog_view, &expected_fog_view);

        let _ = tms.create_verifier("consensus").unwrap();
        let _ = tms.create_verifier("fog-ingest").unwrap();
        let _ = tms.create_verifier("fog-ledger").unwrap();
        let _ = tms.create_verifier("fog-view").unwrap();

        assert!(tms.create_verifier("impostor").is_err());
    }

    const TEST_DATA2: &str = r#"{
    "v3": {
       "consensus": {
           "MRENCLAVE": "207c9705bf640fdb960034595433ee1ff914f9154fbe4bc7fc8a97e912961e5c",
           "mitigated_config_advisories": ["FOO"],
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"]
       },
       "fog-ingest": {
           "MRSIGNER": "2c1a561c4ab64cbc04bfa445cdf7bed9b2ad6f6b04d38d3137f3622b29fdb30e",
           "product_id": 1,
           "minimum_svn": 4,
           "mitigated_config_advisories": ["FOO"],
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"]
       },
       "fog-ledger": {
           "MRSIGNER": "2c1a561c4ab64cbc04bfa445cdf7bed9b2ad6f6b04d38d3137f3622b29fdb30e",
           "product_id": 2,
           "minimum_svn": 4,
           "mitigated_config_advisories": ["FOO"],
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"]
       },
       "fog-view": {
           "MRSIGNER": "2c1a561c4ab64cbc04bfa445cdf7bed9b2ad6f6b04d38d3137f3622b29fdb30e",
           "product_id": 3,
           "minimum_svn": 4,
           "mitigated_config_advisories": ["FOO"],
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"]
       }
    },
    "v4": {
       "consensus": {
           "MRENCLAVE": "e35bc15ee92775029a60a715dca05d310ad40993f56ad43bca7e649ccc9021b5",
           "mitigated_config_advisories": ["FOO"],
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"]
       },
       "fog-ingest": {
           "MRENCLAVE": "a8af815564569aae3558d8e4e4be14d1bcec896623166a10494b4eaea3e1c48c",
           "mitigated_config_advisories": ["FOO"],
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"]
       },
       "fog-ledger": {
           "MRENCLAVE": "da209f4b24e8f4471bd6440c4e9f1b3100f1da09e2836d236e285b274901ed3b",
           "mitigated_config_advisories": ["FOO"],
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"]
       },
       "fog-view": {
           "MRENCLAVE": "8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3",
           "mitigated_config_advisories": ["FOO"],
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"]
       }
    }
}"#;

    #[test]
    fn test_loading2() {
        let tms: TrustedMeasurementSet = serde_json::from_str(TEST_DATA2).unwrap();

        assert_eq!(tms.table.len(), 2);
        let v3 = tms.table.get("v3").unwrap();
        assert_eq!(v3.len(), 4);
        let v3_consensus = v3.get("consensus").unwrap();
        let expected_consensus = StatusVerifierConfig::Mrenclave {
            mr_enclave: hex!("207c9705bf640fdb960034595433ee1ff914f9154fbe4bc7fc8a97e912961e5c"),
            mitigated_config_advisories: vec!["FOO".to_string()],
            mitigated_hardening_advisories: vec![
                "INTEL-SA-00334".to_string(),
                "INTEL-SA-00615".to_string(),
            ],
        };
        assert_eq!(v3_consensus, &expected_consensus);

        let v3_fog_view = v3.get("fog-view").unwrap();
        let expected_fog_view = StatusVerifierConfig::Mrsigner {
            mr_signer: hex!("2c1a561c4ab64cbc04bfa445cdf7bed9b2ad6f6b04d38d3137f3622b29fdb30e"),
            product_id: 3,
            minimum_svn: 4,
            mitigated_config_advisories: vec!["FOO".to_string()],
            mitigated_hardening_advisories: vec![
                "INTEL-SA-00334".to_string(),
                "INTEL-SA-00615".to_string(),
            ],
        };
        assert_eq!(v3_fog_view, &expected_fog_view);

        let v4 = tms.table.get("v4").unwrap();
        assert_eq!(v4.len(), 4);
        let v4_consensus = v4.get("consensus").unwrap();
        let expected_consensus = StatusVerifierConfig::Mrenclave {
            mr_enclave: hex!("e35bc15ee92775029a60a715dca05d310ad40993f56ad43bca7e649ccc9021b5"),
            mitigated_config_advisories: vec!["FOO".to_string()],
            mitigated_hardening_advisories: vec![
                "INTEL-SA-00334".to_string(),
                "INTEL-SA-00615".to_string(),
                "INTEL-SA-00657".to_string(),
            ],
        };
        assert_eq!(v4_consensus, &expected_consensus);

        let v4_fog_view = v4.get("fog-view").unwrap();
        let expected_fog_view = StatusVerifierConfig::Mrenclave {
            mr_enclave: hex!("8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3"),
            mitigated_config_advisories: vec!["FOO".to_string()],
            mitigated_hardening_advisories: vec![
                "INTEL-SA-00334".to_string(),
                "INTEL-SA-00615".to_string(),
                "INTEL-SA-00657".to_string(),
            ],
        };
        assert_eq!(v4_fog_view, &expected_fog_view);

        let _ = tms.create_verifier("consensus").unwrap();
        let _ = tms.create_verifier("fog-ingest").unwrap();
        let _ = tms.create_verifier("fog-ledger").unwrap();
        let _ = tms.create_verifier("fog-view").unwrap();

        assert!(tms.create_verifier("impostor").is_err());
    }

    #[test]
    fn test_expected_failures() {
        // Not enough hex characters
        let result: Result<TrustedMeasurementSet, _> = serde_json::from_str(
            r#"{
            "v0": {
                "consensus": {
                    "MRENCLAVE": "8c80a2b95a549fa8d928d"
                }
            }
        }"#,
        );
        assert!(result.is_err());

        // Too many hex characters
        let result: Result<TrustedMeasurementSet, _> = serde_json::from_str(
            r#"{
            "v0": {
                "consensus": {
                    "MRENCLAVE": "8c80a2b95a549fa8d928d99999999999999999999999999999999999999999999999999999"
                }
            }
        }"#,
        );
        assert!(result.is_err());

        // Should work with right number of characters
        let result: Result<TrustedMeasurementSet, _> = serde_json::from_str(
            r#"{
            "v0": {
                "consensus": {
                    "MRENCLAVE": "8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3"
                }
            }
        }"#,
        );
        assert!(result.is_ok());

        // Mispelled key
        let result: Result<TrustedMeasurementSet, _> = serde_json::from_str(
            r#"{
            "v0": {
                "consensus": {
                    "MRENCLAV": "8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3"
                }
            }
        }"#,
        );
        assert!(result.is_err());

        // Missing MRSIGNER required attributes
        let result: Result<TrustedMeasurementSet, _> = serde_json::from_str(
            r#"{
            "v0": {
                "consensus": {
                    "MRSIGNER": "8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3"
                }
            }
        }"#,
        );
        assert!(result.is_err());

        // Missing MRSIGNER required attributes
        let result: Result<TrustedMeasurementSet, _> = serde_json::from_str(
            r#"{
            "v0": {
                "consensus": {
                    "MRSIGNER": "8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3",
                    "product_id": 1
                }
            }
        }"#,
        );
        assert!(result.is_err());

        // Missing MRSIGNER required attributes
        let result: Result<TrustedMeasurementSet, _> = serde_json::from_str(
            r#"{
            "v0": {
                "consensus": {
                    "MRSIGNER": "8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3",
                    "minimum_svn": 3
                }
            }
        }"#,
        );
        assert!(result.is_err());

        // Working with MRSIGNER required attributes
        let result: Result<TrustedMeasurementSet, _> = serde_json::from_str(
            r#"{
            "v0": {
                "consensus": {
                    "MRSIGNER": "8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3",
                    "product_id": 1,
                    "minimum_svn": 3
                }
            }
        }"#,
        );
        assert!(result.is_ok());

        // Misspelled key
        let result: Result<TrustedMeasurementSet, _> = serde_json::from_str(
            r#"{
            "v0": {
                "consensus": {
                    "MRENCLAVE": "8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3",
                    "mitigated_hardening_advisorees": ["FOO", "BAR"]
                }
            }
        }"#,
        );
        assert!(result.is_err());

        // Corrected key
        let result: Result<TrustedMeasurementSet, _> = serde_json::from_str(
            r#"{
            "v0": {
                "consensus": {
                    "MRENCLAVE": "8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3",
                    "mitigated_hardening_advisories": ["FOO", "BAR"]
                }
            }
        }"#,
        );
        assert!(result.is_ok());
    }
}
