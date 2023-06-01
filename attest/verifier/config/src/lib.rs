// Copyright (c) 2018-2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs)]

extern crate alloc;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use displaydoc::Display;
use serde::{Deserialize, Serialize};

/// Trusted measurement for MRENCLAVE values.
///
/// The MRENCLAVE is the hash over the enclave pages loaded into the SGX
/// protected memory. Whenever the contents of the signed enclave have changed,
/// its MRENCLAVE will change.
///
/// This measurement is also referred to as "Strict Enclave Modification
/// Policy".
///
/// Supports de/serialization to/from JSON. Unknown JSON fields are flagged as
/// an error.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedMrEnclaveMeasurement {
    /// The MRENCLAVE measurement
    ///
    /// For JSON this will be hex-encoded bytes.
    #[serde(with = "hex", rename = "MRENCLAVE")]
    mr_enclave: [u8; 32],
    /// The list of hardening advisories that are known to be mitigated in
    /// software at this enclave revision.
    #[serde(default)]
    mitigated_hardening_advisories: Vec<String>,
}

impl TrustedMrEnclaveMeasurement {
    /// Create a new instance.
    pub fn new<'a, E, I>(mr_enclave: &[u8; 32], advisories: I) -> Self
    where
        I: IntoIterator<Item = &'a E>,
        E: ToString + 'a + ?Sized,
    {
        Self {
            mr_enclave: *mr_enclave,
            mitigated_hardening_advisories: advisories
                .into_iter()
                .map(ToString::to_string)
                .collect(),
        }
    }
}

impl TrustedMrSignerMeasurement {
    /// Create a new instance.
    pub fn new<'a, E, I>(
        mr_signer: &[u8; 32],
        product_id: u16,
        minimum_svn: u16,
        advisories: I,
    ) -> Self
    where
        I: IntoIterator<Item = &'a E>,
        E: ToString + 'a + ?Sized,
    {
        Self {
            mr_signer: *mr_signer,
            product_id,
            minimum_svn,
            mitigated_hardening_advisories: advisories
                .into_iter()
                .map(ToString::to_string)
                .collect(),
        }
    }
}

/// Trusted measurement for MRSIGNER values.
///
/// The MRSIGNER is the hash of the public portion of the key used to sign the
/// enclave. The product ID is used to distinguish different enclaves signed
/// with the same key. Using the MRSIGNER + product ID allows for the same
/// measurements to be used for updates to the enclave. A security version
/// number (SVN) is also used to distinguish different versions of the same
/// enclave.
///
/// This measurement is also referred to as "Security Enclave Modification
/// Policy".
///
/// Supports de/serialization to/from JSON. Unknown JSON fields are flagged as
/// an error.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedMrSignerMeasurement {
    /// The MRSIGNER measurement
    ///
    /// For JSON this will be hex-encoded bytes.
    #[serde(with = "hex", rename = "MRSIGNER")]
    mr_signer: [u8; 32],
    /// The product ID that this verifier checks for.
    product_id: u16,
    /// The minimum security version number that is considered valid by this
    /// verifier.
    minimum_svn: u16,
    /// The list of hardening advisories that are known to be mitigated in
    /// software at this enclave revision.
    #[serde(default)]
    mitigated_hardening_advisories: Vec<String>,
}

/// Trusted measurement for an enclave.
///
/// Either a MRENCLAVE or MRSIGNER type, and the type is inferred by
///
/// Supports de/serialization to/from JSON.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum TrustedMeasurement {
    /// MRENCLAVE measurement type
    MrEnclave(TrustedMrEnclaveMeasurement),
    /// MRSIGNER measurement type
    MrSigner(TrustedMrSignerMeasurement),
}

impl From<TrustedMrEnclaveMeasurement> for TrustedMeasurement {
    fn from(mr_enclave: TrustedMrEnclaveMeasurement) -> Self {
        Self::MrEnclave(mr_enclave)
    }
}

impl From<TrustedMrSignerMeasurement> for TrustedMeasurement {
    fn from(mr_signer: TrustedMrSignerMeasurement) -> Self {
        Self::MrSigner(mr_signer)
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
    table: BTreeMap<String, BTreeMap<String, TrustedMeasurement>>,
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
    /// Get the measurements for a given enclave name.
    pub fn measurements(
        &self,
        enclave_name: impl AsRef<str>,
    ) -> Result<Vec<TrustedMeasurement>, Error> {
        let enclave_name = enclave_name.as_ref();
        let mut measurements = vec![];

        for row in self.table.values() {
            if let Some(measurement) = row.get(enclave_name) {
                measurements.push(measurement.clone());
            }
        }

        match measurements.len() {
            0 => Err(Error::NoMeasurementsFound(enclave_name.to_string())),
            _ => Ok(measurements),
        }
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
        let expected_consensus = TrustedMeasurement::from(TrustedMrEnclaveMeasurement::new(
            &hex!("207c9705bf640fdb960034595433ee1ff914f9154fbe4bc7fc8a97e912961e5c"),
            ["INTEL-SA-00334", "INTEL-SA-00615"],
        ));
        assert_eq!(v3_consensus, &expected_consensus);
        let v3_fog_view = v3.get("fog-view").unwrap();
        let expected_fog_view = TrustedMeasurement::from(TrustedMrEnclaveMeasurement::new(
            &hex!("dca7521ce4564cc2e54e1637e533ea9d1901c2adcbab0e7a41055e719fb0ff9d"),
            ["INTEL-SA-00334", "INTEL-SA-00615"],
        ));
        assert_eq!(v3_fog_view, &expected_fog_view);

        let v4 = tms.table.get("v4").unwrap();
        assert_eq!(v4.len(), 4);
        let v4_consensus = v4.get("consensus").unwrap();
        let expected_consensus = TrustedMeasurement::from(TrustedMrEnclaveMeasurement::new(
            &hex!("e35bc15ee92775029a60a715dca05d310ad40993f56ad43bca7e649ccc9021b5"),
            ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"],
        ));
        assert_eq!(v4_consensus, &expected_consensus);

        let v4_fog_view = v4.get("fog-view").unwrap();
        let expected_fog_view = TrustedMeasurement::from(TrustedMrEnclaveMeasurement::new(
            &hex!("8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3"),
            ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"],
        ));
        assert_eq!(v4_fog_view, &expected_fog_view);

        assert_eq!(
            tms.measurements("consensus").unwrap(),
            vec![v3_consensus.clone(), v4_consensus.clone()]
        );
        assert_eq!(
            tms.measurements("fog-view").unwrap(),
            vec![v3_fog_view.clone(), v4_fog_view.clone()]
        );

        assert!(matches!(
            tms.measurements("impostor"),
            Err(Error::NoMeasurementsFound(_))
        ));
    }

    const TEST_DATA2: &str = r#"{
    "v3": {
       "consensus": {
           "MRENCLAVE": "207c9705bf640fdb960034595433ee1ff914f9154fbe4bc7fc8a97e912961e5c",
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"]
       },
       "fog-ingest": {
           "MRSIGNER": "2c1a561c4ab64cbc04bfa445cdf7bed9b2ad6f6b04d38d3137f3622b29fdb30e",
           "product_id": 1,
           "minimum_svn": 4,
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"]
       },
       "fog-ledger": {
           "MRSIGNER": "2c1a561c4ab64cbc04bfa445cdf7bed9b2ad6f6b04d38d3137f3622b29fdb30e",
           "product_id": 2,
           "minimum_svn": 4,
           "mitigated_hardening_advisories": ["INTEL-SA-00334", "INTEL-SA-00615"]
       },
       "fog-view": {
           "MRSIGNER": "2c1a561c4ab64cbc04bfa445cdf7bed9b2ad6f6b04d38d3137f3622b29fdb30e",
           "product_id": 3,
           "minimum_svn": 4,
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
    fn test_loading2() {
        let tms: TrustedMeasurementSet = serde_json::from_str(TEST_DATA2).unwrap();

        assert_eq!(tms.table.len(), 2);
        let v3 = tms.table.get("v3").unwrap();
        assert_eq!(v3.len(), 4);
        let v3_consensus = v3.get("consensus").unwrap();
        let expected_consensus = TrustedMeasurement::from(TrustedMrEnclaveMeasurement::new(
            &hex!("207c9705bf640fdb960034595433ee1ff914f9154fbe4bc7fc8a97e912961e5c"),
            ["INTEL-SA-00334", "INTEL-SA-00615"],
        ));
        assert_eq!(v3_consensus, &expected_consensus);

        let v3_fog_view = v3.get("fog-view").unwrap();
        let expected_fog_view = TrustedMeasurement::from(TrustedMrSignerMeasurement::new(
            &hex!("2c1a561c4ab64cbc04bfa445cdf7bed9b2ad6f6b04d38d3137f3622b29fdb30e"),
            3,
            4,
            ["INTEL-SA-00334", "INTEL-SA-00615"],
        ));
        assert_eq!(v3_fog_view, &expected_fog_view);

        let v4 = tms.table.get("v4").unwrap();
        assert_eq!(v4.len(), 4);
        let v4_consensus = v4.get("consensus").unwrap();
        let expected_consensus = TrustedMeasurement::from(TrustedMrEnclaveMeasurement::new(
            &hex!("e35bc15ee92775029a60a715dca05d310ad40993f56ad43bca7e649ccc9021b5"),
            ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"],
        ));
        assert_eq!(v4_consensus, &expected_consensus);

        let v4_fog_view = v4.get("fog-view").unwrap();
        let expected_fog_view = TrustedMeasurement::from(TrustedMrEnclaveMeasurement::new(
            &hex!("8c80a2b95a549fa8d928dd0f0771be4f3d774408c0f98bf670b1a2c390706bf3"),
            ["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"],
        ));
        assert_eq!(v4_fog_view, &expected_fog_view);

        assert_eq!(
            tms.measurements("consensus").unwrap(),
            vec![v3_consensus.clone(), v4_consensus.clone()]
        );
        assert_eq!(
            tms.measurements("fog-view").unwrap(),
            vec![v3_fog_view.clone(), v4_fog_view.clone()]
        );

        assert!(matches!(
            tms.measurements("impostor"),
            Err(Error::NoMeasurementsFound(_))
        ));
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
