// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Data types for representing a map of human readable name -> SignerSet in a
//! JSON configuration file.

use displaydoc::Display;
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Public};
use mc_crypto_multisig::SignerSet;
use pem::{EncodeConfig, LineEnding};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{collections::HashMap, fmt, str::FromStr};

/// Maximum nesting depth for the SignerSetMap.
pub const MAX_NESTING_DEPTH: usize = 32;

/// A helper struct for serializing/deserializing an Ed25519Public key that is
/// PEM-DER-encoded.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PemEd25519Public(Ed25519Public);

impl FromStr for PemEd25519Public {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pem = pem::parse(s).map_err(|e| format!("Failed to parse PEM {:?}: {}", s, e))?;
        let public_key = Ed25519Public::try_from_der(&pem.contents)
            .map_err(|e| format!("Failed to parse public key {:?}: {}", s, e))?;
        Ok(PemEd25519Public(public_key))
    }
}

impl fmt::Display for PemEd25519Public {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let pem = pem::Pem {
            tag: "PUBLIC KEY".to_string(),
            contents: self.0.to_der().to_vec(),
        };
        let encoding = EncodeConfig {
            line_ending: LineEnding::LF,
        };
        write!(f, "{}", pem::encode_config(&pem, encoding))
    }
}

/// Error data type for SignerIdentity stuff.
#[derive(Clone, Debug, Deserialize, Display, Eq, PartialEq, Serialize)]
pub enum Error {
    /// SignerSet validation failed
    SignerSetValidationFailed,

    /// Unknown signer identity "{0}"
    UnknownSignerIdentity(String),

    /// Signer set nesting depth exceeded
    NestingTooDeep,
}

/// The types of signer identities we support.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "type")]
pub enum SignerIdentity {
    /// A single signer, represented by a PEM-encoded Ed25519 public key.
    Single {
        /// The PEM-encoded Ed25519 public key, identifying the signer.
        #[serde_as(as = "DisplayFromStr")]
        pub_key: PemEd25519Public,
    },

    /// A multisig signer.
    MultiSig {
        /// The minimum number of signatures required.
        threshold: u32,

        /// List of potential signers.
        signers: Vec<SignerIdentity>,
    },

    /// A signer referred to by their human readable name.
    Identity {
        /// The signer identity name, referring to a signer in a
        /// SignerIdentityMap.
        name: String,
    },
}
impl SignerIdentity {
    /// Convert this identity into a SignerSet.
    pub fn try_into_signer_set(
        &self,
        identity_map: &SignerIdentityMap,
    ) -> Result<SignerSet<Ed25519Public>, Error> {
        let signer_set = self.try_into_signer_set_helper(identity_map, 0)?;
        if !signer_set.is_valid() {
            return Err(Error::SignerSetValidationFailed);
        }
        Ok(signer_set)
    }

    fn try_into_signer_set_helper(
        &self,
        identity_map: &SignerIdentityMap,
        nesting_level: usize,
    ) -> Result<SignerSet<Ed25519Public>, Error> {
        if nesting_level > MAX_NESTING_DEPTH {
            return Err(Error::NestingTooDeep);
        }

        match self {
            Self::Single { pub_key } => Ok(SignerSet::new(vec![pub_key.0], 1)),

            Self::MultiSig { threshold, signers } => {
                let mut individual_signers = Vec::new();
                let mut multi_signers = Vec::new();

                for signer in signers {
                    let signer_set =
                        signer.try_into_signer_set_helper(identity_map, nesting_level + 1)?;

                    // If the signer set contains a single signer, we can add it to the list of
                    // individual signers. Otherwise, we add it to the list of
                    // multi-signers.
                    if signer_set.individual_signers().len() == 1
                        && signer_set.multi_signers().is_empty()
                    {
                        individual_signers.push(signer_set.individual_signers()[0]);
                    } else {
                        multi_signers.push(signer_set);
                    }
                }

                Ok(SignerSet::new_with_multi(
                    individual_signers,
                    multi_signers,
                    *threshold,
                ))
            }

            Self::Identity { name } => {
                let identity = identity_map
                    .get(name)
                    .ok_or_else(|| Error::UnknownSignerIdentity(name.clone()))?;
                identity.try_into_signer_set_helper(identity_map, nesting_level + 1)
            }
        }
    }
}

/// A map of human readable name -> SignerIdentity.
pub type SignerIdentityMap = HashMap<String, SignerIdentity>;

#[cfg(test)]
mod tests {
    use super::*;
    use mc_crypto_keys::Ed25519Public;

    #[test]
    fn test_happy_path() {
        // Keys randomly generated using `openssl genpkey -algorithm ED25519 | openssl
        // pkey -pubout`
        let key_lp1 = PemEd25519Public::from_str(
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAf2gGDJ2c18AJtpYg7C3CpFaFJ8Y6ytVDweKHkmitu2Q=\n-----END PUBLIC KEY-----\n",
        )
        .unwrap()
        .0;
        let key_lp2 = PemEd25519Public::from_str(
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAeUw6FyG1H4ZXAkzTJnyW/fY7eDHzjuztcWnoMOtx+cU=\n-----END PUBLIC KEY-----\n",
        )
        .unwrap()
        .0;
        let key_rsv1 = PemEd25519Public::from_str(
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAoqh+PBcDGtLCbVNiNV8F3k/FdNw9xq6ql8x/54qXnpA=\n-----END PUBLIC KEY-----\n",
        )
        .unwrap()
        .0;
        let key_rsv2 = PemEd25519Public::from_str(
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEArQ2apgrrQili3wfZ+SAABnq69CU2ZT1kBT12HMF4fTo=\n-----END PUBLIC KEY-----\n",
        )
        .unwrap()
        .0;

        let valid_json = r#"{
            "LP1": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAf2gGDJ2c18AJtpYg7C3CpFaFJ8Y6ytVDweKHkmitu2Q=\n-----END PUBLIC KEY-----\n"},
            "LP2": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAeUw6FyG1H4ZXAkzTJnyW/fY7eDHzjuztcWnoMOtx+cU=\n-----END PUBLIC KEY-----\n"},
            "RSV1": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAoqh+PBcDGtLCbVNiNV8F3k/FdNw9xq6ql8x/54qXnpA=\n-----END PUBLIC KEY-----\n"},
            "RSV2": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEArQ2apgrrQili3wfZ+SAABnq69CU2ZT1kBT12HMF4fTo=\n-----END PUBLIC KEY-----\n"},

            "LPs": {"type": "MultiSig", "threshold": 1, "signers": [
                {"type": "Identity", "name": "LP1"},
                {"type": "Identity", "name": "LP2"}
            ]},

            "RSV": {"type": "MultiSig", "threshold": 2, "signers": [
                {"type": "Identity", "name": "RSV1"},
                {"type": "Identity", "name": "RSV2"}
            ]},

            "LPs_and_RSV": {"type": "MultiSig", "threshold": 2, "signers": [
                {"type": "Identity", "name": "LPs"},
                {"type": "Identity", "name": "RSV"}
            ]}
        }"#;

        let map: SignerIdentityMap = serde_json::from_str(valid_json).unwrap();

        let lps_and_rsv = SignerIdentity::MultiSig {
            threshold: 2,
            signers: vec![
                SignerIdentity::Identity { name: "LPs".into() },
                SignerIdentity::Identity { name: "RSV".into() },
            ],
        }
        .try_into_signer_set(&map)
        .unwrap();
        assert_eq!(
            lps_and_rsv,
            SignerSet::new_with_multi(
                vec![],
                vec![
                    SignerSet::new(vec![key_lp1, key_lp2], 1),
                    SignerSet::new(vec![key_rsv1, key_rsv2], 2),
                ],
                2,
            )
        );
        assert_eq!(
            map.get("LPs_and_RSV")
                .unwrap()
                .try_into_signer_set(&map)
                .unwrap(),
            lps_and_rsv
        );

        let signer_set = SignerIdentity::MultiSig {
            threshold: 3,
            signers: vec![
                SignerIdentity::Identity {
                    name: "LPs_and_RSV".into(),
                },
                SignerIdentity::Identity { name: "LPs".into() },
                SignerIdentity::Identity {
                    name: "RSV1".into(),
                },
                SignerIdentity::Single {
                    pub_key: PemEd25519Public::default(),
                },
            ],
        }
        .try_into_signer_set(&map)
        .unwrap();

        assert_eq!(
            signer_set,
            SignerSet::new_with_multi(
                vec![key_rsv1, Ed25519Public::default()],
                vec![lps_and_rsv, SignerSet::new(vec![key_lp1, key_lp2], 1)],
                3,
            )
        );
    }

    #[test]
    fn unknown_identity_fails_to_parse() {
        // Note: The identity inside "signers" has lowercase `c` - so we are making sure
        // that identity name comparison is case-sensitive, in addition to
        // testing unknown identities behave as expected.
        let invalid_config_json = r#"
        {
            "MobileCoin": {"type": "Single", "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n"},
            "SomeIdentity": {
              "type": "MultiSig",
              "threshold": 1,
              "signers": [
                {"type": "Identity", "name": "Mobilecoin"}
              ]
            }
          }
        "#;

        let map: SignerIdentityMap = serde_json::from_str(invalid_config_json).unwrap();
        assert_eq!(
            map.get("SomeIdentity").unwrap().try_into_signer_set(&map),
            Err(Error::UnknownSignerIdentity("Mobilecoin".into()))
        );
    }
    #[test]
    fn invalid_pem_fails_to_parse() {
        // This PEM is missing a dash
        let invalid_config_json = r#"
        {
            "MobileCoin": {"type": "Single", "pub_key": "----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n"}
        }
        "#;

        let err = serde_json::from_str::<SignerIdentityMap>(invalid_config_json).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Failed to parse PEM \"----BEGIN PUBLIC KEY-----\\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\\n-----END PUBLIC KEY-----\\n\": malformedframing at line 4 column 9"
        );
    }

    #[test]
    fn threshold_zero_fails_to_parse() {
        let invalid_config_json = r#"
        {
            "SomeIdentity": {
                "type": "MultiSig",
                "threshold": 0,
                "signers": [
                    {
                        "type": "Single",
                        "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n"
                    }
                ]
            }
        }
        "#;

        let map: SignerIdentityMap = serde_json::from_str(invalid_config_json).unwrap();

        assert_eq!(
            map.get("SomeIdentity").unwrap().try_into_signer_set(&map),
            Err(Error::SignerSetValidationFailed)
        );
    }

    #[test]
    fn less_signers_than_threshold_fails_to_parse() {
        let invalid_config_json = r#"
        {
            "SomeIdentity": {
                "type": "MultiSig",
                "threshold": 2,
                "signers": [
                    {
                        "type": "Single",
                        "pub_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n"
                    }
                ]
            }
        }
        "#;

        let map: SignerIdentityMap = serde_json::from_str(invalid_config_json).unwrap();

        assert_eq!(
            map.get("SomeIdentity").unwrap().try_into_signer_set(&map),
            Err(Error::SignerSetValidationFailed)
        );
    }

    #[test]
    fn unknown_identity_returns_error() {
        let map = SignerIdentityMap::from_iter(vec![(
            "LP".into(),
            SignerIdentity::Single {
                pub_key: PemEd25519Public::default(),
            },
        )]);

        // Passing a map that doesn't contain the identity should return an error.
        assert!(matches!(
            SignerIdentity::Identity {
                name: "NotLP".into(),
            }
            .try_into_signer_set(&map),
            Err(Error::UnknownSignerIdentity(name)) if name == "NotLP"
        ));

        // Passing a default map should return an error.
        assert!(matches!(
            SignerIdentity::Identity { name: "LP".into() }.try_into_signer_set(&Default::default()),
            Err(Error::UnknownSignerIdentity(name)) if name == "LP"
        ));
    }

    #[test]
    fn recursion_aborts_safely() {
        let map = SignerIdentityMap::from_iter(vec![
            (
                "LP".into(),
                SignerIdentity::Single {
                    pub_key: PemEd25519Public::default(),
                },
            ),
            (
                "Infinite".into(),
                SignerIdentity::Identity {
                    name: "Infinite".into(),
                },
            ),
            (
                "Multi".into(),
                SignerIdentity::MultiSig {
                    threshold: 1,
                    signers: vec![SignerIdentity::Identity {
                        name: "Infinite".into(),
                    }],
                },
            ),
        ]);

        assert_eq!(
            SignerIdentity::Identity {
                name: "Infinite".into()
            }
            .try_into_signer_set(&map),
            Err(Error::NestingTooDeep),
        );

        assert_eq!(
            SignerIdentity::Identity {
                name: "Multi".into()
            }
            .try_into_signer_set(&map),
            Err(Error::NestingTooDeep)
        );

        assert_eq!(
            SignerIdentity::MultiSig {
                threshold: 1,
                signers: vec![SignerIdentity::Identity {
                    name: "Multi".into()
                }]
            }
            .try_into_signer_set(&map),
            Err(Error::NestingTooDeep)
        );
    }
}
