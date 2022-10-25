// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Data types for representing a map of human readable name -> SignerSet in a
//! JSON configuration file.

// TODO
// Multi -> MultiSig
// Get rid of Option<> in map

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
    ValidationFailed,

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
    Multi {
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
        identity_map: Option<&SignerIdentityMap>,
    ) -> Result<SignerSet<Ed25519Public>, Error> {
        let signer_set = self.try_into_signer_set_helper(identity_map, 0)?;
        if !signer_set.is_valid() {
            return Err(Error::ValidationFailed);
        }
        Ok(signer_set)
    }

    fn try_into_signer_set_helper(
        &self,
        // TODO shouldn;t be Option<>
        identity_map: Option<&SignerIdentityMap>,
        nesting_level: usize,
    ) -> Result<SignerSet<Ed25519Public>, Error> {
        if nesting_level > MAX_NESTING_DEPTH {
            return Err(Error::NestingTooDeep);
        }

        match self {
            Self::Single { pub_key } => Ok(SignerSet::new(vec![pub_key.0], 1)),

            Self::Multi { threshold, signers } => {
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
                    .ok_or_else(|| Error::UnknownSignerIdentity(name.clone()))?
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
    use mc_crypto_keys::{Ed25519Pair, Ed25519Public};
    use mc_util_from_random::FromRandom;
    use mc_util_test_helper::get_seeded_rng;

    #[test]
    fn test_happy_path() {
        let mut rng = get_seeded_rng();

        let lp1 = Ed25519Pair::from_random(&mut rng).public_key();
        let lp2 = Ed25519Pair::from_random(&mut rng).public_key();
        let rsv1 = Ed25519Pair::from_random(&mut rng).public_key();
        let rsv2 = Ed25519Pair::from_random(&mut rng).public_key();

        let map = SignerIdentityMap::from_iter(vec![
            (
                "LP1".into(),
                SignerIdentity::Single {
                    pub_key: PemEd25519Public(lp1),
                },
            ),
            (
                "LP2".into(),
                SignerIdentity::Single {
                    pub_key: PemEd25519Public(lp2),
                },
            ),
            (
                "RSV1".into(),
                SignerIdentity::Single {
                    pub_key: PemEd25519Public(rsv1),
                },
            ),
            (
                "RSV2".into(),
                SignerIdentity::Single {
                    pub_key: PemEd25519Public(rsv2),
                },
            ),
            (
                "LPs".into(),
                SignerIdentity::Multi {
                    threshold: 1,
                    signers: vec![
                        SignerIdentity::Identity { name: "LP1".into() },
                        SignerIdentity::Identity { name: "LP2".into() },
                    ],
                },
            ),
            (
                "RSV".into(),
                SignerIdentity::Multi {
                    threshold: 2,
                    signers: vec![
                        SignerIdentity::Identity {
                            name: "RSV1".into(),
                        },
                        SignerIdentity::Identity {
                            name: "RSV2".into(),
                        },
                    ],
                },
            ),
            (
                "LPs_and_RSV".into(),
                SignerIdentity::Multi {
                    threshold: 2,
                    signers: vec![
                        SignerIdentity::Identity { name: "LPs".into() },
                        SignerIdentity::Identity { name: "RSV".into() },
                    ],
                },
            ),
        ]);

        let lps_and_rsv = SignerIdentity::Multi {
            threshold: 2,
            signers: vec![
                SignerIdentity::Identity { name: "LPs".into() },
                SignerIdentity::Identity { name: "RSV".into() },
            ],
        }
        .try_into_signer_set(Some(&map))
        .unwrap();
        assert_eq!(
            lps_and_rsv,
            SignerSet::new_with_multi(
                vec![],
                vec![
                    SignerSet::new(vec![lp1, lp2], 1),
                    SignerSet::new(vec![rsv1, rsv2], 2),
                ],
                2,
            )
        );
        assert_eq!(
            map.get("LPs_and_RSV")
                .unwrap()
                .try_into_signer_set(Some(&map))
                .unwrap(),
            lps_and_rsv
        );

        let signer_set = SignerIdentity::Multi {
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
        .try_into_signer_set(Some(&map))
        .unwrap();

        assert_eq!(
            signer_set,
            SignerSet::new_with_multi(
                vec![rsv1, Ed25519Public::default()],
                vec![lps_and_rsv, SignerSet::new(vec![lp1, lp2], 1)],
                3,
            )
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
            .try_into_signer_set(Some(&map)),
            Err(Error::UnknownSignerIdentity(name)) if name == "NotLP"
        ));

        // Passing None should return an error.
        assert!(matches!(
            SignerIdentity::Identity { name: "LP".into() }.try_into_signer_set(None),
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
                "Multi1".into(),
                SignerIdentity::Identity {
                    name: "Multi1".into(),
                },
            ),
            (
                "Multi2".into(),
                SignerIdentity::Multi {
                    threshold: 1,
                    signers: vec![SignerIdentity::Identity {
                        name: "Multi1".into(),
                    }],
                },
            ),
        ]);

        assert_eq!(
            SignerIdentity::Identity {
                name: "Multi1".into()
            }
            .try_into_signer_set(Some(&map)),
            Err(Error::NestingTooDeep),
        );

        assert_eq!(
            SignerIdentity::Identity {
                name: "Multi2".into()
            }
            .try_into_signer_set(Some(&map)),
            Err(Error::NestingTooDeep)
        );

        assert_eq!(
            SignerIdentity::Multi {
                threshold: 1,
                signers: vec![SignerIdentity::Identity {
                    name: "Multi2".into()
                }]
            }
            .try_into_signer_set(Some(&map)),
            Err(Error::NestingTooDeep)
        );
    }
}
