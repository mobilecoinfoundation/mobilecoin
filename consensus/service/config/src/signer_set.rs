// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Data types for representing a `SignerSetV2` in a configuration file.
//! We do not deserialize a `SignerSetV2` directly, because it is too hard
//! to maintain by a human operator.
//! See tests below for an example of the file format.

use mc_crypto_keys::{DistinguishedEncoding, Ed25519Public};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{collections::HashMap, fmt, str::FromStr};

/// A helper struct for serializing/deserializing an Ed25519Public key that is
/// PEM-DER-encoded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PemEd25519Public(pub Ed25519Public);

impl FromStr for PemEd25519Public {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pem = pem::parse(s).map_err(|e| format!("Failed to parse PEM: {}", e))?;
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
        write!(f, "{}", pem::encode(&pem).replace('\r', ""))
    }
}

impl From<Ed25519Public> for PemEd25519Public {
    fn from(public_key: Ed25519Public) -> Self {
        PemEd25519Public(public_key)
    }
}

impl From<PemEd25519Public> for mc_crypto_multisig::SignerContainer<Ed25519Public> {
    fn from(pem_public_key: PemEd25519Public) -> Self {
        pem_public_key.0.into()
    }
}

/// Wrapper around `mc_crypto_multisig::SignerEntity` that allows us specifying
/// singers via a string as opposed to an Ed25519Public key.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "type", content = "identity")]
enum Signer {
    Single(String),
    Multi(SignerSet),
}

/// Wrapper around `mc_crypto_multisig::SignerSet` that allows us specifying
/// singers via a string name
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
struct SignerSet {
    threshold: u32,
    signers: Vec<Signer>,
}

impl SignerSet {
    /// Given a map of signer names to public keys, return a
    /// `mc_crypto_multisig::SignerSet` that represents the same signing
    /// structure that is described by this `SignerSet`.
    pub fn resolve(
        &self,
        signer_identities: &HashMap<String, PemEd25519Public>,
    ) -> Result<mc_crypto_multisig::SignerSetV2<Ed25519Public>, String> {
        let signers = self
            .signers
            .iter()
            .map(|signer| match signer {
                Signer::Single(identity) => signer_identities
                    .get(identity)
                    .ok_or_else(|| format!("Unknown identity: {}", identity))
                    .cloned()
                    .map(Into::into),
                Signer::Multi(signer_set) => signer_set
                    .resolve(signer_identities)
                    .map(|signer_set| signer_set.into()),
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(mc_crypto_multisig::SignerSetV2::new(
            signers,
            self.threshold,
        ))
    }
}

/// Signer set configuration, structured in a way that makes it a bit more sane
/// for humans to review and edit.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct SignerSetConfig {
    /// A map of human readable name to a PEM-encoded public key, representing a
    /// single signing identity.
    #[serde_as(as = "HashMap<DisplayFromStr, DisplayFromStr>")]
    signer_identities: HashMap<String, PemEd25519Public>,

    /// Signer set configuration.
    signer_set: SignerSet,
}

impl TryFrom<&SignerSetConfig> for mc_crypto_multisig::SignerSetV2<Ed25519Public> {
    type Error = String;

    fn try_from(signer_set_config: &SignerSetConfig) -> Result<Self, Self::Error> {
        signer_set_config
            .signer_set
            .resolve(&signer_set_config.signer_identities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_happy_flow() {
        // Keys randomly generated using `openssl genpkey -algorithm ED25519 | openssl
        // pkey -pubout`
        let key_mobilecoin = PemEd25519Public::from_str("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n").unwrap().0;
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
        let key_lp3a = PemEd25519Public::from_str(
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAoqh+PBcDGtLCbVNiNV8F3k/FdNw9xq6ql8x/54qXnpA=\n-----END PUBLIC KEY-----\n",
        )
        .unwrap()
        .0;
        let key_lp3b = PemEd25519Public::from_str(
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEArQ2apgrrQili3wfZ+SAABnq69CU2ZT1kBT12HMF4fTo=\n-----END PUBLIC KEY-----\n",
        )
        .unwrap()
        .0;
        let key_some_org = PemEd25519Public::from_str(
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAnpD/7uFovy/ABkoM13Pz/wvQ1yu2WL9yzEjjNkNWuBc=\n-----END PUBLIC KEY-----\n",
        )
        .unwrap()
        .0;

        let valid_json = r#"
        {
            "signer_identities": {
              "MobileCoin": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n",
              "LP-1": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAf2gGDJ2c18AJtpYg7C3CpFaFJ8Y6ytVDweKHkmitu2Q=\n-----END PUBLIC KEY-----\n",
              "LP-2": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAeUw6FyG1H4ZXAkzTJnyW/fY7eDHzjuztcWnoMOtx+cU=\n-----END PUBLIC KEY-----\n",
              "LP-3A": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAoqh+PBcDGtLCbVNiNV8F3k/FdNw9xq6ql8x/54qXnpA=\n-----END PUBLIC KEY-----\n",
              "LP-3B": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEArQ2apgrrQili3wfZ+SAABnq69CU2ZT1kBT12HMF4fTo=\n-----END PUBLIC KEY-----\n",
              "SomeOrg": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAnpD/7uFovy/ABkoM13Pz/wvQ1yu2WL9yzEjjNkNWuBc=\n-----END PUBLIC KEY-----\n"
            },
            "signer_set": {
              "threshold": 3,
              "signers": [
                {
                  "type": "Single",
                  "identity": "MobileCoin"
                },
                {
                  "type": "Single",
                  "identity": "SomeOrg"
                },
                {
                  "type": "Multi",
                  "identity": {
                    "threshold": 2,
                    "signers": [
                      {
                        "type": "Single",
                        "identity": "LP-1"
                      },
                      {
                        "type": "Single",
                        "identity": "LP-2"
                      },
                      {
                        "type": "Multi",
                        "identity": {
                          "threshold": 2,
                          "signers": [
                             {
                              "type": "Single",
                              "identity": "LP-3A"
                             },
                             {
                              "type": "Single",
                              "identity": "LP-3B"
                             },
                             {
                              "type": "Single",
                              "identity": "MobileCoin"
                             }
                         ]
                        }
                      }
                    ]
                  }
                }
              ]
            }
          }
        "#;

        let signer_set_config: SignerSetConfig = serde_json::from_str(valid_json).unwrap();

        let signer_set: mc_crypto_multisig::SignerSetV2<Ed25519Public> =
            (&signer_set_config).try_into().unwrap();

        let expected_signer_set = mc_crypto_multisig::SignerSetV2::new(
            vec![
                key_mobilecoin.into(),
                key_some_org.into(),
                mc_crypto_multisig::SignerSetV2::new(
                    vec![
                        key_lp1.into(),
                        key_lp2.into(),
                        mc_crypto_multisig::SignerSetV2::new(
                            vec![key_lp3a.into(), key_lp3b.into(), key_mobilecoin.into()],
                            2,
                        )
                        .into(),
                    ],
                    2,
                )
                .into(),
            ],
            3,
        );

        assert_eq!(signer_set, expected_signer_set);
    }

    #[test]
    fn unknown_identity_fails_to_parse() {
        let invalid_config_json = r#"
        {
            "signer_identities": {
              "MobileCoin": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n"
            },
            "signer_set": {
              "threshold": 3,
              "signers": [
                {
                  "type": "Single",
                  "identity": "Nope"
                }
              ]
            }
          }
        "#;

        let signer_set_config: SignerSetConfig = serde_json::from_str(invalid_config_json).unwrap();
        let signer_set: Result<mc_crypto_multisig::SignerSetV2<_>, _> =
            (&signer_set_config).try_into();

        assert_eq!(signer_set, Err("Unknown identity: Nope".into()));
    }

    #[test]
    fn invalid_pem_fails_to_parse() {
        // This PEM is missing a dash
        let invalid_config_json = r#"
        {
            "signer_identities": {
              "MobileCoin": "----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl3XVo/DeiTjHn8dYQuEtBjQrEWNQSKpfzw3X9dewSVY=\n-----END PUBLIC KEY-----\n"
            },
            "signer_set": {
              "threshold": 3,
              "signers": [
                {
                  "type": "Single",
                  "identity": "MobileCoin"
                }
              ]
            }
          }
        "#;

        let err = serde_json::from_str::<SignerSetConfig>(invalid_config_json).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Failed to parse PEM: malformedframing at line 4 column 145"
        );
    }
}
