// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Configuration for the key range validator.

use crate::ParseError;
use hex::ToHex;
use mc_blockchain_types::BlockIndex;
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Public};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    ops::RangeInclusive,
    path::{Path, PathBuf},
};

/// Container for keys with a range of block indexes that are valid per key.
pub type KeyValidityMap = HashMap<Ed25519Public, Vec<RangeInclusive<BlockIndex>>>;

const PUBLIC_KEY_TAG: &str = "PUBLIC KEY";

/// Container for key validity configs.
/// Supports parsing a `metadata-signers.toml` as specified in [MCIP #43](https://github.com/mobilecoinfoundation/mcips/pull/43).
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub struct Config {
    /// The key validity ranges.
    #[serde(alias = "node")] // alias for parsing
    pub configs: Vec<KeyValidity>,

    /// Optional base path for parsing relative PEM file paths.
    #[serde(skip)]
    pub base_path: Option<PathBuf>,
}

impl Config {
    /// Load the config as TOML or JSON from the given file path.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ParseError> {
        let path = path.as_ref();
        let bytes = fs::read(path)?;
        if let Ok(mut config) = serde_json::from_slice(&bytes): Result<Self, _> {
            config.base_path = path.parent().map(Into::into);
            Ok(config)
        } else if let Ok(mut config) = toml::from_slice(&bytes): Result<Self, _> {
            config.base_path = path.parent().map(Into::into);
            Ok(config)
        } else {
            Err(ParseError::UnsuportedFileFormat(path.to_string_lossy().into_owned()))
        }
    }

    /// Get a [KeyValidityMap] from this config.
    pub fn to_validity_map(&self) -> Result<KeyValidityMap, ParseError> {
        let mut map = KeyValidityMap::new();
        for config in &self.configs {
            let key = parse_pem_or_hex(&config.pub_key, self.base_path.clone())?;
            map.entry(key).or_default().push(config.to_range());
        }
        Ok(map)
    }
}

/// A declaration that a public key is valid for a specified range of block
/// indexes.
#[derive(Clone, Debug, Deserialize, Ord, PartialOrd, Serialize)]
pub struct KeyValidity {
    /// The pub key, as a PEM file path or 64 hexadecimal characters.
    /// File paths are parsed relative to the config file.
    #[serde(alias = "message_signing_pub_key")] // alias for parsing
    pub pub_key: String,
    /// The first block index that used this key.
    pub first_block_index: BlockIndex,
    /// The last block index that used this key. Can be `None` for active keys.
    pub last_block_index: Option<BlockIndex>,
}

impl KeyValidity {
    /// Instantiate an instance with the given serialized value and index range.
    pub fn new(
        pub_key: String,
        first_block_index: BlockIndex,
        // Allows passing `N`, `Some(N)` or `None`
        last_block_index: impl Into<Option<BlockIndex>>,
    ) -> Self {
        Self {
            pub_key,
            first_block_index,
            last_block_index: last_block_index.into(),
        }
    }

    /// Instantiate an instance with the given pub key and index range.
    pub fn with_key(
        key: Ed25519Public,
        first_block_index: BlockIndex,
        // Allows passing `N`, `Some(N)` or `None`
        last_block_index: impl Into<Option<BlockIndex>>,
    ) -> Self {
        Self::new(key.encode_hex(), first_block_index, last_block_index)
    }

    /// Get a range of indexes from this config.
    pub fn to_range(&self) -> RangeInclusive<BlockIndex> {
        self.first_block_index..=self.last_block_index.unwrap_or(BlockIndex::MAX)
    }
}

impl PartialEq for KeyValidity {
    fn eq(&self, other: &Self) -> bool {
        self.first_block_index == other.first_block_index
            && self.last_block_index == other.last_block_index
            && self.pub_key.trim() == other.pub_key.trim()
    }
}
impl Eq for KeyValidity {}

/// A helper method for deserializing an Ed25519Public from a PEM string, PEM
/// file path, or hexadecimal string.
fn parse_pem_or_hex(
    value: &str,
    base_path: impl Into<Option<PathBuf>>,
) -> Result<Ed25519Public, ParseError> {
    let value = value.trim();

    let base_path = base_path.into().or_else(|| std::env::current_dir().ok());
    let path = if let Some(base) = base_path {
        base.join(&value)
    } else {
        value.into()
    };

    Ok(if path.exists() {
        let pem = pem::parse(fs::read(path)?)?;
        if pem.tag == PUBLIC_KEY_TAG {
            Ed25519Public::try_from_der(&pem.contents)?
        } else {
            Err(ParseError::InvalidPemTag(pem.tag))?
        }
    } else if let Ok(pem) = pem::parse(value) {
        if pem.tag == PUBLIC_KEY_TAG {
            Ed25519Public::try_from_der(&pem.contents)?
        } else {
            Err(ParseError::InvalidPemTag(pem.tag))?
        }
    } else if value.len() == 64 {
        Ed25519Public::try_from(hex::decode(value)?)?
    } else {
        Err(ParseError::InvalidPubKeyValue(value.to_owned()))?
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    static INPUT_TOML: &str = r#"
        # Key A is always valid.
        [[node]]
        pub_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        first_block_index = 0

        # Key B is only valid for the first 10 blocks.
        [[node]]
        pub_key = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        first_block_index = 0
        last_block_index = 10

        # Key C is valid for all blocks except 11..=19
        [[node]]
        pub_key = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        first_block_index = 0
        last_block_index = 10

        [[node]]
        # Can also use `message_signing_pub_key`
        message_signing_pub_key = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        first_block_index = 20
    "#;

    static INPUT_JSON: &str = r#"
    {
        "node": [
            {
                "pub_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "first_block_index": 0
            },
            {
                "pub_key": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "first_block_index": 0,
                "last_block_index": 10
            },
            {
                "pub_key": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "first_block_index": 0,
                "last_block_index": 10
            },
            {
                "message_signing_pub_key": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "first_block_index": 20
            }
        ]
    }
    "#;

    /// PEM encoding of the Ed25519Public key:
    ///     0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    const KEY_A_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=\n-----END PUBLIC KEY-----";

    /// PEM encoding of the Ed25519Public key:
    ///     0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    const KEY_B_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAu7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=\n-----END PUBLIC KEY-----";

    /// PEM encoding of the Ed25519Public key:
    ///     0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    const KEY_C_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw=\n-----END PUBLIC KEY-----";

    fn make_pub_key(val: u8) -> Ed25519Public {
        Ed25519Public::try_from(vec![val; 32]).unwrap()
    }

    #[test]
    fn load_toml_from_path() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("metadata-signers.toml");
        fs::write(&path, INPUT_TOML).unwrap();

        let key_a = make_pub_key(0xAA);
        let key_b = make_pub_key(0xBB);
        let key_c = make_pub_key(0xCC);

        // Parse the TOML.
        let cfg = Config::load(&path).unwrap();
        assert_eq!(
            cfg,
            Config {
                configs: vec![
                    KeyValidity::with_key(key_a, 0, None),
                    KeyValidity::with_key(key_b, 0, 10),
                    KeyValidity::with_key(key_c, 0, 10),
                    KeyValidity::with_key(key_c, 20, None),
                ],
                base_path: path.parent().map(Into::into),
            }
        );

        // Verify the validity map.
        assert_eq!(
            cfg.to_validity_map().unwrap(),
            [
                (key_a, vec![0..=BlockIndex::MAX]),
                (key_b, vec![0..=10]),
                (key_c, vec![0..=10, 20..=BlockIndex::MAX]),
            ]
            .into()
        );
    }

    #[test]
    fn load_json_from_path() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("metadata-signers.json");
        fs::write(&path, INPUT_JSON).unwrap();

        let key_a = make_pub_key(0xAA);
        let key_b = make_pub_key(0xBB);
        let key_c = make_pub_key(0xCC);

        // Parse the JSON.
        let cfg = Config::load(&path).unwrap();
        assert_eq!(
            cfg,
            Config {
                configs: vec![
                    KeyValidity::with_key(key_a, 0, None),
                    KeyValidity::with_key(key_b, 0, 10),
                    KeyValidity::with_key(key_c, 0, 10),
                    KeyValidity::with_key(key_c, 20, None),
                ],
                base_path: path.parent().map(Into::into),
            }
        );

        // Verify the validity map.
        assert_eq!(
            cfg.to_validity_map().unwrap(),
            [
                (key_a, vec![0..=BlockIndex::MAX]),
                (key_b, vec![0..=10]),
                (key_c, vec![0..=10, 20..=BlockIndex::MAX]),
            ]
            .into()
        );
    }

    #[test]
    fn toml_with_pems() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let subdir = TempDir::new_in(dir).unwrap();

        let config_path = dir.join("metadata-signers.toml");
        let abs_path = subdir.path().join("test_abs.pem");
        let rel_path = "test_rel.pem";

        // Write key A in the child directory.
        fs::write(&abs_path, KEY_A_PEM).unwrap();

        // Write key B at rel_path next to the TOML file.
        fs::write(dir.join(rel_path), KEY_B_PEM).unwrap();

        // Write the TOML, with key C as inline PEM.
        let toml = format!(
            r#"
            [[node]]
            pub_key = "{}"
            first_block_index = 0

            [[node]]
            pub_key = "{}"
            first_block_index = 0
            last_block_index = 10

            [[node]]
            message_signing_pub_key = """{}"""
            first_block_index = 20
        "#,
            abs_path.display(),
            rel_path,
            KEY_C_PEM,
        );
        fs::write(&config_path, toml).unwrap();

        // Parse the TOML.
        let config = Config::load(&config_path).unwrap();

        assert_eq!(
            config,
            Config {
                configs: vec![
                    KeyValidity::new(abs_path.display().to_string(), 0, None),
                    KeyValidity::new(rel_path.to_string(), 0, 10),
                    KeyValidity::new(KEY_C_PEM.to_string(), 20, None),
                ],
                base_path: config_path.parent().map(Into::into),
            }
        );

        // Verify the validity map.
        assert_eq!(
            config.to_validity_map().unwrap(),
            [
                (make_pub_key(0xAA), vec![0..=BlockIndex::MAX]),
                (make_pub_key(0xBB), vec![0..=10]),
                (make_pub_key(0xCC), vec![20..=BlockIndex::MAX])
            ]
            .into()
        );
    }

    #[test]
    fn json_with_pems() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path();
        let subdir = TempDir::new_in(dir).unwrap();

        let config_path = dir.join("metadata-signers.json");
        let abs_path = subdir.path().join("test_abs.pem");
        let rel_path = "test_rel.pem";

        // Write key A in the child directory.
        fs::write(&abs_path, KEY_A_PEM).unwrap();

        // Write key B at rel_path next to the JSON file.
        fs::write(dir.join(rel_path), KEY_B_PEM).unwrap();

        // Write the JSON, with key C as inline PEM.
        let json = serde_json::json!({
            "node": [
                {
                    "pub_key": abs_path.to_str(),
                    "first_block_index": 0,
                },
                {
                    "pub_key": rel_path,
                    "first_block_index": 0,
                    "last_block_index": 10,
                },
                {
                    "message_signing_pub_key": KEY_C_PEM,
                    "first_block_index": 20,
                },
            ]
        })
        .to_string();
        fs::write(&config_path, json).unwrap();

        // Parse the JSON.
        let config = Config::load(&config_path).unwrap();

        assert_eq!(
            config,
            Config {
                configs: vec![
                    KeyValidity::new(abs_path.display().to_string(), 0, None),
                    KeyValidity::new(rel_path.to_string(), 0, 10),
                    KeyValidity::new(KEY_C_PEM.to_string(), 20, None),
                ],
                base_path: config_path.parent().map(Into::into),
            }
        );

        // Verify the validity map.
        assert_eq!(
            config.to_validity_map().unwrap(),
            [
                (make_pub_key(0xAA), vec![0..=BlockIndex::MAX]),
                (make_pub_key(0xBB), vec![0..=10]),
                (make_pub_key(0xCC), vec![20..=BlockIndex::MAX])
            ]
            .into()
        );
    }
}
