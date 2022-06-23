// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Configuration for Gnosis safe auditing

use super::{Error, EthAddr};
use mc_transaction_core::TokenId;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use url::Url;

/// Configuration for a token we want to audit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditedToken {
    /// The MobileCoin token id.
    pub token_id: TokenId,

    /// The Ethereum token contract address.
    pub eth_token_contract_addr: EthAddr,

    /// The auxiliary burn contract address (this is the contract that is used
    /// in a Gnosis safe multi-sig withdrawal to record the matching TxOut
    /// public key for the burn transaction on the MobileCoin blockchain).
    pub aux_burn_contract_addr: EthAddr,

    /// The 4 bytes function signature that is used in the multi-sig
    /// burn/withdrawal transaction. This is used as a sanity check.
    pub aux_burn_function_sig: [u8; 4],
}

/// Configuration for a single safe we want to audit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditedSafeConfig {
    /// The safe address.
    pub safe_addr: EthAddr,

    /// The Gnosis safe transaction service API endpoint to sync from.
    pub api_url: Url,

    /// The tokens we want to audit.
    pub tokens: Vec<AuditedToken>,
}

impl AuditedSafeConfig {
    /// Get an audited token by its Ethereum contract address.
    pub fn get_token_by_eth_contract_addr(
        &self,
        eth_contract_addr: &EthAddr,
    ) -> Option<&AuditedToken> {
        self.tokens
            .iter()
            .find(|token| token.eth_token_contract_addr == *eth_contract_addr)
    }
}

/// Configuration for Gnosis safe(s) auditing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GnosisSafeConfig {
    /// The safe(s) we want to audit.
    pub safes: Vec<AuditedSafeConfig>,
}

impl GnosisSafeConfig {
    /// Load configuration data from a toml/json file.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();

        // Read configuration file.
        let data = fs::read_to_string(path)?;

        // Parse configuration file.
        let config: Self = match path.extension().and_then(|ext| ext.to_str()) {
            None => Err(Error::PathExtension),
            Some("toml") => toml::from_str(&data).map_err(Error::from),
            Some("json") => serde_json::from_str(&data).map_err(Error::from),
            Some(ext) => Err(Error::UnrecognizedExtension(ext.to_string())),
        }?;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tempfile::tempdir;

    static INPUT_TOML: &str = r#"
        [[safes]]
        safe_addr = "0x90213de428E9Ce4C77dD4943755Aa69cb2F803b7"
        api_url = "https://safe-api.example.com"

        [[safes.tokens]]
        token_id = 1
        eth_token_contract_addr = "0xd92e713d051c37ebb2561803a3b5fbabc4962431"
        aux_burn_contract_addr = "0x76BD419fBa96583d968b422D4f3CB2A70bf4CF40"
        aux_burn_function_sig = [0xc7, 0x6f, 0x06, 0x35]


        [[safes.tokens]]
        token_id = 2
        eth_token_contract_addr = "0x1111111111111111111111111111111111111111"
        aux_burn_contract_addr = "0x2222222222222222222222222222222222222222"
        aux_burn_function_sig = [0xaa, 0xbb, 0xcc, 0xdd]
    "#;

    static INPUT_JSON: &str = r#"{
        "safes": [
            {
                "safe_addr": "0x90213de428E9Ce4C77dD4943755Aa69cb2F803b7",
                "api_url": "https://safe-api.example.com",
                "tokens": [
                    {
                        "token_id": 1,
                        "eth_token_contract_addr": "0xd92e713d051c37ebb2561803a3b5fbabc4962431",
                        "aux_burn_contract_addr": "0x76BD419fBa96583d968b422D4f3CB2A70bf4CF40",
                        "aux_burn_function_sig": [199, 111, 6, 53]
                    },
                    {
                        "token_id": 2,
                        "eth_token_contract_addr": "0x1111111111111111111111111111111111111111",
                        "aux_burn_contract_addr": "0x2222222222222222222222222222222222222222",
                        "aux_burn_function_sig": [170, 187, 204, 221]
                    }
                ]
            }
        ]
    }"#;

    #[test]
    fn valid_config() {
        let cfg1: GnosisSafeConfig = toml::from_str(INPUT_TOML).expect("failed parsing toml");
        let cfg2: GnosisSafeConfig = serde_json::from_str(INPUT_JSON).expect("failed parsing json");

        assert_eq!(cfg1, cfg2);

        assert_eq!(
            cfg1,
            GnosisSafeConfig {
                safes: vec![AuditedSafeConfig {
                    safe_addr: EthAddr::from_str("0x90213de428E9Ce4C77dD4943755Aa69cb2F803b7")
                        .unwrap(),
                    api_url: Url::parse("https://safe-api.example.com").unwrap(),
                    tokens: vec![
                        AuditedToken {
                            token_id: TokenId::from(1),
                            eth_token_contract_addr: EthAddr::from_str(
                                "0xd92e713d051c37ebb2561803a3b5fbabc4962431",
                            )
                            .unwrap(),
                            aux_burn_contract_addr: EthAddr::from_str(
                                "0x76BD419fBa96583d968b422D4f3CB2A70bf4CF40",
                            )
                            .unwrap(),
                            aux_burn_function_sig: [199, 111, 6, 53],
                        },
                        AuditedToken {
                            token_id: TokenId::from(2),
                            eth_token_contract_addr: EthAddr::from_str(
                                "0x1111111111111111111111111111111111111111",
                            )
                            .unwrap(),
                            aux_burn_contract_addr: EthAddr::from_str(
                                "0x2222222222222222222222222222222222222222",
                            )
                            .unwrap(),
                            aux_burn_function_sig: [170, 187, 204, 221],
                        }
                    ]
                }],
            }
        );
    }

    #[test]
    fn configs_from_path() {
        let dir = tempdir().unwrap();
        let toml_file = dir.path().join("testing.toml");
        fs::write(&toml_file, INPUT_TOML).unwrap();
        let json_file = dir.path().join("testing.json");
        fs::write(&json_file, INPUT_JSON).unwrap();
        let cfg1 = GnosisSafeConfig::load_from_path(toml_file).unwrap();
        let cfg2 = GnosisSafeConfig::load_from_path(json_file).unwrap();
        assert_eq!(cfg1, cfg2);
    }

    #[test]
    fn unsupported_extension() {
        let dir = tempdir().unwrap();
        let poml_file = dir.path().join("testing.poml");
        fs::write(&poml_file, INPUT_TOML).unwrap();
        let result = GnosisSafeConfig::load_from_path(poml_file);
        assert!(matches!(result, Err(Error::UnrecognizedExtension(_))));
    }

    #[test]
    fn no_extension() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("testing");
        fs::write(&file, INPUT_TOML).unwrap();
        let result = GnosisSafeConfig::load_from_path(file);
        assert!(matches!(result, Err(Error::PathExtension)));
    }
}
