// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    db::MintAuditorDb,
    gnosis::{AuditedSafeConfig, AuditedToken, EthAddr, GnosisSafeConfig},
};
use mc_common::logger::Logger;
use mc_transaction_core::TokenId;
use std::str::FromStr;
use tempfile::{tempdir, TempDir};
use url::Url;

/// Test values. Must match whats inside data/test/all-transactions.json
pub const SAFE_ADDR: &str = "0xeC018400FFe5Ad6E0B42Aa592Ee1CF6092972dEe";
pub const ETH_TOKEN_CONTRACT_ADDR: &str = "0xD92E713d051C37EbB2561803a3b5FBAbc4962431";
pub const AUX_BURN_CONTRACT_ADDR: &str = "0x76BD419fBa96583d968b422D4f3CB2A70bf4CF40";
pub const AUX_BURN_FUNCTION_SIG: [u8; 4] = [0xc7, 0x6f, 0x06, 0x35];

pub fn test_gnosis_config() -> GnosisSafeConfig {
    GnosisSafeConfig {
        safes: vec![AuditedSafeConfig {
            safe_addr: EthAddr::from_str(SAFE_ADDR).unwrap(),
            api_url: Url::parse("https://safe-api.example.com").unwrap(),
            tokens: vec![AuditedToken {
                token_id: TokenId::from(1),
                eth_token_contract_addr: EthAddr::from_str(ETH_TOKEN_CONTRACT_ADDR).unwrap(),
                aux_burn_contract_addr: EthAddr::from_str(AUX_BURN_CONTRACT_ADDR).unwrap(),
                aux_burn_function_sig: AUX_BURN_FUNCTION_SIG,
            }],
        }],
    }
}

pub struct TestDbContext {
    // Kept here to avoid the temp directory being deleted.
    _temp_dir: TempDir,
    db_path: String,
}

impl Default for TestDbContext {
    fn default() -> Self {
        let temp_dir = tempdir().expect("failed getting temp dir");
        let db_path = temp_dir
            .path()
            .join("mint-auditor.db")
            .into_os_string()
            .into_string()
            .unwrap();
        Self {
            _temp_dir: temp_dir,
            db_path,
        }
    }
}

impl TestDbContext {
    pub fn get_db_instance(&self, logger: Logger) -> MintAuditorDb {
        MintAuditorDb::new_from_path(&self.db_path, 7, logger)
            .expect("failed creating new MintAuditorDb")
    }
}
