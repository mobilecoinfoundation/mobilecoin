// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    db::{Conn, GnosisSafeDeposit, GnosisSafeTx, GnosisSafeWithdrawal, MintAuditorDb, MintTx},
    gnosis::{
        api_data_types::RawGnosisTransaction, AuditedSafeConfig, AuditedToken, EthAddr, EthTxHash,
        GnosisSafeConfig,
    },
};
use mc_account_keys::burn_address;
use mc_common::logger::Logger;
use mc_transaction_core::{tx::TxOut, Amount, BlockVersion, TokenId};
use mc_transaction_core_test_utils::{
    create_mint_config_tx_and_signers, create_mint_tx, MockFogResolver,
};
use mc_transaction_std::{BurnRedemptionMemoBuilder, TransactionBuilder};
use mc_util_from_random::{CryptoRng, FromRandom, RngCore};
use serde_json::json;
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

/// Insert a GnosisSafeDeposit into the database.
pub fn insert_gnosis_deposit(deposit: &mut GnosisSafeDeposit, conn: &Conn) {
    let raw_tx = RawGnosisTransaction::from(json!({
        "txHash": deposit.eth_tx_hash(),
    }));
    GnosisSafeTx::insert(&raw_tx, conn).unwrap();
    deposit.insert(conn).unwrap();
}

/// Insert a GnosisSafeWithdrawal into the database.
pub fn insert_gnosis_withdrawal(withdrawal: &mut GnosisSafeWithdrawal, conn: &Conn) {
    let raw_tx = RawGnosisTransaction::from(json!({
        "txHash": withdrawal.eth_tx_hash(),
    }));
    GnosisSafeTx::insert(&raw_tx, conn).unwrap();
    withdrawal.insert(conn).unwrap();
}

/// Create a GnosisSafeDeposit used for testing.
pub fn create_gnosis_safe_deposit(
    amount: u64,
    rng: &mut (impl CryptoRng + RngCore),
) -> GnosisSafeDeposit {
    GnosisSafeDeposit::new(
        None,
        EthTxHash::from_random(rng),
        1,
        EthAddr::from_str(SAFE_ADDR).unwrap(),
        EthAddr::from_str(ETH_TOKEN_CONTRACT_ADDR).unwrap(),
        amount,
    )
}

/// Create a MintTx that matches a GnosisSafeDeposit.
pub fn insert_mint_tx_from_deposit(
    deposit: &GnosisSafeDeposit,
    conn: &Conn,
    rng: &mut (impl CryptoRng + RngCore),
) -> MintTx {
    let config = &test_gnosis_config().safes[0];
    let token_id = config.tokens[0].token_id;

    let (_mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id, rng);
    let mut mint_tx = create_mint_tx(token_id, &signers, deposit.amount(), rng);
    mint_tx.prefix.nonce = hex::decode(&deposit.expected_mc_mint_tx_nonce_hex()).unwrap();
    MintTx::insert_from_core_mint_tx(0, None, &mint_tx, conn).unwrap()
}

/// Create a burn TxOut.
pub fn create_burn_tx_out(
    token_id: TokenId,
    amount: u64,
    rng: &mut (impl CryptoRng + RngCore),
) -> TxOut {
    let fog_resolver = MockFogResolver::default();

    let mut memo_builder = BurnRedemptionMemoBuilder::new([2u8; 64]);
    memo_builder.enable_destination_memo();

    let mut transaction_builder = TransactionBuilder::new(
        BlockVersion::MAX,
        Amount::new(10, token_id),
        fog_resolver.clone(),
        memo_builder,
    )
    .unwrap();

    transaction_builder.set_fee(3).unwrap();

    let (burn_output, _confirmation) = transaction_builder
        .add_output(Amount::new(amount, token_id), &burn_address(), rng)
        .unwrap();

    burn_output
}

/// Create a GnosisSafeWithdrawalused for testing.
pub fn create_gnosis_safe_withdrawal(
    amount: u64,
    rng: &mut (impl CryptoRng + RngCore),
) -> GnosisSafeWithdrawal {
    let mut public_key = [0u8; 32];
    rng.fill_bytes(&mut public_key);

    GnosisSafeWithdrawal::new(
        None,
        EthTxHash::from_random(rng),
        1,
        EthAddr::from_str(SAFE_ADDR).unwrap(),
        EthAddr::from_str(ETH_TOKEN_CONTRACT_ADDR).unwrap(),
        amount,
        hex::encode(&public_key),
    )
}
