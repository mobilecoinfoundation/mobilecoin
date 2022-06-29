// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Code for syncing transactions from the Gnosis API into the SQLite database.
//!
//! NOTE: Right now, if the audited safes configuration changes, one should
//! delete the SQLite database and re-audit. The code is not smart enough to
//! handle adding/removing safes/tokens for Gnosis transactions that were
//! already processed.

use crate::{
    counters,
    db::{
        AuditedMint, Conn, Counters, GnosisSafeDeposit, GnosisSafeTx, GnosisSafeWithdrawal,
        MintAuditorDb,
    },
    error::Error,
    gnosis::{
        api_data_types::{
            EthereumTransaction, MultiSigTransaction, RawGnosisTransaction, Transaction,
        },
        fetcher::GnosisSafeFetcher,
        AuditedSafeConfig, Error as GnosisError,
    },
};
use mc_common::logger::{log, Logger};

/// An object for syncing transaction data from the Gnosis API into the SQLite
/// database.
pub struct GnosisSync {
    fetcher: GnosisSafeFetcher,
    audited_safe: AuditedSafeConfig,
    mint_auditor_db: MintAuditorDb,
    logger: Logger,
}

impl GnosisSync {
    /// Instantiate a new [GnosisSync] object.
    pub fn new(
        audited_safe: AuditedSafeConfig,
        mint_auditor_db: MintAuditorDb,
        logger: Logger,
    ) -> Result<Self, GnosisError> {
        Ok(Self {
            fetcher: GnosisSafeFetcher::new(audited_safe.api_url.clone(), logger.clone())?,
            audited_safe,
            mint_auditor_db,
            logger,
        })
    }

    /// Poll the Gnosis API for transaction data.
    pub fn poll(&self) {
        // TODO: This is inefficient since it repeatedly fetches all transactions, even
        // once we reached ones we have seen before. The gnosis safe API returns
        // transactions from the newest to the oldest, and right now there is no way to
        // change that (see https://github.com/safe-global/safe-transaction-service/issues/847).
        // For this to be more efficient we need to first fetch everything once, until
        // we are certain we have synced all transactions. After that, we could
        // add an optimization that stops fetching once we've reached a transaction
        // we've seen before. This requires keeping track of whether we have
        // managed to complete a full fetch. Since right now we are not
        // expecting a large amount of transactions, this optimization is postponed to a
        // future PR.
        match self
            .fetcher
            .get_all_transaction_data(&self.audited_safe.safe_addr)
        {
            Ok(transactions) => {
                self.process_transactions(transactions);
            }
            Err(err) => {
                counters::NUM_FAILED_GNOSIS_GET_ALL_TRANSACTION_DATA.inc();
                log::error!(self.logger, "Failed to fetch Gnosis transactions: {}", err);
            }
        }
    }

    /// Process transactions and insert them to the database.
    pub fn process_transactions(&self, transactions: Vec<RawGnosisTransaction>) {
        for tx in transactions {
            let conn = self
                .mint_auditor_db
                .get_conn()
                .expect("failed getting connection");

            // SQLite3 does not like concurrent writes. Since we are going to be writing to
            // the database, ensure we are the only writers.
            conn.exclusive_transaction(|| {
                match GnosisSafeTx::insert(&tx, &conn) {
                    Ok(_) => {}
                    Err(Error::AlreadyExists(_)) => {
                        log::trace!(
                            self.logger,
                            "Skipping already-processed eth transaction {:?}",
                            tx.tx_hash()
                        );
                        return Ok(());
                    }
                    Err(err) => {
                        log::error!(self.logger, "Failed to insert GnosisSafeTx: {}", err);
                        return Err(err);
                    }
                };

                match tx.decode()? {
                    Transaction::Ethereum(eth_tx) => {
                        self.process_eth_transaction(&conn, &eth_tx)?;
                    }
                    Transaction::MultiSig(multi_sig_tx) => {
                        self.process_multi_sig_transaction(&conn, &multi_sig_tx)?;
                    }
                    Transaction::Module(value) => {
                        log::warn!(
                            self.logger,
                            "Got unexpected \"Module\" transaction: {:?}",
                            value
                        );
                    }
                };

                Ok(())
            })
            .expect("failed processing transaction");

            Counters::get(&conn)
                .expect("failed getting counters")
                .update_prometheus();
        }
    }

    /// Process an Ethereum transaction.
    fn process_eth_transaction(&self, conn: &Conn, tx: &EthereumTransaction) -> Result<(), Error> {
        log::trace!(self.logger, "Processing Ethereum transaction: {:?}", tx);

        for transfer in &tx.transfers {
            // See if this is a deposit to the safe.
            if transfer.to == self.audited_safe.safe_addr {
                log::info!(
                    self.logger,
                    "Processing gnosis safe deposit: {:?}",
                    transfer
                );

                // Empty token address means ETH
                let token_addr = transfer.token_addr.clone().unwrap_or_default();

                let mut deposit = GnosisSafeDeposit::new(
                    None,
                    transfer.tx_hash,
                    tx.eth_block_number,
                    transfer.to.clone(),
                    token_addr,
                    u64::from(transfer.value),
                );
                deposit.insert(conn)?;

                // Attempt to match the deposit with an existing MintTx.
                match AuditedMint::attempt_match_deposit_with_mint(
                    &deposit,
                    &self.audited_safe,
                    conn,
                ) {
                    Ok(mint_tx) => {
                        log::info!(
                            self.logger,
                            "Gnosis deposit eth_tx_hash={} matched MintTx nonce={}",
                            deposit.eth_tx_hash(),
                            mint_tx.nonce_hex(),
                        )
                    }
                    Err(Error::NotFound) => {
                        log::debug!(self.logger, "Gnosis deposit eth_tx_hash={} does not currently have matching MintTx, this could be fine if the ledger is not fully synced.", deposit.eth_tx_hash());
                    }
                    Err(err) => {
                        log::error!(
                            self.logger,
                            "Gnosis deposit eth_tx_hash={} failed matching to a MintTx: {}",
                            deposit.eth_tx_hash(),
                            err
                        );

                        // TODO update counter
                    }
                };
            }
            // We don't know what this is.
            else {
                log::crit!(
                    self.logger,
                    "Unknown transfer {:?} in eth tx {}",
                    transfer,
                    tx.tx_hash,
                );
            }
        }

        Ok(())
    }

    /// Process a MultiSig transaction.
    fn process_multi_sig_transaction(
        &self,
        conn: &Conn,
        multi_sig_tx: &MultiSigTransaction,
    ) -> Result<(), Error> {
        // See if this is a withdrawal from the safe we are tracking. In theory we
        // should never receive a response for a different safe since the Gnosis API
        // filters by safe address.
        if multi_sig_tx.safe != self.audited_safe.safe_addr {
            log::warn!(
                self.logger,
                "Received MultiSig transaction for a different safe than {}: {:?}",
                self.audited_safe.safe_addr,
                multi_sig_tx
            );
            return Ok(());
        }

        match self.parse_withdrawal_with_pub_key_multi_sig_tx(multi_sig_tx) {
            Ok(mut withdrawal) => {
                log::info!(
                    self.logger,
                    "Processing withdrawal from multi-sig tx: {:?}",
                    withdrawal
                );

                withdrawal.insert(conn)?;
            }

            Err(err) => {
                log::warn!(
                    self.logger,
                    "Failed parsing a withdrawal from multisig tx {}: {}",
                    multi_sig_tx.tx_hash,
                    err
                );
            }
        };

        Ok(())
    }

    /// See if this is a multi-sig withdrawal that uses the auxiliary contract
    /// for recording the tx out public key, and if so parse it into a
    /// [NewGnosisSafeWithdrawal] object.
    fn parse_withdrawal_with_pub_key_multi_sig_tx(
        &self,
        multi_sig_tx: &MultiSigTransaction,
    ) -> Result<GnosisSafeWithdrawal, GnosisError> {
        // Get the decoded data - this is the part that contains details about the
        // individual transfers included in the multi-transfer.
        let data = multi_sig_tx
            .data_decoded
            .as_ref()
            .ok_or_else(|| GnosisError::ApiResultParse("data_decoded is empty".into()))?;

        if data.method != "multiSend" {
            return Err(GnosisError::ApiResultParse(format!(
                "multi-sig tx method mismatch: got {}, expected multiSend",
                data.method
            )));
        }

        // The decoded data is expected to contain a single "transactions" parameter,
        // which should be an array of the individual transfers.
        if data.parameters.len() != 1 {
            return Err(GnosisError::ApiResultParse(format!(
                "invalid number of parameters: got {}, expected 1",
                data.parameters.len()
            )));
        }

        let parameter = &data.parameters[0];
        let value_decoded = parameter.value_decoded.as_ref().ok_or_else(|| {
            GnosisError::ApiResultParse("decoded data parameter is missing value_decoded".into())
        })?;

        // Each value contains a single transfer. We expect to have two transfers:
        // 1) A transfer moving the token being withdrawn from the safe
        // 2) A "dummy" transfer into the auxiliary contract, used to record the
        // matching MobileCoin tx out public key of the matching burn.
        if value_decoded.len() != 2 {
            return Err(GnosisError::ApiResultParse(format!(
                "Invalid number of values in multiSend transfer: got {}, expected 2",
                value_decoded.len()
            )));
        }

        // The first value is the transfer of the actual token held in the safe. It
        // should match a token we are auditing.
        let transfer_data = &value_decoded[0];
        let audited_token = self
            .audited_safe
            .get_token_by_eth_contract_addr(&transfer_data.to)
            .ok_or_else(|| {
                GnosisError::ApiResultParse(format!(
                    "Encountered multiSend transaction to an unknown token: {}",
                    transfer_data.to
                ))
            })?;

        // The first value (transfer of token held in safe) should contain two
        // parameters - the ethereum address receiving the withdrawal and the
        // amount being moved out of the safe.
        let transfer_data_decoded = transfer_data.data_decoded.as_ref().ok_or_else(|| {
            GnosisError::ApiResultParse("multiSend transfer first value has no decoded data".into())
        })?;
        if transfer_data_decoded.method != "transfer" {
            return Err(GnosisError::ApiResultParse(format!(
                "Invalid first value method: got {}, expected transfer",
                transfer_data_decoded.method
            )));
        }

        let value_str = transfer_data_decoded
            .parameters
            .iter()
            .find_map(|param| {
                if param.name == "value" {
                    Some(&param.value)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                GnosisError::ApiResultParse("first value is missing the \"value\" parameter".into())
            })?;
        let transfer_value = value_str.parse::<u64>().map_err(|err| {
            GnosisError::ApiResultParse(format!(
                "invalid first value parameter: \"value\" {} cannot be be converted to u64: {}",
                value_str, err,
            ))
        })?;

        // The second value (dummy transfer to auxiliary contract) should contain the
        // MobileCoin tx out public key in the data. There is no decoded version
        // of the data since the Gnosis API does not know how to decode custom
        // contracts.
        let aux_contract_value = &value_decoded[1];
        if aux_contract_value.to != audited_token.aux_burn_contract_addr {
            return Err(GnosisError::ApiResultParse(format!(
                "aux contract destination mismatch: got {}, expected {}",
                aux_contract_value.to, audited_token.aux_burn_contract_addr
            )));
        }

        if !aux_contract_value.data.starts_with("0x") {
            return Err(GnosisError::ApiResultParse(format!(
                "aux contract data doesn't start with 0x: got {}",
                aux_contract_value.data,
            )));
        }

        let aux_data_bytes = hex::decode(&aux_contract_value.data[2..]).map_err(|err| {
            GnosisError::ApiResultParse(format!(
                "aux contract data {} cannot be hex-decoded: {}",
                aux_contract_value.data, err,
            ))
        })?;

        if !aux_data_bytes.starts_with(&audited_token.aux_burn_function_sig) {
            return Err(GnosisError::ApiResultParse(format!(
                "aux contract data {} does not start with the expected function signature ({})",
                aux_contract_value.data,
                hex::encode(audited_token.aux_burn_function_sig),
            )));
        }

        // The tx out pub key is the last 32 bytes. Ensure we have enough bytes in the
        // data for that.
        let min_length = audited_token.aux_burn_function_sig.len() + 32;
        if aux_data_bytes.len() < min_length {
            return Err(GnosisError::ApiResultParse(format!(
                "aux contract data {} does not contain enough bytes. got {}, expected at least {}",
                aux_contract_value.data,
                aux_contract_value.data.len(),
                min_length,
            )));
        }

        let tx_out_pub_key = &aux_data_bytes[aux_data_bytes.len() - 32..];

        // Parsed everything we need.
        Ok(GnosisSafeWithdrawal::new(
            None,
            multi_sig_tx.tx_hash,
            multi_sig_tx.eth_block_number,
            multi_sig_tx.safe.clone(),
            transfer_data.to.clone(),
            transfer_value,
            hex::encode(tx_out_pub_key),
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        db::{
            schema::{gnosis_safe_deposits, gnosis_safe_withdrawals},
            test_utils::{
                insert_mint_tx_from_deposit, TestDbContext, AUX_BURN_CONTRACT_ADDR,
                AUX_BURN_FUNCTION_SIG, ETH_TOKEN_CONTRACT_ADDR, SAFE_ADDR,
            },
            MintTx,
        },
        gnosis::{
            api_data_types::AllTransactionsResponse, config::AuditedToken, EthAddr, EthTxHash,
        },
    };
    use diesel::prelude::*;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_transaction_core::TokenId;
    use mc_transaction_core_test_utils::{create_mint_config_tx_and_signers, create_mint_tx};
    use std::{collections::HashSet, str::FromStr};
    use url::Url;

    // Generated by the following command:
    // curl -X GET "https://safe-transaction.rinkeby.gnosis.io/api/v1/safes/0xeC018400FFe5Ad6E0B42Aa592Ee1CF6092972dEe/all-transactions/?ordering=-executionDate&offset=0&executed=true&queued=false&trusted=true" -H  "accept: application/json" -H  "X-CSRFToken: skjBYGJ68aaPzCvTmFfKh5EryjEbjHpKRjNGtcqqH8jU7zdzxOR1nGNqoAGb1NGI" | python3 -mjson.tool
    // This is a test safe that was created on the Rinkeby network and contains some
    // deposits and withdrawals.
    const ALL_TRANSACTIONS_JSON: &str = include_str!("../../data/test/all-transactions.json");

    // Helper to parse ALL_TRANSACTIONS_JSON into a list of RawGnosisTransactions
    fn get_raw_transactions() -> Vec<RawGnosisTransaction> {
        let all_transactions_response: AllTransactionsResponse =
            serde_json::from_str(ALL_TRANSACTIONS_JSON).unwrap();
        all_transactions_response
            .results
            .into_iter()
            .map(RawGnosisTransaction::from)
            .collect()
    }

    #[test_with_logger]
    fn process_transactions_works(logger: Logger) {
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();
        let raw_transactions = get_raw_transactions();

        // Must match the contents of the test JSON file.
        let audited_safe_config = AuditedSafeConfig {
            safe_addr: EthAddr::from_str(SAFE_ADDR).unwrap(),
            api_url: Url::parse("http://unused:8545").unwrap(),
            tokens: vec![AuditedToken {
                token_id: TokenId::from(1),
                eth_token_contract_addr: EthAddr::from_str(ETH_TOKEN_CONTRACT_ADDR).unwrap(),
                aux_burn_contract_addr: EthAddr::from_str(AUX_BURN_CONTRACT_ADDR).unwrap(),
                aux_burn_function_sig: AUX_BURN_FUNCTION_SIG,
            }],
        };

        let expected_deposits = vec![
            GnosisSafeDeposit::new(
                Some(2),
                EthTxHash::from_str(
                    "0xa202a4c37f0670557ceeb33f796fba0c187f699f5dd4d8add0eba1c3154b2fa7",
                )
                .unwrap(),
                10824613,
                EthAddr::from_str(SAFE_ADDR).unwrap(),
                EthAddr::from_str(ETH_TOKEN_CONTRACT_ADDR).unwrap(),
                1000000,
            ),
            GnosisSafeDeposit::new(
                Some(1),
                EthTxHash::from_str(
                    "0x4f3124c61c48aa7c7892f8fe426e0c0d8afae100fc0a9aa8e290e530a7632849",
                )
                .unwrap(),
                10824662,
                EthAddr::from_str(SAFE_ADDR).unwrap(),
                EthAddr::from_str(ETH_TOKEN_CONTRACT_ADDR).unwrap(),
                10000000,
            ),
        ];

        // Store the MintTxs in the database so we can see they get audited properly.
        let mint_tx1 = insert_mint_tx_from_deposit(&expected_deposits[0], &conn, &mut rng);
        let mint_tx2 = insert_mint_tx_from_deposit(&expected_deposits[1], &conn, &mut rng);

        // Add another unrelated MintTx.
        let token_id = TokenId::from(1);
        let (_mint_config_tx, signers) = create_mint_config_tx_and_signers(token_id, &mut rng);
        let mint_tx3 = MintTx::insert_from_core_mint_tx(
            0,
            None,
            &create_mint_tx(token_id, &signers, 100, &mut rng),
            &conn,
        )
        .unwrap();

        // Initially, none are audited.
        assert_eq!(
            HashSet::<MintTx>::from_iter(vec![mint_tx1, mint_tx2, mint_tx3.clone()]),
            HashSet::from_iter(MintTx::find_unaudited_mint_txs(&conn).unwrap())
        );

        // Perform a gnosis sync.
        let sync = GnosisSync::new(audited_safe_config, mint_auditor_db, logger).unwrap();
        sync.process_transactions(raw_transactions);

        // Validate that we are seeing the expected deposits.
        let deposits = gnosis_safe_deposits::table
            .order_by(gnosis_safe_deposits::eth_block_number)
            .load::<GnosisSafeDeposit>(&conn)
            .unwrap();

        assert_eq!(deposits, expected_deposits);

        // Validate that we are seeing the expected withdrawals.
        let withdrawals = gnosis_safe_withdrawals::table
            .order_by(gnosis_safe_withdrawals::eth_block_number)
            .load::<GnosisSafeWithdrawal>(&conn)
            .unwrap();
        let expected_withdrawals = vec![
            GnosisSafeWithdrawal::new(
                Some(2),
                EthTxHash::from_str(
                    "0x323b145662d2a64de0a55977089b7a89ed6003e341d5a68266a200dde83639d4",
                )
                .unwrap(),
                10824635,
                EthAddr::from_str(SAFE_ADDR).unwrap(),
                EthAddr::from_str(ETH_TOKEN_CONTRACT_ADDR).unwrap(),
                500000,
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string(),
            ),
            GnosisSafeWithdrawal::new(
                Some(1),
                EthTxHash::from_str(
                    "0x2f55d7b7620876c1dfc25419937a7fd2538489c1dd3adf6b438396a958d88e28",
                )
                .unwrap(),
                10824678,
                EthAddr::from_str(SAFE_ADDR).unwrap(),
                EthAddr::from_str(ETH_TOKEN_CONTRACT_ADDR).unwrap(),
                2000000,
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string(),
            ),
        ];
        assert_eq!(withdrawals, expected_withdrawals);

        // Only the third MintTx remains unaudited.
        assert_eq!(
            vec![mint_tx3],
            MintTx::find_unaudited_mint_txs(&conn).unwrap()
        );
    }

    #[test_with_logger]
    fn process_transactions_ignores_unknown(logger: Logger) {
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();
        let raw_transactions = get_raw_transactions();

        // Must match the contents of the test JSON file.
        // (Except the safe address, since that is what we are testing here)
        let unknown_safe_audited_safe_config = AuditedSafeConfig {
            safe_addr: EthAddr::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            api_url: Url::parse("http://unused:8545").unwrap(),
            tokens: vec![AuditedToken {
                token_id: TokenId::from(1),
                eth_token_contract_addr: EthAddr::from_str(ETH_TOKEN_CONTRACT_ADDR).unwrap(),
                aux_burn_contract_addr: EthAddr::from_str(AUX_BURN_CONTRACT_ADDR).unwrap(),
                aux_burn_function_sig: AUX_BURN_FUNCTION_SIG,
            }],
        };

        // Must match the contents of the test JSON file.
        // (Except the fields we are purposefully altering to make sure they are
        // ignored)
        let unknown_token_audited_safe_config = AuditedSafeConfig {
            safe_addr: EthAddr::from_str(SAFE_ADDR).unwrap(),
            api_url: Url::parse("http://unused:8545").unwrap(),
            tokens: vec![
                // Unknown token contract address
                AuditedToken {
                    token_id: TokenId::from(1),
                    eth_token_contract_addr: EthAddr::from_str(
                        "0x0000000000000000000000000000000000000000",
                    )
                    .unwrap(),
                    aux_burn_contract_addr: EthAddr::from_str(AUX_BURN_CONTRACT_ADDR).unwrap(),
                    aux_burn_function_sig: AUX_BURN_FUNCTION_SIG,
                },
                // Unknown aux burn contract address
                AuditedToken {
                    token_id: TokenId::from(1),
                    eth_token_contract_addr: EthAddr::from_str(ETH_TOKEN_CONTRACT_ADDR).unwrap(),
                    aux_burn_contract_addr: EthAddr::from_str(
                        "0x0000000000000000000000000000000000000000",
                    )
                    .unwrap(),
                    aux_burn_function_sig: AUX_BURN_FUNCTION_SIG,
                },
                // Unknown aux burn function sig
                AuditedToken {
                    token_id: TokenId::from(1),
                    eth_token_contract_addr: EthAddr::from_str(ETH_TOKEN_CONTRACT_ADDR).unwrap(),
                    aux_burn_contract_addr: EthAddr::from_str(AUX_BURN_CONTRACT_ADDR).unwrap(),
                    aux_burn_function_sig: [0xc7, 0x6f, 0x06, 0xFF],
                },
            ],
        };

        // Perform a gnosis sync.
        let sync = GnosisSync::new(
            unknown_safe_audited_safe_config,
            mint_auditor_db.clone(),
            logger.clone(),
        )
        .unwrap();
        sync.process_transactions(raw_transactions.clone());

        let sync =
            GnosisSync::new(unknown_token_audited_safe_config, mint_auditor_db, logger).unwrap();
        sync.process_transactions(raw_transactions);

        // Validate that we are seeing no deposits/withdrawals.
        let deposits = gnosis_safe_deposits::table
            .order_by(gnosis_safe_deposits::eth_block_number)
            .load::<GnosisSafeDeposit>(&conn)
            .unwrap();
        assert_eq!(deposits, vec![]);

        let withdrawals = gnosis_safe_withdrawals::table
            .order_by(gnosis_safe_withdrawals::eth_block_number)
            .load::<GnosisSafeWithdrawal>(&conn)
            .unwrap();
        assert_eq!(withdrawals, vec![]);
    }
}
