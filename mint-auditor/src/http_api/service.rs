// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mint auditor service for handling HTTP requests

use crate::{
    db::{AuditedBurn, AuditedMint, BlockAuditData, BlockBalance, Counters, MintAuditorDb},
    http_api::api_types::{AuditedBurnResponse, AuditedMintResponse, BlockAuditDataResponse},
    Error,
};

/// Service for handling auditor requests
pub struct MintAuditorHttpService {
    /// Mint auditor database.
    mint_auditor_db: MintAuditorDb,
}

/// Service for handling auditor requests
impl MintAuditorHttpService {
    /// Create a new mint auditor HTTP service.
    pub fn new(mint_auditor_db: MintAuditorDb) -> Self {
        Self { mint_auditor_db }
    }

    /// get counters
    pub fn get_counters(&self) -> Result<Counters, Error> {
        let conn = self.mint_auditor_db.get_conn()?;
        Counters::get(&conn)
    }

    /// Get the audit data for a target block
    pub fn get_block_audit_data(&self, block_index: u64) -> Result<BlockAuditDataResponse, Error> {
        let conn = self.mint_auditor_db.get_conn()?;

        let block_audit_data = BlockAuditData::get(&conn, block_index)?;

        let balances = BlockBalance::get_balances_for_block(&conn, block_audit_data.block_index())?;

        Ok(BlockAuditDataResponse::new(block_audit_data, balances))
    }

    /// Get the audit data for the last synced block.
    pub fn get_last_block_audit_data(&self) -> Result<BlockAuditDataResponse, Error> {
        let conn = self.mint_auditor_db.get_conn()?;

        let block_audit_data =
            BlockAuditData::last_block_audit_data(&conn)?.ok_or(Error::NotFound)?;

        let balances = BlockBalance::get_balances_for_block(&conn, block_audit_data.block_index())?;

        Ok(BlockAuditDataResponse::new(block_audit_data, balances))
    }

    /// Get a paginated list of audited mints, along with corresponding mint tx
    /// and gnosis safe deposit
    pub fn get_audited_mints(
        &self,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<AuditedMintResponse>, Error> {
        let conn = self.mint_auditor_db.get_conn()?;

        let query_result = AuditedMint::list_with_mint_and_deposit(offset, limit, &conn)?;

        let response = query_result
            .into_iter()
            .map(|(audited, mint, deposit)| AuditedMintResponse {
                audited,
                mint,
                deposit,
            })
            .collect();

        Ok(response)
    }

    /// Get a paginated list of audited burns, along with corresponding burn tx
    /// and gnosis safe withdrawal
    pub fn get_audited_burns(
        &self,
        offset: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Vec<AuditedBurnResponse>, Error> {
        let conn = self.mint_auditor_db.get_conn()?;

        let query_result = AuditedBurn::list_with_burn_and_withdrawal(offset, limit, &conn)?;

        let response = query_result
            .into_iter()
            .map(|(audited, burn, withdrawal)| AuditedBurnResponse {
                audited,
                burn,
                withdrawal,
            })
            .collect();

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        test_utils::{
            append_and_sync, create_burn_tx_out, create_gnosis_safe_deposit,
            create_gnosis_safe_withdrawal_from_burn_tx_out, insert_gnosis_deposit,
            insert_gnosis_withdrawal, insert_mint_tx_from_deposit, test_gnosis_config,
            TestDbContext,
        },
        BurnTxOut, GnosisSafeDeposit, GnosisSafeWithdrawal, MintTx,
    };
    use mc_account_keys::AccountKey;
    use mc_blockchain_types::{BlockContents, BlockVersion};
    use mc_common::{
        logger::{test_with_logger, Logger},
        HashMap,
    };
    use mc_ledger_db::{
        test_utils::{create_ledger, initialize_ledger},
        Ledger,
    };
    use mc_transaction_core::TokenId;
    use mc_transaction_core_test_utils::{
        create_mint_config_tx_and_signers, create_mint_tx, create_test_tx_out,
        mint_config_tx_to_validated as to_validated,
    };

    /// Create a test database with some data in it.
    /// Seeds a ledger DB with some txos and mint txos, then syncs the mint
    /// auditor DB with the ledger.
    fn get_test_db(logger: &Logger) -> (MintAuditorDb, TestDbContext) {
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(22);

        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());

        let mut ledger_db = create_ledger();
        let account_key = AccountKey::random(&mut rng);
        let num_initial_blocks = 1;
        initialize_ledger(
            BlockVersion::MAX,
            &mut ledger_db,
            num_initial_blocks,
            &account_key,
            &mut rng,
        );

        for block_index in 0..num_initial_blocks {
            let block_data = ledger_db.get_block_data(block_index).unwrap();

            mint_auditor_db
                .sync_block(block_data.block(), block_data.contents())
                .unwrap();
        }

        // Sync a block that contains a few mint config transactions.
        let (mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let (mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id2, &mut rng);

        let block_contents = BlockContents {
            validated_mint_config_txs: vec![
                to_validated(&mint_config_tx1),
                to_validated(&mint_config_tx2),
            ],
            ..Default::default()
        };

        append_and_sync(block_contents, &mut ledger_db, &mint_auditor_db, &mut rng).unwrap();

        // Sync a block that contains a few mint transactions.
        let mint_tx1 = create_mint_tx(token_id1, &signers1, 1, &mut rng);
        let mint_tx2 = create_mint_tx(token_id2, &signers2, 2, &mut rng);
        let mint_tx3 = create_mint_tx(token_id1, &signers1, 100, &mut rng);

        let block_contents = BlockContents {
            mint_txs: vec![mint_tx1, mint_tx2, mint_tx3],
            outputs: (0..3)
                .map(|_i| create_test_tx_out(BlockVersion::MAX, &mut rng))
                .collect(),
            ..Default::default()
        };

        append_and_sync(block_contents, &mut ledger_db, &mint_auditor_db, &mut rng).unwrap();

        (mint_auditor_db, test_db_context)
    }

    #[test_with_logger]
    fn test_get_block_audit_data(logger: Logger) {
        let (mint_auditor_db, _test_db_context) = get_test_db(&logger);
        let service = MintAuditorHttpService::new(mint_auditor_db);

        let response = service.get_block_audit_data(2).unwrap();

        assert_eq!(response.block_index, 2,);
        assert_eq!(response.balances, HashMap::from_iter([(1, 101), (22, 2)]));
    }

    #[test_with_logger]
    fn test_get_last_block_audit_data(logger: Logger) {
        let (mint_auditor_db, _test_db_context) = get_test_db(&logger);
        let service = MintAuditorHttpService::new(mint_auditor_db);
        let response = service.get_last_block_audit_data().unwrap();
        assert_eq!(response.block_index, 2,);
        assert_eq!(response.balances, HashMap::from_iter([(1, 101), (22, 2)]));
    }

    #[test_with_logger]
    fn test_get_counters(logger: Logger) {
        let (mint_auditor_db, _test_db_context) = get_test_db(&logger);
        let service = MintAuditorHttpService::new(mint_auditor_db);

        let response = service.get_counters().unwrap();

        // The number of blocks synced depends on the database that [get_test_db]
        // generates.
        assert_eq!(response.num_blocks_synced(), 3,);
    }

    #[test_with_logger]
    fn test_get_audited_mints_service(logger: Logger) {
        let config = &test_gnosis_config();
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let mint_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = mint_auditor_db.get_conn().unwrap();
        let service = MintAuditorHttpService::new(mint_auditor_db);

        let mut deposits: Vec<GnosisSafeDeposit> = vec![];
        let mut mints: Vec<MintTx> = vec![];

        for _ in 0..10 {
            let mut deposit = create_gnosis_safe_deposit(100, &mut rng);
            deposits.push(deposit.clone());
            insert_gnosis_deposit(&mut deposit, &conn);
            let mint = insert_mint_tx_from_deposit(&deposit, &conn, &mut rng);
            mints.push(mint.clone());
            AuditedMint::try_match_mint_with_deposit(&mint, config, &conn).unwrap();
        }

        let all_audited_mints = service.get_audited_mints(None, None).unwrap();
        assert_eq!(all_audited_mints.len(), 10);

        assert_eq!(all_audited_mints[0].mint, mints[0]);
        assert_eq!(
            all_audited_mints[0].deposit.eth_tx_hash(),
            deposits[0].eth_tx_hash()
        );

        let paginated_mints = service.get_audited_mints(Some(4), Some(3)).unwrap();
        assert_eq!(paginated_mints.len(), 3);
        assert_eq!(paginated_mints[0].audited.id.unwrap(), 5);
        assert_eq!(paginated_mints[2].audited.id.unwrap(), 7);
    }

    #[test_with_logger]
    fn test_get_audited_burns_service(logger: Logger) {
        let config = &test_gnosis_config().safes[0];
        let mut rng = mc_util_test_helper::get_seeded_rng();
        let test_db_context = TestDbContext::default();
        let burn_auditor_db = test_db_context.get_db_instance(logger.clone());
        let conn = burn_auditor_db.get_conn().unwrap();
        let token_id = config.tokens[0].token_id;
        let service = MintAuditorHttpService::new(burn_auditor_db);

        let mut withdrawals: Vec<GnosisSafeWithdrawal> = vec![];
        let mut burns: Vec<BurnTxOut> = vec![];

        for _ in 0..10 {
            let mut burn = create_burn_tx_out(token_id, 100, &mut rng);
            burn.insert(&conn).unwrap();
            burns.push(burn.clone());
            let mut withdrawal = create_gnosis_safe_withdrawal_from_burn_tx_out(&burn, &mut rng);
            withdrawals.push(withdrawal.clone());
            insert_gnosis_withdrawal(&mut withdrawal, &conn);
            AuditedBurn::try_match_withdrawal_with_burn(&withdrawal, config, &conn).unwrap();
        }

        let all_audited_burns = service.get_audited_burns(None, None).unwrap();
        assert_eq!(all_audited_burns.len(), 10);

        assert_eq!(all_audited_burns[0].burn, burns[0]);
        assert_eq!(
            all_audited_burns[0].withdrawal.eth_tx_hash(),
            withdrawals[0].eth_tx_hash()
        );

        let paginated_burns = service.get_audited_burns(Some(4), Some(3)).unwrap();
        assert_eq!(paginated_burns.len(), 3);
        assert_eq!(paginated_burns[0].audited.id.unwrap(), 5);
        assert_eq!(paginated_burns[2].audited.id.unwrap(), 7);
    }
}
