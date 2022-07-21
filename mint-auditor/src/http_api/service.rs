// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mint auditor service for handling http requests

use crate::{
    db::{BlockAuditData, BlockBalance, Counters, MintAuditorDb},
    http_api::api_types::BlockAuditDataResponse,
    Error,
};

/// Service for handling auditor requests
pub struct MintAuditorHttpService {}

/// Service for handling auditor requests
impl MintAuditorHttpService {
    /// get counters
    pub fn get_counters(mint_auditor_db: &MintAuditorDb) -> Result<Counters, Error> {
        let conn = mint_auditor_db.get_conn()?;
        Ok(Counters::get(&conn)?)
    }

    /// Get the audit data for a target block
    pub fn get_block_audit_data(
        block_index: u64,
        mint_auditor_db: &MintAuditorDb,
    ) -> Result<BlockAuditDataResponse, Error> {
        let conn = mint_auditor_db.get_conn()?;

        let block_audit_data = BlockAuditData::get(&conn, block_index)?;

        let balances = BlockBalance::get_balances_for_block(&conn, block_audit_data.block_index())?;

        Ok(BlockAuditDataResponse::new(block_audit_data, balances))
    }

    /// Get the audit data for the last synced block.
    pub fn get_last_block_audit_data(
        mint_auditor_db: &MintAuditorDb,
    ) -> Result<BlockAuditDataResponse, Error> {
        let conn = mint_auditor_db.get_conn()?;

        let block_audit_data =
            BlockAuditData::last_block_audit_data(&conn)?.ok_or(Error::NotFound)?;

        let balances = BlockBalance::get_balances_for_block(&conn, block_audit_data.block_index())?;

        Ok(BlockAuditDataResponse::new(block_audit_data, balances))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::{append_and_sync, TestDbContext};
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

        let response = MintAuditorHttpService::get_block_audit_data(2, &mint_auditor_db).unwrap();

        assert_eq!(response.block_index, 2,);
        assert_eq!(response.balances, HashMap::from_iter([(1, 101), (22, 2)]));
    }

    #[test_with_logger]
    fn test_get_last_block_audit_data(logger: Logger) {
        let (mint_auditor_db, _test_db_context) = get_test_db(&logger);

        let response = MintAuditorHttpService::get_last_block_audit_data(&mint_auditor_db).unwrap();
        assert_eq!(response.block_index, 2,);
        assert_eq!(response.balances, HashMap::from_iter([(1, 101), (22, 2)]));
    }

    #[test_with_logger]
    fn test_get_counters(logger: Logger) {
        let (mint_auditor_db, _test_db_context) = get_test_db(&logger);

        let response = MintAuditorHttpService::get_counters(&mint_auditor_db).unwrap();

        // The number of blocks synced depends on the database that [get_test_db]
        // generates.
        assert_eq!(
            response,
            CountersResponse {
                num_blocks_synced: 3,
                ..Default::default()
            }
        );
    }
}
