// Copyright (c) 2018-2022 The MobileCoin Foundation

use super::{BlockAuditData, BlockContents, Error, HashMap, MintAuditorDb, TokenId};
use mc_blockchain_types::{BlockIndex, BlockVersion};
use mc_common::logger::Logger;
use mc_ledger_db::{test_utils::add_block_contents_to_ledger, LedgerDB};
use mc_util_test_helper::{CryptoRng, RngCore};
use tempfile::{tempdir, TempDir};

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

pub fn append_and_sync(
    block_contents: BlockContents,
    ledger_db: &mut LedgerDB,
    mint_auditor_db: &MintAuditorDb,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(BlockAuditData, HashMap<TokenId, u64>, BlockIndex), Error> {
    let block_data =
        add_block_contents_to_ledger(ledger_db, BlockVersion::MAX, block_contents, rng)?;

    let block = block_data.block();
    mint_auditor_db
        .sync_block(block, block_data.contents())
        .map(|(audit_data, balance_map)| (audit_data, balance_map, block.index))
}
