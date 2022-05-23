// Copyright (c) 2018-2022 The MobileCoin Foundation

use super::{BlockAuditData, Error, MintAuditorDb};
use mc_blockchain_test_utils::make_block_metadata;
use mc_blockchain_types::{Block, BlockContents, BlockIndex, BlockVersion};
use mc_common::{logger::Logger, HashMap};
use mc_ledger_db::{Ledger, LedgerDB};
use mc_transaction_core::TokenId;
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
    block_contents: &BlockContents,
    ledger_db: &mut LedgerDB,
    mint_auditor_db: &MintAuditorDb,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(BlockAuditData, HashMap<TokenId, u64>, BlockIndex), Error> {
    let parent_block = ledger_db.get_latest_block()?;
    let block = Block::new_with_parent(
        BlockVersion::MAX,
        &parent_block,
        &Default::default(),
        block_contents,
    );

    let metadata = make_block_metadata(block.id.clone(), rng);
    ledger_db.append_block(&block, block_contents, None, Some(&metadata))?;

    mint_auditor_db
        .sync_block(&block, block_contents)
        .map(|(mint_audit_data, balance_map)| (mint_audit_data, balance_map, block.index))
}
