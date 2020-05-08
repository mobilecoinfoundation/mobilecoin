// Copyright (c) 2018-2020 MobileCoin Inc.

//! Database storage for block signatures.

use crate::error::SignatureStoreError;

use lmdb::{Cursor, Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_common::logger::{log, Logger};
use mc_transaction_core::BlockSignature;
use mc_util_serial::{decode, encode};
use std::sync::Arc;

// LMDB Database Names
pub const BLOCK_SIGNATURES_DB_NAME: &str = "watcher_db:signature_store:block_signatures";

#[derive(Clone)]
/// Storage of Block Signatures.
pub struct SignatureStore {
    /// LMDB Environment.
    env: Arc<Environment>,

    /// Mapping of block ID to block signatures.
    block_signatures: Database,

    /// Logger.
    logger: Logger,
}

impl SignatureStore {
    pub fn new(env: Arc<Environment>, logger: Logger) -> Result<Self, SignatureStoreError> {
        let block_signatures = env.create_db(
            Some(BLOCK_SIGNATURES_DB_NAME),
            DatabaseFlags::DUP_SORT | DatabaseFlags::DUP_FIXED,
        )?;
        Ok(Self {
            env,
            block_signatures,
            logger,
        })
    }

    /// Insert a block signature for a block ID.
    pub fn add_signatures(
        &self,
        db_txn: &mut RwTransaction,
        block_index: u64,
        signatures: &Vec<BlockSignature>,
    ) -> Result<(), SignatureStoreError> {
        let key_bytes = encode(&block_index);
        for signature in signatures {
            let value_bytes = encode(signature);
            db_txn.put(
                self.block_signatures,
                &key_bytes,
                &value_bytes,
                WriteFlags::empty(),
            )?;

            println!(
                "\x1b[1;32mInserting {:?} ({:?}) to block_signatures store\x1b[0m",
                block_index, signature,
            );
        }

        Ok(())
    }

    /// Returns the Signatures associated with a given block ID.
    pub fn get_signatures(
        &self,
        db_txn: &impl Transaction,
        block_index: u64,
    ) -> Result<Vec<BlockSignature>, SignatureStoreError> {
        let mut cursor = db_txn.open_ro_cursor(self.block_signatures)?;
        let key_bytes = encode(&block_index);

        log::trace!(
            self.logger,
            "Getting block signatures for {:?}",
            block_index
        );

        let sig = db_txn.get(self.block_signatures, &key_bytes)?;
        log::trace!(self.logger, "Is there anything for the key? {:?}", sig);

        match cursor.iter_dup_of(&key_bytes) {
            Ok(iter) => {
                let mut results: Vec<BlockSignature> = Vec::new();
                for (_key_bytes, value_bytes) in iter {
                    let block_signature = decode(value_bytes)?;
                    log::trace!(
                        self.logger,
                        "Got block signatures for {:?} ({:?})",
                        block_index,
                        block_signature,
                    );
                    results.push(block_signature);
                }
                Ok(results)
            }
            Err(err) => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_crypto_keys::Ed25519Pair;
    use mc_transaction_core::{account_keys::AccountKey, Block, BlockContents};
    use mc_transaction_core_test_utils::get_blocks;
    use mc_util_from_random::FromRandom;
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use tempdir::TempDir;

    fn setup_signature_store(logger: Logger) -> SignatureStore {
        let db_tmp = TempDir::new("wallet_db").expect("Could not make tempdir for wallet db");
        let db_path = db_tmp.path().to_str().unwrap();
        let env = Arc::new(
            Environment::new()
                .set_max_dbs(10)
                .set_map_size(10000000)
                .open(db_path.as_ref())
                .unwrap(),
        );

        SignatureStore::new(env, logger).unwrap()
    }

    fn setup_blocks() -> Vec<(Block, BlockContents)> {
        let mut rng: Hc128Rng = Hc128Rng::from_seed([8u8; 32]);
        let origin = Block::new_origin_block(&[]);

        let accounts: Vec<AccountKey> = (0..20).map(|_i| AccountKey::random(&mut rng)).collect();
        let recipient_pub_keys = accounts
            .iter()
            .map(|account| account.default_subaddress())
            .collect::<Vec<_>>();
        get_blocks(&recipient_pub_keys, 10, 1, 10, &origin, &mut rng)
    }

    // SignatureStore should insert and get multiple signatures.
    #[test_with_logger]
    fn test_insert_and_get(logger: Logger) {
        let mut rng: Hc128Rng = Hc128Rng::from_seed([8u8; 32]);
        let sig_store = setup_signature_store(logger.clone());

        let blocks = setup_blocks();

        let signing_key_a = Ed25519Pair::from_random(&mut rng);
        let signing_key_b = Ed25519Pair::from_random(&mut rng);

        let signed_block_a1 =
            BlockSignature::from_block_and_keypair(&blocks[1].0, &signing_key_a).unwrap();
        let _signed_block_b1 =
            BlockSignature::from_block_and_keypair(&blocks[1].0, &signing_key_b).unwrap();

        let mut db_txn = sig_store.env.begin_rw_txn().unwrap();
        sig_store.insert(&mut db_txn, 1, &signed_block_a1).unwrap();
        db_txn.commit().unwrap();

        let db_ro_txn = sig_store.env.begin_ro_txn().unwrap();
        assert_eq!(sig_store.get_signatures(&db_ro_txn, 1).unwrap().len(), 1);
    }
}
