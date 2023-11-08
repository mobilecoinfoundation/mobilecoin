// Copyright (c) 2018-2023 The MobileCoin Foundation

use crate::{BlockDataResponse, BlockProvider, Error, TxOutInfoByPublicKeyResponse};
use mc_blockchain_types::{Block, BlockIndex};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::ledger::{TxOutResult, TxOutResultCode};
use mc_ledger_db::{Error as LedgerError, Ledger};
use mc_transaction_core::tx::{TxOut, TxOutMembershipProof};
use mc_watcher::watcher_db::WatcherDB;
use mc_watcher_api::TimestampResultCode;
use std::time::Duration;

#[derive(Clone)]
pub struct LocalBlockProvider<L: Ledger + Clone + Sync> {
    ledger: L,
    watcher: Option<WatcherDB>,
}

impl<L: Ledger + Clone + Sync> LocalBlockProvider<L> {
    pub fn new(ledger: L, watcher: impl Into<Option<WatcherDB>>) -> Box<Self> {
        Box::new(Self {
            ledger,
            watcher: watcher.into(),
        })
    }

    fn get_tx_out_result(
        &self,
        tx_out_pubkey: &CompressedRistrettoPublic,
    ) -> Result<TxOutResult, LedgerError> {
        let mut result = TxOutResult::new();
        result.set_tx_out_pubkey(tx_out_pubkey.into());

        let tx_out_index = match self.ledger.get_tx_out_index_by_public_key(tx_out_pubkey) {
            Ok(index) => index,
            Err(LedgerError::NotFound) => {
                result.result_code = TxOutResultCode::NotFound;
                return Ok(result);
            }
            Err(err) => {
                return Err(err);
            }
        };

        result.result_code = TxOutResultCode::Found;
        result.tx_out_global_index = tx_out_index;

        let block_index = match self.ledger.get_block_index_by_tx_out_index(tx_out_index) {
            Ok(index) => index,
            Err(_err) => {
                // TODO
                // log::error!(
                //     self.logger,
                //     "Unexpected error when getting block by tx out index {}: {}",
                //     tx_out_index,
                //     err
                // );
                result.result_code = TxOutResultCode::DatabaseError;
                return Ok(result);
            }
        };

        // Get the timestamp of the block_index if possible
        let (timestamp, ts_result): (u64, TimestampResultCode) = self
            .watcher
            .as_ref()
            .map(|watcher| match watcher.get_block_timestamp(block_index) {
                Ok((ts, res)) => (ts, res),
                Err(_err) => {
                    // TODO
                    // log::error!(
                    //     self.logger,
                    //     "Could not obtain timestamp for block {} due to error {:?}",
                    //     block_index,
                    //     err
                    // );
                    (u64::MAX, TimestampResultCode::WatcherDatabaseError)
                }
            })
            .unwrap_or_else(|| (u64::MAX, TimestampResultCode::Unavailable));

        result.block_index = block_index;
        result.timestamp = timestamp;
        result.timestamp_result_code = ts_result as u32;

        Ok(result)
    }
}

impl<L: Ledger + Clone + Sync> BlockProvider for LocalBlockProvider<L> {
    fn num_blocks(&self) -> Result<u64, Error> {
        Ok(self.ledger.num_blocks()?)
    }

    fn get_latest_block(&self) -> Result<Block, Error> {
        Ok(self.ledger.get_latest_block()?)
    }

    fn get_block_data(&self, block_index: BlockIndex) -> Result<BlockDataResponse, Error> {
        let block_data = self.ledger.get_block_data(block_index)?;
        let latest_block = self.ledger.get_latest_block()?;
        Ok(BlockDataResponse {
            block_data,
            latest_block,
        })
    }

    fn poll_block_timestamp(&self, block_index: BlockIndex, watcher_timeout: Duration) -> u64 {
        self.watcher
            .as_ref()
            .expect("poll_block_timestamp requires a watcher")
            .poll_block_timestamp(block_index, watcher_timeout)
    }

    fn get_tx_out_and_membership_proof_by_index(
        &self,
        tx_out_index: u64,
    ) -> Result<(TxOut, TxOutMembershipProof), Error> {
        Ok(self
            .ledger
            .get_tx_out_by_index(tx_out_index)
            .and_then(|tx_out| {
                let proofs = self
                    .ledger
                    .get_tx_out_proof_of_memberships(&[tx_out_index])?;
                Ok((tx_out, proofs[0].clone()))
            })?)
    }

    fn get_tx_out_info_by_public_key(
        &self,
        tx_out_pub_keys: &[CompressedRistrettoPublic],
    ) -> Result<TxOutInfoByPublicKeyResponse, Error> {
        let results = tx_out_pub_keys
            .iter()
            .map(|pk| self.get_tx_out_result(pk))
            .collect::<Result<Vec<_>, _>>()?;
        let latest_block = self.ledger.get_latest_block()?;

        Ok(TxOutInfoByPublicKeyResponse {
            results,
            latest_block,
        })
    }
}
