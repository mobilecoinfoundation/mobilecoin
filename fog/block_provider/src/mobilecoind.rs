// Copyright (c) 2018-2023 The MobileCoin Foundation

use crate::{
    BlockDataWithTimestamp, BlockProvider, BlocksDataResponse, Error, TxOutInfoByPublicKeyResponse,
};
use grpcio::{ChannelBuilder, EnvBuilder};
use mc_api::watcher::TimestampResultCode;
use mc_blockchain_types::{Block, BlockData, BlockIndex};
use mc_common::logger::{log, Logger};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_mobilecoind_api::{
    mobilecoind_api_grpc::MobilecoindApiClient, GetBlockRequest, GetBlocksDataRequest,
    MobilecoindUri,
};
use mc_transaction_core::tx::{TxOut, TxOutMembershipProof};
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_watcher::watcher_db::{POLL_BLOCK_TIMESTAMP_POLLING_FREQUENCY, POLL_BLOCK_TIMESTAMP_ERROR_RETRY_FREQUENCY};
use std::{
    sync::Arc,
    thread::sleep,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct MobilecoindBlockProvider {
    client: MobilecoindApiClient,
    logger: Logger,
}

impl MobilecoindBlockProvider {
    pub fn new(mobilecoind_uri: &MobilecoindUri, logger: &Logger) -> Box<Self> {
        let env = Arc::new(EnvBuilder::new().name_prefix("Mobilecoind-GRPC").build());
        let ch = ChannelBuilder::new(env)
            .max_receive_message_len(std::i32::MAX)
            .max_send_message_len(std::i32::MAX)
            .connect_to_uri(mobilecoind_uri, logger);

        let client = MobilecoindApiClient::new(ch);

        Box::new(Self {
            client,
            logger: logger.clone(),
        })
    }
}

impl BlockProvider for MobilecoindBlockProvider {
    fn num_blocks(&self) -> Result<u64, Error> {
        let response = self.client.get_ledger_info(&Default::default())?;
        Ok(response.block_count)
    }

    /// Get the latest block in the ledger.
    fn get_latest_block(&self) -> Result<Block, Error> {
        let response = self.client.get_latest_block(&Default::default())?;
        Ok(response.get_block().try_into()?)
    }

    /// Get block data of multiple blocks by block number, and in addition get
    /// information about the latest block. Also include block timestamp for
    /// each block, if available.
    fn get_blocks_data(&self, block_indices: &[BlockIndex]) -> Result<BlocksDataResponse, Error> {
        let request = GetBlocksDataRequest {
            blocks: block_indices.to_vec().into(),
            ..Default::default()
        };
        let response = self.client.get_blocks_data(&request)?;

        let results = response
            .results
            .iter()
            .map(|result| {
                if !result.found {
                    return Ok(None);
                }

                Ok(Some(BlockDataWithTimestamp {
                    block_data: BlockData::try_from(result.get_block_data())?,
                    block_timestamp: result.timestamp,
                    block_timestamp_result_code: (&result.timestamp_result_code).try_into()?,
                }))
            })
            .collect::<Result<Vec<_>, Error>>()?
            .into();

        let latest_block = Block::try_from(response.get_latest_block())?;

        Ok(BlocksDataResponse {
            results,
            latest_block,
        })
    }

    /// Poll indefinitely for a watcher timestamp, logging warnings if we wait
    /// for more than watcher_timeout.
    fn poll_block_timestamp(&self, block_index: BlockIndex, watcher_timeout: Duration) -> u64 {
        // special case the origin block has a timestamp of u64::MAX
        if block_index == 0 {
            return u64::MAX;
        }

        let request = GetBlockRequest {
            block: block_index,
            ..Default::default()
        };

        // Timer that tracks how long we have had WatcherBehind error for,
        // if this exceeds watcher_timeout, we log a warning.
        let mut watcher_behind_timer = Instant::now();
        loop {
            match self.client.get_block(&request) {
                Ok(response) => match response.timestamp_result_code {
                    TimestampResultCode::WatcherBehind => {
                        if watcher_behind_timer.elapsed() > watcher_timeout {
                            log::warn!(self.logger, "watcher is still behind on block index = {} after waiting {} seconds, caller will be blocked", block_index, watcher_timeout.as_secs());
                            watcher_behind_timer = Instant::now();
                        }
                        sleep(POLL_BLOCK_TIMESTAMP_POLLING_FREQUENCY);
                    }
                    TimestampResultCode::BlockIndexOutOfBounds => {
                        log::warn!(self.logger, "block index {} was out of bounds, we should not be scanning it, we will have junk timestamps for it", block_index);
                        return u64::MAX;
                    }
                    TimestampResultCode::Unavailable => {
                        log::crit!(self.logger, "watcher configuration is wrong and timestamps will not be available with this configuration. caller is blocked at block index {}", block_index);
                        sleep(POLL_BLOCK_TIMESTAMP_ERROR_RETRY_FREQUENCY);
                    }
                    TimestampResultCode::WatcherDatabaseError => {
                        log::crit!(self.logger, "The watcher database has an error which prevents us from getting timestamps. caller is blocked at block index {}", block_index);
                        sleep(POLL_BLOCK_TIMESTAMP_ERROR_RETRY_FREQUENCY);
                    }
                    TimestampResultCode::TimestampFound => {
                        return response.timestamp;
                    }
                    other => {
                        log::crit!(
                            self.logger,
                            "Unexpected result code {:?} for block index {}",
                            other,
                            block_index
                        );
                        sleep(POLL_BLOCK_TIMESTAMP_ERROR_RETRY_FREQUENCY);
                    }
                },
                Err(err) => {
                    log::error!(
                            self.logger,
                            "Could not obtain timestamp for block {} due to error {}, this may mean the watcher is not correctly configured. will retry",
                            block_index,
                            err
                        );
                    sleep(POLL_BLOCK_TIMESTAMP_ERROR_RETRY_FREQUENCY);
                }
            };
        }
    }

    /// Get TxOut and membership proof by tx out index.
    fn get_tx_out_and_membership_proof_by_index(
        &self,
        _tx_out_index: u64,
    ) -> Result<(TxOut, TxOutMembershipProof), Error> {
        todo!()
    }

    /// Get information about multiple TxOuts by their public keys, and in
    /// addition get information about the latest block.
    fn get_tx_out_info_by_public_key(
        &self,
        _tx_out_pub_keys: &[CompressedRistrettoPublic],
    ) -> Result<TxOutInfoByPublicKeyResponse, Error> {
        todo!()
    }
}
