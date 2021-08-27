// Copyright (c) 2018-2021 The MobileCoin Foundation

use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_common::logger::{log, Logger};
use mc_fog_api::{
    external,
    ledger::{BlockData, BlockRequest, BlockResponse},
    ledger_grpc::FogBlockApi,
};
use mc_ledger_db::{self, Error as DbError, Ledger};
use mc_util_grpc::{rpc_database_err, rpc_logger, send_result, Authenticator};
use mc_util_metrics::SVC_COUNTERS;
use mc_watcher::watcher_db::WatcherDB;
use mc_watcher_api::TimestampResultCode;
use std::sync::Arc;

#[derive(Clone)]
pub struct BlockService<L: Ledger + Clone> {
    ledger: L,
    watcher: WatcherDB,
    authenticator: Arc<dyn Authenticator + Send + Sync>,
    logger: Logger,
}

impl<L: Ledger + Clone> BlockService<L> {
    pub fn new(
        ledger: L,
        watcher: WatcherDB,
        authenticator: Arc<dyn Authenticator + Send + Sync>,
        logger: Logger,
    ) -> Self {
        Self {
            ledger,
            watcher,
            authenticator,
            logger,
        }
    }

    fn get_blocks_impl(&mut self, request: BlockRequest) -> Result<BlockResponse, RpcStatus> {
        mc_common::trace_time!(self.logger, "Get Blocks");

        let mut result = BlockResponse::new();

        result.num_blocks = self
            .ledger
            .num_blocks()
            .map_err(|err| rpc_database_err(err, &self.logger))?;
        result.global_txo_count = self
            .ledger
            .num_txos()
            .map_err(|err| rpc_database_err(err, &self.logger))?;

        for range in request.ranges.iter() {
            for block_idx in range.start_block..range.end_block {
                match self.get_block(block_idx) {
                    Ok(block) => result.blocks.push(block),
                    // TODO: signal internal error for some errors?
                    Err(err) => {
                        log::error!(self.logger, "DbError getting block {}: {}", block_idx, err)
                    }
                };
            }
        }

        Ok(result)
    }

    fn get_block(&mut self, block_index: u64) -> Result<BlockData, DbError> {
        let mut result = BlockData::new();
        let block_contents = self.ledger.get_block_contents(block_index)?;
        let block = self.ledger.get_block(block_index)?;
        for output in block_contents.outputs {
            result.outputs.push(external::TxOut::from(&output));
        }
        result.index = block_index;
        result.global_txo_count = block.cumulative_txo_count;

        // Get the timestamp of the block_index if possible
        let (timestamp, ts_result): (u64, TimestampResultCode) =
            match self.watcher.get_block_timestamp(block_index) {
                Ok((ts, res)) => (ts, res),
                Err(err) => {
                    log::error!(
                        self.logger,
                        "Could not obtain timestamp for block {} due to error {:?}",
                        block_index,
                        err
                    );
                    (u64::MAX, TimestampResultCode::WatcherDatabaseError)
                }
            };

        result.timestamp = timestamp;
        result.timestamp_result_code = ts_result as u32;

        Ok(result)
    }
}

impl<L: Ledger + Clone> FogBlockApi for BlockService<L> {
    fn get_blocks(
        &mut self,
        ctx: RpcContext,
        request: BlockRequest,
        sink: UnarySink<BlockResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), &logger);
            }

            send_result(ctx, sink, self.get_blocks_impl(request), &logger)
        })
    }
}
