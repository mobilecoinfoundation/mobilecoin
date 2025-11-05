// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::SVC_COUNTERS;
use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_common::logger::Logger;
use mc_fog_api::fog_ledger::{BlockData, BlockRequest, BlockResponse, FogBlockApi};
use mc_fog_block_provider::{BlockProvider, BlocksDataResponse};
use mc_util_grpc::{
    check_request_chain_id, rpc_database_err, rpc_logger, send_result, Authenticator,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct BlockService {
    chain_id: String,
    block_provider: Box<dyn BlockProvider>,
    authenticator: Arc<dyn Authenticator + Send + Sync>,
    logger: Logger,
}

impl BlockService {
    pub fn new(
        chain_id: String,

        block_provider: Box<dyn BlockProvider>,
        authenticator: Arc<dyn Authenticator + Send + Sync>,
        logger: Logger,
    ) -> Self {
        Self {
            chain_id,
            block_provider,
            authenticator,
            logger,
        }
    }

    fn get_blocks_impl(&mut self, request: BlockRequest) -> Result<BlockResponse, RpcStatus> {
        mc_common::trace_time!(self.logger, "Get Blocks");

        let block_indices = request
            .ranges
            .iter()
            .flat_map(|range| range.start_block..range.end_block)
            .collect::<Vec<_>>();

        let BlocksDataResponse {
            results,
            latest_block,
        } = self
            .block_provider
            .get_blocks_data(block_indices.as_slice())
            .map_err(|err| rpc_database_err(err, &self.logger))?;

        Ok(BlockResponse {
            num_blocks: latest_block.index + 1,
            global_txo_count: latest_block.cumulative_txo_count,
            blocks: results
                .into_iter()
                .flatten()
                .map(|b| BlockData {
                    outputs: b
                        .block_data
                        .contents()
                        .outputs
                        .iter()
                        .map(Into::into)
                        .collect(),
                    global_txo_count: b.block_data.block().cumulative_txo_count,
                    timestamp: b.block_timestamp,
                    timestamp_result_code: b.block_timestamp_result_code as u32,
                    index: b.block_data.block().index,
                })
                .collect(),
        })
    }
}

impl FogBlockApi for BlockService {
    fn get_blocks(
        &mut self,
        ctx: RpcContext,
        request: BlockRequest,
        sink: UnarySink<BlockResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = check_request_chain_id(&self.chain_id, &ctx) {
                return send_result(ctx, sink, Err(err), logger);
            }

            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }

            send_result(ctx, sink, self.get_blocks_impl(request), logger)
        })
    }
}
