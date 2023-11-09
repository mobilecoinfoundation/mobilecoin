// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::SVC_COUNTERS;
use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_common::logger::Logger;
use mc_fog_api::{
    external,
    ledger::{BlockData, BlockRequest, BlockResponse},
    ledger_grpc::FogBlockApi,
};
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

        let mut response = BlockResponse::new();
        response.num_blocks = latest_block.index + 1;
        response.global_txo_count = latest_block.cumulative_txo_count;

        response.blocks = results
            .into_iter()
            .flatten()
            .map(|b| {
                let mut result = BlockData::new();
                for output in b.block_data.contents().outputs.iter() {
                    result.outputs.push(external::TxOut::from(output));
                }
                result.index = b.block_data.block().index;
                result.global_txo_count = b.block_data.block().cumulative_txo_count;
                result.timestamp = b.block_timestamp;
                result.timestamp_result_code = b.block_timestamp_result_code as u32;
                result
            })
            .collect();

        Ok(response)
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
