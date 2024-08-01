// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::SVC_COUNTERS;
use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_common::logger::Logger;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::{
    ledger::{TxOutRequest, TxOutResponse},
    ledger_grpc::FogUntrustedTxOutApi,
};
use mc_fog_block_provider::{BlockProvider, TxOutInfoByPublicKeyResponse};
use mc_util_grpc::{
    check_request_chain_id, rpc_internal_error, rpc_invalid_arg_error, rpc_logger, send_result,
    Authenticator,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct UntrustedTxOutService {
    chain_id: String,
    block_provider: Box<dyn BlockProvider>,
    authenticator: Arc<dyn Authenticator + Send + Sync>,
    logger: Logger,
}

impl UntrustedTxOutService {
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

    fn get_tx_outs_impl(&mut self, request: TxOutRequest) -> Result<TxOutResponse, RpcStatus> {
        mc_common::trace_time!(self.logger, "Get Blocks");

        let tx_out_pub_keys = request
            .tx_out_pubkeys
            .iter()
            .map(CompressedRistrettoPublic::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| rpc_invalid_arg_error("tx_out_pubkey", err, &self.logger))?;

        let TxOutInfoByPublicKeyResponse {
            results,
            latest_block,
        } = self
            .block_provider
            .get_tx_out_info_by_public_key(tx_out_pub_keys.as_slice())
            .map_err(|err| {
                rpc_internal_error("get_tX_out_info_by_public_key", err, &self.logger)
            })?;

        let mut response = TxOutResponse::new();

        response.num_blocks = latest_block.index + 1;
        response.global_txo_count = latest_block.cumulative_txo_count;
        response.results = results.into();

        Ok(response)
    }
}

impl FogUntrustedTxOutApi for UntrustedTxOutService {
    fn get_tx_outs(
        &mut self,
        ctx: RpcContext,
        request: TxOutRequest,
        sink: UnarySink<TxOutResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = check_request_chain_id(&self.chain_id, &ctx) {
                return send_result(ctx, sink, Err(err), logger);
            }

            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }

            send_result(ctx, sink, self.get_tx_outs_impl(request), logger)
        })
    }
}
