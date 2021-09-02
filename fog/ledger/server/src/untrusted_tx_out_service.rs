// Copyright (c) 2018-2021 The MobileCoin Foundation

use core::convert::TryFrom;

use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_common::logger::{log, Logger};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::{
    ledger::{TxOutRequest, TxOutResponse, TxOutResult, TxOutResultCode},
    ledger_grpc::FogUntrustedTxOutApi,
};
use mc_ledger_db::{self, Error as DbError, Ledger};
use mc_util_grpc::{rpc_internal_error, rpc_logger, send_result, Authenticator};
use mc_util_metrics::SVC_COUNTERS;
use mc_watcher::watcher_db::WatcherDB;
use mc_watcher_api::TimestampResultCode;
use std::sync::Arc;

#[derive(Clone)]
pub struct UntrustedTxOutService<L: Ledger + Clone> {
    ledger: L,
    watcher: WatcherDB,
    authenticator: Arc<dyn Authenticator + Send + Sync>,
    logger: Logger,
}

impl<L: Ledger + Clone> UntrustedTxOutService<L> {
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

    fn get_tx_outs_impl(&mut self, request: TxOutRequest) -> Result<TxOutResponse, RpcStatus> {
        mc_common::trace_time!(self.logger, "Get Blocks");

        let mut response = TxOutResponse::new();

        response.num_blocks = self
            .ledger
            .num_blocks()
            .map_err(|err| rpc_internal_error("Database error", err, &self.logger))?;
        response.global_txo_count = self
            .ledger
            .num_txos()
            .map_err(|err| rpc_internal_error("Database error", err, &self.logger))?;

        for tx_out_pubkey_proto in request.tx_out_pubkeys.iter() {
            response.results.push(
                match CompressedRistrettoPublic::try_from(tx_out_pubkey_proto) {
                    Ok(tx_out_pubkey) => match self.get_tx_out(&tx_out_pubkey) {
                        Ok(result) => result,
                        Err(err) => {
                            log::error!(
                                self.logger,
                                "DbError getting tx_out {}: {}",
                                tx_out_pubkey,
                                err
                            );
                            let mut result = TxOutResult::new();
                            result.set_tx_out_pubkey(tx_out_pubkey_proto.clone());
                            result.result_code = TxOutResultCode::DatabaseError;
                            result
                        }
                    },
                    Err(err) => {
                        log::error!(
                            self.logger,
                            "Request was not a valid pubkey {:?}: {}",
                            tx_out_pubkey_proto,
                            err
                        );
                        let mut result = TxOutResult::new();
                        result.set_tx_out_pubkey(tx_out_pubkey_proto.clone());
                        result.result_code = TxOutResultCode::MalformedRequest;
                        result
                    }
                },
            )
        }

        Ok(response)
    }

    fn get_tx_out(
        &mut self,
        tx_out_pubkey: &CompressedRistrettoPublic,
    ) -> Result<TxOutResult, DbError> {
        let mut result = TxOutResult::new();
        result.set_tx_out_pubkey(tx_out_pubkey.into());

        let tx_out_index = match self.ledger.get_tx_out_index_by_public_key(tx_out_pubkey) {
            Ok(index) => index,
            Err(DbError::NotFound) => {
                result.result_code = TxOutResultCode::NotFound;
                return Ok(result);
            }
            Err(err) => {
                return Err(err);
            }
        };

        result.result_code = TxOutResultCode::Found;
        result.tx_out_global_index = tx_out_index;

        let block_index = self
            .ledger
            .get_block_index_by_tx_out_index(tx_out_index)
            .map_err(|err| {
                log::error!(
                    self.logger,
                    "Unexpected error when getting block by tx out index {}: {}",
                    tx_out_index,
                    err
                );
                err
            })?;

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

        result.block_index = block_index;
        result.timestamp = timestamp;
        result.timestamp_result_code = ts_result as u32;

        Ok(result)
    }
}

impl<L: Ledger + Clone> FogUntrustedTxOutApi for UntrustedTxOutService<L> {
    fn get_tx_outs(
        &mut self,
        ctx: RpcContext,
        request: TxOutRequest,
        sink: UnarySink<TxOutResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), &logger);
            }

            send_result(ctx, sink, self.get_tx_outs_impl(request), &logger)
        })
    }
}
