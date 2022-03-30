// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mint auditor GRPC service implementation.

use crate::{Error, MintAuditorDb};
use grpcio::{RpcContext, RpcStatus, RpcStatusCode, Service, UnarySink};
use mc_common::logger::Logger;
use mc_mint_auditor_api::{
    mint_auditor::{GetBlockAuditDataRequest, GetBlockAuditDataResponse},
    mint_auditor_grpc::{create_mint_auditor_api, MintAuditorApi},
};
use mc_util_grpc::{rpc_logger, send_result};

/// Mint auditor GRPC service implementation.
#[derive(Clone)]
pub struct MintAuditorService {
    /// Mint auditor database.
    mint_auditor_db: MintAuditorDb,

    /// Logger.
    logger: Logger,
}
impl MintAuditorService {
    /// Create a new mint auditor service.
    pub fn new(mint_auditor_db: MintAuditorDb, logger: Logger) -> Self {
        Self {
            mint_auditor_db,
            logger,
        }
    }

    /// Convert into a grpc service
    pub fn into_service(self) -> Service {
        create_mint_auditor_api(self)
    }
}

impl MintAuditorApi for MintAuditorService {
    fn get_block_audit_data(
        &mut self,
        ctx: RpcContext,
        req: GetBlockAuditDataRequest,
        sink: UnarySink<GetBlockAuditDataResponse>,
    ) {
        let logger = rpc_logger(&ctx, &self.logger);

        let result = self
            .mint_auditor_db
            .get_block_audit_data(req.get_block_index())
            .map_err(|err| match err {
                Error::NotFound => RpcStatus::with_message(
                    RpcStatusCode::NOT_FOUND,
                    format!(
                        "Block audit data not found for block index {}",
                        req.get_block_index()
                    ),
                ),
                err @ _ => RpcStatus::with_message(RpcStatusCode::INTERNAL, err.to_string()),
            })
            .map(|block_audit_data| {
                let mut resp = GetBlockAuditDataResponse::new();
                resp.set_block_audit_data((&block_audit_data).into());
                resp
            });

        send_result(ctx, sink, result, &logger);
    }
}
