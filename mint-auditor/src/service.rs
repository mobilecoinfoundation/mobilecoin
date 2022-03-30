// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mint auditor GRPC service implementation.

use crate::{Error, MintAuditorDb};
use grpcio::{RpcContext, RpcStatus, RpcStatusCode, Service, UnarySink};
use mc_common::logger::Logger;
use mc_mint_auditor_api::{
    empty::Empty,
    mint_auditor::{
        GetBlockAuditDataRequest, GetBlockAuditDataResponse, GetLastBlockAuditDataResponse,
    },
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
                err => RpcStatus::with_message(RpcStatusCode::INTERNAL, err.to_string()),
            })
            .map(|block_audit_data| {
                let mut resp = GetBlockAuditDataResponse::new();
                resp.set_block_audit_data((&block_audit_data).into());
                resp
            });

        send_result(ctx, sink, result, &logger);
    }

    fn get_last_block_audit_data(
        &mut self,
        ctx: RpcContext,
        _req: Empty,
        sink: UnarySink<GetLastBlockAuditDataResponse>,
    ) {
        let logger = rpc_logger(&ctx, &self.logger);

        let last_synced_block_index = match self.mint_auditor_db.last_synced_block_index() {
            Ok(Some(block_index)) => block_index,
            Ok(None) => {
                return send_result(
                    ctx,
                    sink,
                    Err(RpcStatus::with_message(
                        RpcStatusCode::NOT_FOUND,
                        "No last synced block index".to_string(),
                    )),
                    &logger,
                );
            }
            Err(err) => {
                return send_result(
                    ctx,
                    sink,
                    Err(RpcStatus::with_message(
                        RpcStatusCode::INTERNAL,
                        err.to_string(),
                    )),
                    &logger,
                );
            }
        };

        let result = self
            .mint_auditor_db
            .get_block_audit_data(last_synced_block_index)
            .map_err(|err| match err {
                Error::NotFound => RpcStatus::with_message(
                    RpcStatusCode::NOT_FOUND,
                    format!(
                        "Block audit data not found for block index {}",
                        last_synced_block_index
                    ),
                ),
                err => RpcStatus::with_message(RpcStatusCode::INTERNAL, err.to_string()),
            })
            .map(|block_audit_data| {
                let mut resp = GetLastBlockAuditDataResponse::new();
                resp.set_block_audit_data((&block_audit_data).into());
                resp.set_block_index(last_synced_block_index);
                resp
            });

        send_result(ctx, sink, result, &logger);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grpcio::{ChannelBuilder, Environment, Server, ServerBuilder};
    use mc_account_keys::AccountKey;
    use mc_common::logger::{test_with_logger, Logger};
    use mc_ledger_db::Ledger;
    use mc_mint_auditor_api::{mint_auditor_grpc::MintAuditorApiClient, BlockAuditData};
    use mc_transaction_core::{Block, BlockContents, BlockVersion, TokenId};
    use mc_transaction_core_test_utils::{
        create_ledger, create_mint_config_tx_and_signers, create_mint_tx, create_test_tx_out,
        initialize_ledger,
    };
    use rand_core::SeedableRng;
    use rand_hc::Hc128Rng;
    use std::{collections::HashMap, iter::FromIterator, sync::Arc};
    use tempfile::tempdir;

    /// Starts the service on localhost and connects a client to it.
    fn get_client_server(
        mint_auditor_db: &MintAuditorDb,
        logger: &Logger,
    ) -> (MintAuditorApiClient, Server) {
        let service =
            MintAuditorService::new(mint_auditor_db.clone(), logger.clone()).into_service();
        let env = Arc::new(Environment::new(1));
        let mut server = ServerBuilder::new(env.clone())
            .register_service(service)
            .bind("127.0.0.1", 0)
            .build()
            .unwrap();
        server.start();
        let (_, port) = server.bind_addrs().next().unwrap();
        let ch = ChannelBuilder::new(env).connect(&format!("127.0.0.1:{}", port));
        let client = MintAuditorApiClient::new(ch);
        (client, server)
    }

    /// Create a test database with some data in it.
    fn get_test_db(logger: &Logger) -> MintAuditorDb {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);
        let token_id1 = TokenId::from(1);
        let token_id2 = TokenId::from(22);

        let mint_audit_db_path = tempdir().unwrap();
        let mint_audit_db =
            MintAuditorDb::create_or_open(&mint_audit_db_path, logger.clone()).unwrap();

        let mut ledger_db = create_ledger();
        let account_key = AccountKey::random(&mut rng);
        let num_initial_blocks = 1;
        initialize_ledger(
            BlockVersion::MAX,
            &mut ledger_db,
            num_initial_blocks,
            &account_key,
            &mut rng,
        );

        for block_index in 0..num_initial_blocks {
            let block_data = ledger_db.get_block_data(block_index).unwrap();

            mint_audit_db
                .sync_block(block_data.block(), block_data.contents())
                .unwrap();
        }

        // Sync a block that contains a few mint transactions.
        let (_mint_config_tx1, signers1) = create_mint_config_tx_and_signers(token_id1, &mut rng);
        let (_mint_config_tx2, signers2) = create_mint_config_tx_and_signers(token_id2, &mut rng);

        let mint_tx1 = create_mint_tx(token_id1, &signers1, 1, &mut rng);
        let mint_tx2 = create_mint_tx(token_id2, &signers2, 2, &mut rng);
        let mint_tx3 = create_mint_tx(token_id1, &signers1, 100, &mut rng);

        let block_contents = BlockContents {
            mint_txs: vec![mint_tx1, mint_tx2, mint_tx3],
            outputs: (0..3).map(|_i| create_test_tx_out(&mut rng)).collect(),
            ..Default::default()
        };

        let parent_block = ledger_db
            .get_block(ledger_db.num_blocks().unwrap() - 1)
            .unwrap();
        let block = Block::new_with_parent(
            BlockVersion::MAX,
            &parent_block,
            &Default::default(),
            &block_contents,
        );

        mint_audit_db.sync_block(&block, &block_contents).unwrap();
        mint_audit_db
    }

    #[test_with_logger]
    fn test_get_block_audit_data(logger: Logger) {
        let mint_audit_db = get_test_db(&logger);
        let (client, _server) = get_client_server(&mint_audit_db, &logger);

        let request = GetBlockAuditDataRequest {
            block_index: 1,
            ..Default::default()
        };

        let response = client.get_block_audit_data(&request).unwrap();

        assert_eq!(
            response,
            GetBlockAuditDataResponse {
                block_audit_data: Some(BlockAuditData {
                    balance_map: HashMap::from_iter([(1, 101), (22, 2)]),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }
        );
    }

    #[test_with_logger]
    fn test_get_last_block_audit_data(logger: Logger) {
        let mint_audit_db = get_test_db(&logger);
        let (client, _server) = get_client_server(&mint_audit_db, &logger);

        let response = client.get_last_block_audit_data(&Empty::default()).unwrap();

        assert_eq!(
            response,
            GetLastBlockAuditDataResponse {
                block_audit_data: Some(BlockAuditData {
                    balance_map: HashMap::from_iter([(1, 101), (22, 2)]),
                    ..Default::default()
                })
                .into(),
                block_index: 1,
                ..Default::default()
            }
        );
    }
}
