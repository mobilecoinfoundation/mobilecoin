// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Serves blockchain-related API requests.

use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink};
use mc_common::logger::{log, Logger};
use mc_consensus_api::{
    blockchain,
    consensus_common::{BlocksRequest, BlocksResponse, LastBlockInfoResponse},
    consensus_common_grpc::BlockchainApi,
    empty::Empty,
};
use mc_ledger_db::Ledger;
use mc_transaction_core::constants::MINIMUM_FEE;
use mc_util_grpc::{rpc_logger, send_result, Authenticator};
use mc_util_metrics::{self, SVC_COUNTERS};
use protobuf::RepeatedField;
use std::{cmp, convert::From, sync::Arc};

#[derive(Clone)]
pub struct BlockchainApiService<L: Ledger + Clone> {
    /// Ledger Database.
    ledger: L,

    /// GRPC request authenticator.
    authenticator: Arc<dyn Authenticator + Send + Sync>,

    /// Maximal number of results to return in API calls that return multiple
    /// results.
    max_page_size: u16,

    /// Logger.
    logger: Logger,

    /// Configured minimum-fee
    minimum_fee: Option<u64>,
}

impl<L: Ledger + Clone> BlockchainApiService<L> {
    pub fn new(
        ledger: L,
        authenticator: Arc<dyn Authenticator + Send + Sync>,
        logger: Logger,
        minimum_fee: Option<u64>,
    ) -> Self {
        BlockchainApiService {
            ledger,
            authenticator,
            max_page_size: 2000,
            logger,
            minimum_fee,
        }
    }

    // Set the maximum number of items returned for a single request.
    #[allow(dead_code)]
    pub fn set_max_page_size(&mut self, max_page_size: u16) {
        self.max_page_size = max_page_size;
    }

    /// Returns information about the last block.
    fn get_last_block_info_helper(&mut self) -> Result<LastBlockInfoResponse, mc_ledger_db::Error> {
        let num_blocks = self.ledger.num_blocks()?;
        let mut resp = LastBlockInfoResponse::new();
        resp.set_index(num_blocks - 1);
        resp.set_minimum_fee(self.minimum_fee.unwrap_or(MINIMUM_FEE));

        Ok(resp)
    }

    /// Returns blocks in the range [offset, offset + limit).
    ///
    /// If `limit` exceeds `max_page_size`, then only [offset, offset +
    /// max_page_size) is returned. If `limit` exceeds the maximum index in
    /// the database, then only [offset, max_index] is returned. This method
    /// is a hack to expose the `get_blocks` implementation for unit testing.
    fn get_blocks_helper(&mut self, offset: u64, limit: u32) -> Result<BlocksResponse, ()> {
        let start_index = offset;
        let end_index = offset + cmp::min(limit, self.max_page_size as u32) as u64;

        // Get "persistence type" blocks.
        let mut block_entities: Vec<mc_transaction_core::Block> = vec![];
        for block_index in start_index..end_index {
            match self.ledger.get_block(block_index as u64) {
                Ok(block) => block_entities.push(block),
                Err(mc_ledger_db::Error::NotFound) => {
                    // This is okay - it means we have reached the last block in the ledger in the
                    // previous loop iteration.
                    break;
                }
                Err(error) => {
                    log::error!(
                        self.logger,
                        "Error getting block {}: {:?}",
                        block_index,
                        error
                    );
                    break;
                }
            }
        }

        // Convert to "API type" blocks.
        let blocks: Vec<blockchain::Block> = block_entities
            .into_iter()
            .map(|block| blockchain::Block::from(&block))
            .collect();

        let mut response = BlocksResponse::new();
        response.set_blocks(RepeatedField::from_vec(blocks));
        Ok(response)
    }
}

impl<L: Ledger + Clone> BlockchainApi for BlockchainApiService<L> {
    /// Gets the last block.
    fn get_last_block_info(
        &mut self,
        ctx: RpcContext,
        _request: Empty,
        sink: UnarySink<LastBlockInfoResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);

        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), &logger);
            }

            let resp = self
                .get_last_block_info_helper()
                .map_err(|_| RpcStatus::new(RpcStatusCode::INTERNAL));
            send_result(ctx, sink, resp, &logger);
        });
    }

    /// Gets a range [offset, offset+limit) of Blocks.
    fn get_blocks(
        &mut self,
        ctx: RpcContext,
        request: BlocksRequest,
        sink: UnarySink<BlocksResponse>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);

        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), &logger);
            }

            log::trace!(
                logger,
                "Received BlocksRequest for offset {} and limit {})",
                request.offset,
                request.limit
            );

            let resp = self
                .get_blocks_helper(request.offset, request.limit)
                .map_err(|_| RpcStatus::new(RpcStatusCode::INTERNAL));
            send_result(ctx, sink, resp, &logger);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grpcio::{ChannelBuilder, Environment, Error as GrpcError, Server, ServerBuilder};
    use mc_common::{logger::test_with_logger, time::SystemTimeProvider};
    use mc_consensus_api::consensus_common_grpc::{self, BlockchainApiClient};
    use mc_transaction_core_test_utils::{create_ledger, initialize_ledger, AccountKey};
    use mc_util_grpc::{AnonymousAuthenticator, TokenAuthenticator};
    use rand::{rngs::StdRng, SeedableRng};
    use std::{
        sync::atomic::{AtomicUsize, Ordering::SeqCst},
        time::Duration,
    };

    fn get_free_port() -> u16 {
        static PORT_NR: AtomicUsize = AtomicUsize::new(0);
        PORT_NR.fetch_add(1, SeqCst) as u16 + 30200
    }

    /// Starts the service on localhost and connects a client to it.
    fn get_client_server<L: Ledger + Clone + 'static>(
        instance: BlockchainApiService<L>,
    ) -> (BlockchainApiClient, Server) {
        let service = consensus_common_grpc::create_blockchain_api(instance);
        let env = Arc::new(Environment::new(1));
        let mut server = ServerBuilder::new(env.clone())
            .register_service(service)
            .bind("127.0.0.1", get_free_port())
            .build()
            .unwrap();
        server.start();
        let (_, port) = server.bind_addrs().next().unwrap();
        let ch = ChannelBuilder::new(env).connect(&format!("127.0.0.1:{}", port));
        let client = BlockchainApiClient::new(ch);
        (client, server)
    }

    #[test_with_logger]
    // `get_last_block_info` should returns the last block.
    fn test_get_last_block_info(logger: Logger) {
        let mut ledger_db = create_ledger();
        let authenticator = Arc::new(AnonymousAuthenticator::default());
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let account_key = AccountKey::random(&mut rng);
        let block_entities = initialize_ledger(&mut ledger_db, 10, &account_key, &mut rng);
        let minimum_fee = 10_000;

        let mut expected_response = LastBlockInfoResponse::new();
        expected_response.set_index(block_entities.last().unwrap().index);
        expected_response.set_minimum_fee(minimum_fee);
        assert_eq!(
            block_entities.last().unwrap().index,
            ledger_db.num_blocks().unwrap() - 1
        );

        let mut blockchain_api_service =
            BlockchainApiService::new(ledger_db, authenticator, logger, Some(minimum_fee));

        let block_response = blockchain_api_service.get_last_block_info_helper().unwrap();
        assert_eq!(block_response, expected_response);
    }

    #[test_with_logger]
    // `get_last_block_info` should reject unauthenticated responses when configured
    // with an authenticator.
    fn test_get_last_block_info_rejects_unauthenticated(logger: Logger) {
        let ledger_db = create_ledger();
        let authenticator = Arc::new(TokenAuthenticator::new(
            [1; 32],
            Duration::from_secs(60),
            SystemTimeProvider::default(),
        ));

        let blockchain_api_service =
            BlockchainApiService::new(ledger_db, authenticator, logger, None);

        let (client, _server) = get_client_server(blockchain_api_service);

        match client.get_last_block_info(&Empty::default()) {
            Ok(response) => {
                panic!("Unexpected response {:?}", response);
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAUTHENTICATED);
            }
            Err(err @ _) => {
                panic!("Unexpected error {:?}", err);
            }
        }
    }

    #[test_with_logger]
    // `get_blocks` should returns the correct range of blocks.
    fn test_get_blocks_response_range(logger: Logger) {
        let mut ledger_db = create_ledger();
        let authenticator = Arc::new(AnonymousAuthenticator::default());
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let account_key = AccountKey::random(&mut rng);
        let block_entities = initialize_ledger(&mut ledger_db, 10, &account_key, &mut rng);

        let expected_blocks: Vec<blockchain::Block> = block_entities
            .into_iter()
            .map(|block_entity| blockchain::Block::from(&block_entity))
            .collect();

        let mut blockchain_api_service =
            BlockchainApiService::new(ledger_db, authenticator, logger, None);

        {
            // The empty range [0,0) should return an empty collection of Blocks.
            let block_response = blockchain_api_service.get_blocks_helper(0, 0).unwrap();
            assert_eq!(0, block_response.blocks.len());
        }

        {
            // The singleton range [0,1) should return a single Block.
            let block_response = blockchain_api_service.get_blocks_helper(0, 1).unwrap();
            let blocks = block_response.blocks;
            assert_eq!(1, blocks.len());
            assert_eq!(expected_blocks.get(0).unwrap(), blocks.get(0).unwrap());
        }

        {
            // The range [0,10) should return 10 Blocks.
            let block_response = blockchain_api_service.get_blocks_helper(0, 10).unwrap();
            let blocks = block_response.blocks;
            assert_eq!(10, blocks.len());
            assert_eq!(expected_blocks.get(0).unwrap(), blocks.get(0).unwrap());
            assert_eq!(expected_blocks.get(7).unwrap(), blocks.get(7).unwrap());
            assert_eq!(expected_blocks.get(9).unwrap(), blocks.get(9).unwrap());
        }
    }

    #[test_with_logger]
    // `get_blocks` should return the intersection of the request with the available
    // data if a client requests data that does not exist.
    fn test_get_blocks_request_out_of_bounds(logger: Logger) {
        let mut ledger_db = create_ledger();
        let authenticator = Arc::new(AnonymousAuthenticator::default());
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let account_key = AccountKey::random(&mut rng);
        let _blocks = initialize_ledger(&mut ledger_db, 10, &account_key, &mut rng);

        let mut blockchain_api_service =
            BlockchainApiService::new(ledger_db, authenticator, logger, None);

        {
            // The range [0, 1000) requests values that don't exist. The response should
            // contain [0,10).
            let block_response = blockchain_api_service.get_blocks_helper(0, 1000).unwrap();
            assert_eq!(10, block_response.blocks.len());
        }
    }

    #[test_with_logger]
    // `get_blocks` should only return the "maximum" number of items if the
    // requested range is larger.
    fn test_get_blocks_max_size(logger: Logger) {
        let mut ledger_db = create_ledger();
        let authenticator = Arc::new(AnonymousAuthenticator::default());
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let account_key = AccountKey::random(&mut rng);
        let block_entities = initialize_ledger(&mut ledger_db, 10, &account_key, &mut rng);

        let expected_blocks: Vec<blockchain::Block> = block_entities
            .into_iter()
            .map(|block_entity| blockchain::Block::from(&block_entity))
            .collect();

        let mut blockchain_api_service =
            BlockchainApiService::new(ledger_db, authenticator, logger, None);
        blockchain_api_service.set_max_page_size(5);

        // The request exceeds the max_page_size, so only max_page_size items should be
        // returned.
        let block_response = blockchain_api_service.get_blocks_helper(0, 100).unwrap();
        let blocks = block_response.blocks;
        assert_eq!(5, blocks.len());
        assert_eq!(expected_blocks.get(0).unwrap(), blocks.get(0).unwrap());
        assert_eq!(expected_blocks.get(4).unwrap(), blocks.get(4).unwrap());
    }

    #[test_with_logger]
    // `get_blocks` should reject unauthenticated responses when configured with an
    // authenticator.
    fn test_get_blocks_rejects_unauthenticated(logger: Logger) {
        let ledger_db = create_ledger();
        let authenticator = Arc::new(TokenAuthenticator::new(
            [1; 32],
            Duration::from_secs(60),
            SystemTimeProvider::default(),
        ));

        let blockchain_api_service =
            BlockchainApiService::new(ledger_db, authenticator, logger, None);

        let (client, _server) = get_client_server(blockchain_api_service);

        match client.get_blocks(&BlocksRequest::default()) {
            Ok(response) => {
                panic!("Unexpected response {:?}", response);
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAUTHENTICATED);
            }
            Err(err @ _) => {
                panic!("Unexpected error {:?}", err);
            }
        }
    }
}
