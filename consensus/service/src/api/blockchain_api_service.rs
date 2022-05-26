// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Serves blockchain-related API requests.

use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink};
use mc_common::logger::{log, Logger};
use mc_consensus_api::{
    blockchain,
    consensus_common::{BlocksRequest, BlocksResponse, LastBlockInfoResponse},
    consensus_common_grpc::BlockchainApi,
    empty::Empty,
};
use mc_consensus_enclave::FeeMap;
use mc_ledger_db::Ledger;
use mc_transaction_core::{tokens::Mob, BlockVersion, Token};
use mc_util_grpc::{rpc_logger, send_result, Authenticator};
use mc_util_metrics::{self, SVC_COUNTERS};
use protobuf::RepeatedField;
use std::{cmp, collections::HashMap, sync::Arc};

#[derive(Clone)]
pub struct BlockchainApiService<L: Ledger + Clone> {
    /// Ledger Database.
    ledger: L,

    /// GRPC request authenticator.
    authenticator: Arc<dyn Authenticator + Send + Sync>,

    /// Maximal number of results to return in API calls that return multiple
    /// results.
    max_page_size: u16,

    /// Minimum fee per token.
    fee_map: FeeMap,

    /// Configured block version
    network_block_version: BlockVersion,

    /// Logger.
    logger: Logger,
}

impl<L: Ledger + Clone> BlockchainApiService<L> {
    pub fn new(
        ledger: L,
        authenticator: Arc<dyn Authenticator + Send + Sync>,
        fee_map: FeeMap,
        network_block_version: BlockVersion,
        logger: Logger,
    ) -> Self {
        BlockchainApiService {
            ledger,
            authenticator,
            max_page_size: 2000,
            fee_map,
            network_block_version,
            logger,
        }
    }

    // Set the maximum number of items returned for a single request.
    #[cfg(test)]
    pub fn set_max_page_size(&mut self, max_page_size: u16) {
        self.max_page_size = max_page_size;
    }

    /// Returns information about the last block.
    fn get_last_block_info_helper(&mut self) -> Result<LastBlockInfoResponse, mc_ledger_db::Error> {
        let num_blocks = self.ledger.num_blocks()?;
        let mut resp = LastBlockInfoResponse::new();
        resp.set_index(num_blocks - 1);
        resp.set_mob_minimum_fee(
            self.fee_map
                .get_fee_for_token(&Mob::ID)
                .expect("should always have a fee for MOB"),
        );
        resp.set_minimum_fees(HashMap::from_iter(
            self.fee_map
                .iter()
                .map(|(token_id, fee)| (**token_id, *fee)),
        ));
        resp.set_network_block_version(*self.network_block_version);

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
        let mut block_entities: Vec<mc_blockchain_types::Block> = vec![];
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
                return send_result(ctx, sink, err.into(), logger);
            }

            let resp = self
                .get_last_block_info_helper()
                .map_err(|_| RpcStatus::new(RpcStatusCode::INTERNAL));
            send_result(ctx, sink, resp, logger);
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
                return send_result(ctx, sink, err.into(), logger);
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
            send_result(ctx, sink, resp, logger);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grpcio::{ChannelBuilder, Environment, Error as GrpcError, Server, ServerBuilder};
    use mc_common::{logger::test_with_logger, time::SystemTimeProvider};
    use mc_consensus_api::consensus_common_grpc::{self, BlockchainApiClient};
    use mc_ledger_db::test_utils::{create_ledger, initialize_ledger};
    use mc_transaction_core::TokenId;
    use mc_transaction_core_test_utils::AccountKey;
    use mc_util_grpc::{AnonymousAuthenticator, TokenAuthenticator};
    use rand::{rngs::StdRng, SeedableRng};
    use std::{collections::HashMap, time::Duration};

    /// Starts the service on localhost and connects a client to it.
    fn get_client_server<L: Ledger + Clone + 'static>(
        instance: BlockchainApiService<L>,
    ) -> (BlockchainApiClient, Server) {
        let service = consensus_common_grpc::create_blockchain_api(instance);
        let env = Arc::new(Environment::new(1));
        let mut server = ServerBuilder::new(env.clone())
            .register_service(service)
            .bind("127.0.0.1", 0)
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
        let fee_map =
            FeeMap::try_from_iter([(Mob::ID, 4000000000), (TokenId::from(60), 128000)]).unwrap();

        let mut ledger_db = create_ledger();
        let authenticator = Arc::new(AnonymousAuthenticator::default());
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let account_key = AccountKey::random(&mut rng);
        let block_entities = initialize_ledger(
            BlockVersion::MAX,
            &mut ledger_db,
            10,
            &account_key,
            &mut rng,
        );
        let last_index = block_entities.last().unwrap().block().index;

        let mut expected_response = LastBlockInfoResponse::new();
        expected_response.set_index(last_index);
        expected_response.set_mob_minimum_fee(4000000000);
        expected_response.set_minimum_fees(HashMap::from_iter(vec![(0, 4000000000), (60, 128000)]));
        expected_response.set_network_block_version(*BlockVersion::MAX);
        assert_eq!(last_index + 1, ledger_db.num_blocks().unwrap());

        let mut blockchain_api_service =
            BlockchainApiService::new(ledger_db, authenticator, fee_map, BlockVersion::MAX, logger);

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

        let blockchain_api_service = BlockchainApiService::new(
            ledger_db,
            authenticator,
            FeeMap::default(),
            BlockVersion::MAX,
            logger,
        );

        let (client, _server) = get_client_server(blockchain_api_service);

        match client.get_last_block_info(&Empty::default()) {
            Ok(response) => {
                panic!("Unexpected response {:?}", response);
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAUTHENTICATED);
            }
            Err(err) => {
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
        let expected_blocks = initialize_ledger(
            BlockVersion::MAX,
            &mut ledger_db,
            10,
            &account_key,
            &mut rng,
        )
        .into_iter()
        .map(|block_data| blockchain::Block::from(block_data.block()))
        .collect::<Vec<_>>();

        let mut blockchain_api_service = BlockchainApiService::new(
            ledger_db,
            authenticator,
            FeeMap::default(),
            BlockVersion::MAX,
            logger,
        );

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
        let _blocks = initialize_ledger(
            BlockVersion::MAX,
            &mut ledger_db,
            10,
            &account_key,
            &mut rng,
        );

        let mut blockchain_api_service = BlockchainApiService::new(
            ledger_db,
            authenticator,
            FeeMap::default(),
            BlockVersion::MAX,
            logger,
        );

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
        let expected_blocks = initialize_ledger(
            BlockVersion::MAX,
            &mut ledger_db,
            10,
            &account_key,
            &mut rng,
        )
        .into_iter()
        .map(|block_data| blockchain::Block::from(block_data.block()))
        .collect::<Vec<_>>();

        let mut blockchain_api_service = BlockchainApiService::new(
            ledger_db,
            authenticator,
            FeeMap::default(),
            BlockVersion::MAX,
            logger,
        );
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

        let blockchain_api_service = BlockchainApiService::new(
            ledger_db,
            authenticator,
            FeeMap::default(),
            BlockVersion::MAX,
            logger,
        );

        let (client, _server) = get_client_server(blockchain_api_service);

        match client.get_blocks(&BlocksRequest::default()) {
            Ok(response) => {
                panic!("Unexpected response {:?}", response);
            }
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(rpc_status.code(), RpcStatusCode::UNAUTHENTICATED);
            }
            Err(err) => {
                panic!("Unexpected error {:?}", err);
            }
        }
    }
}
