// Copyright (c) 2018-2020 MobileCoin Inc.

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
use mc_util_grpc::{rpc_logger, send_result};
use mc_util_metrics::{self, SVC_COUNTERS};
use protobuf::RepeatedField;
use std::{cmp, convert::From};

#[derive(Clone)]
pub struct BlockchainApiService<L: Ledger + Clone> {
    /// Ledger Database.
    ledger: L,

    /// Maximal number of results to return in API calls that return multiple results.
    max_page_size: u16,

    /// Logger.
    logger: Logger,
}

impl<L: Ledger + Clone> BlockchainApiService<L> {
    pub fn new(ledger: L, logger: Logger) -> Self {
        BlockchainApiService {
            ledger,
            max_page_size: 2000,
            logger,
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

        Ok(resp)
    }

    /// Returns blocks in the range [offset, offset + limit).
    ///
    /// If `limit` exceeds `max_page_size`, then only [offset, offset + max_page_size) is returned.
    /// If `limit` exceeds the maximum index in the database, then only [offset, max_index] is returned.
    /// This method is a hack to expose the `get_blocks` implementation for unit testing.
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
            let resp = self
                .get_last_block_info_helper()
                .map_err(|_| RpcStatus::new(RpcStatusCode::INTERNAL, None));
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
            log::trace!(
                logger,
                "Received BlocksRequest for offset {} and limit {})",
                request.offset,
                request.limit
            );

            let resp = self
                .get_blocks_helper(request.offset, request.limit)
                .map_err(|_| RpcStatus::new(RpcStatusCode::INTERNAL, None));
            send_result(ctx, sink, resp, &logger);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_common::logger::test_with_logger;
    use mc_transaction_core_test_utils::{create_ledger, initialize_ledger, AccountKey};
    use rand::{rngs::StdRng, SeedableRng};

    #[test_with_logger]
    // `get_last_block_info` should returns the last block.
    fn test_get_last_block_info(logger: Logger) {
        let mut ledger_db = create_ledger();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let account_key = AccountKey::random(&mut rng);
        let block_entities = initialize_ledger(&mut ledger_db, 10, &account_key, &mut rng);

        let mut expected_response = LastBlockInfoResponse::new();
        expected_response.set_index(block_entities.last().unwrap().index);
        assert_eq!(
            block_entities.last().unwrap().index,
            ledger_db.num_blocks().unwrap() - 1
        );

        let mut blockchain_api_service = BlockchainApiService::new(ledger_db, logger);

        let block_response = blockchain_api_service.get_last_block_info_helper().unwrap();
        assert_eq!(block_response, expected_response);
    }

    #[test_with_logger]
    // `get_blocks` should returns the correct range of blocks.
    fn test_get_blocks_response_range(logger: Logger) {
        let mut ledger_db = create_ledger();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let account_key = AccountKey::random(&mut rng);
        let block_entities = initialize_ledger(&mut ledger_db, 10, &account_key, &mut rng);

        let expected_blocks: Vec<blockchain::Block> = block_entities
            .into_iter()
            .map(|block_entity| blockchain::Block::from(&block_entity))
            .collect();

        let mut blockchain_api_service = BlockchainApiService::new(ledger_db, logger);

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
    // `get_blocks` should return the intersection of the request with the available data
    // if a client requests data that does not exist.
    fn test_get_blocks_request_out_of_bounds(logger: Logger) {
        let mut ledger_db = create_ledger();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let account_key = AccountKey::random(&mut rng);
        let _blocks = initialize_ledger(&mut ledger_db, 10, &account_key, &mut rng);

        let mut blockchain_api_service = BlockchainApiService::new(ledger_db, logger);

        {
            // The range [0, 1000) requests values that don't exist. The response should contain [0,10).
            let block_response = blockchain_api_service.get_blocks_helper(0, 1000).unwrap();
            assert_eq!(10, block_response.blocks.len());
        }
    }

    #[test_with_logger]
    // `get_blocks` should only return the "maximum" number of items if the requested range is larger.
    fn test_get_blocks_max_size(logger: Logger) {
        let mut ledger_db = create_ledger();
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let account_key = AccountKey::random(&mut rng);
        let block_entities = initialize_ledger(&mut ledger_db, 10, &account_key, &mut rng);

        let expected_blocks: Vec<blockchain::Block> = block_entities
            .into_iter()
            .map(|block_entity| blockchain::Block::from(&block_entity))
            .collect();

        let mut blockchain_api_service = BlockchainApiService::new(ledger_db, logger);
        blockchain_api_service.set_max_page_size(5);

        // The request exceeds the max_page_size, so only max_page_size items should be returned.
        let block_response = blockchain_api_service.get_blocks_helper(0, 100).unwrap();
        let blocks = block_response.blocks;
        assert_eq!(5, blocks.len());
        assert_eq!(expected_blocks.get(0).unwrap(), blocks.get(0).unwrap());
        assert_eq!(expected_blocks.get(4).unwrap(), blocks.get(4).unwrap());
    }
}
